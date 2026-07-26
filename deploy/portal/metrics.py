"""Ограниченная история обезличенной нагрузки хоста для portal-agent."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable


RETENTION_SECONDS = 72 * 60 * 60
SAMPLE_INTERVAL_SECONDS = 60
ALLOWED_RANGES = {1, 6, 24, 72}
ALLOWED_STEPS = {1, 5, 15, 60}
AUTO_STEPS = {1: 1, 6: 1, 24: 5, 72: 5}
MAX_POINTS = 1500
METRIC_COLUMNS = (
    "cpu_percent",
    "memory_used",
    "memory_total",
    "memory_percent",
    "disk_used",
    "disk_total",
    "disk_percent",
    "load1",
    "rx_bytes_per_second",
    "tx_bytes_per_second",
)


class MetricsQueryError(ValueError):
    """Недопустимый bounded query истории."""


class MetricsStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connection(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @contextmanager
    def session(self):
        db = self.connection()
        try:
            yield db
            db.commit()
        finally:
            db.close()

    def _initialize(self) -> None:
        with self.session() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=NORMAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS samples ("
                "ts INTEGER PRIMARY KEY, cpu_percent REAL, memory_used INTEGER, memory_total INTEGER, "
                "memory_percent REAL, disk_used INTEGER, disk_total INTEGER, disk_percent REAL, "
                "load1 REAL, rx_bytes_per_second REAL, tx_bytes_per_second REAL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)")

    def record(self, sample: dict, now: int | None = None) -> None:
        timestamp = int(sample["timestamp"])
        cutoff = int(now if now is not None else timestamp) - RETENTION_SECONDS
        values = [sample.get(column) for column in METRIC_COLUMNS]
        with self.session() as db:
            db.execute(
                "INSERT OR REPLACE INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [timestamp, *values],
            )
            db.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))

    def current(self) -> dict:
        with self.session() as db:
            row = db.execute("SELECT * FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
        if row is None:
            return {"available": False, "sample": None}
        return {"available": True, "sample": dict(row)}

    @staticmethod
    def validate_query(range_hours: int, step: int | str) -> tuple[int, int]:
        if range_hours not in ALLOWED_RANGES:
            raise MetricsQueryError("range_hours должен быть одним из 1, 6, 24, 72.")
        if step == "auto":
            step_minutes = AUTO_STEPS[range_hours]
        elif isinstance(step, int) and step in ALLOWED_STEPS:
            step_minutes = step
        else:
            raise MetricsQueryError("step должен быть auto, 1, 5, 15 или 60 минут.")
        if range_hours * 60 / step_minutes > MAX_POINTS:
            raise MetricsQueryError("Выбранный шаг создаёт слишком много точек.")
        return range_hours, step_minutes

    def history(self, range_hours: int, step: int | str, now: int | None = None) -> dict:
        range_hours, step_minutes = self.validate_query(range_hours, step)
        generated_at = int(now if now is not None else time.time())
        start = generated_at - range_hours * 60 * 60
        with self.session() as db:
            rows = db.execute(
                "SELECT * FROM samples WHERE ts >= ? AND ts <= ? ORDER BY ts",
                (start, generated_at),
            ).fetchall()
        bucket_seconds = step_minutes * 60
        buckets: dict[int, list[sqlite3.Row]] = {}
        for row in rows:
            bucket = int(row["ts"]) // bucket_seconds * bucket_seconds
            buckets.setdefault(bucket, []).append(row)
        points = []
        for timestamp, items in sorted(buckets.items()):
            point: dict[str, int | float | None] = {"timestamp": timestamp}
            for column in METRIC_COLUMNS:
                values = [float(item[column]) for item in items if item[column] is not None]
                point[column] = round(sum(values) / len(values), 3) if values else None
            points.append(point)
        return {
            "available": bool(points),
            "range_hours": range_hours,
            "step_minutes": step_minutes,
            "generated_at": generated_at,
            "points": points[:MAX_POINTS],
        }


class HostMetricsCollector:
    def __init__(
        self,
        project_root: Path,
        read_file: Callable[[Path], str] | None = None,
        statvfs: Callable[[Path], object] | None = None,
    ):
        self.project_root = Path(project_root)
        self.read_file = read_file or (lambda path: path.read_text(encoding="utf-8"))
        self.statvfs = statvfs or os.statvfs
        self._previous_cpu: tuple[int, int] | None = None
        self._previous_network: tuple[int, int, int] | None = None

    def _cpu(self) -> float | None:
        fields = self.read_file(Path("/proc/stat")).splitlines()[0].split()[1:]
        values = [int(value) for value in fields]
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        previous = self._previous_cpu
        self._previous_cpu = (total, idle)
        if previous is None or total <= previous[0]:
            return None
        total_delta = total - previous[0]
        idle_delta = max(0, idle - previous[1])
        return round(max(0.0, min(100.0, (total_delta - idle_delta) * 100 / total_delta)), 3)

    def _memory(self) -> tuple[int, int, float]:
        values = {}
        for line in self.read_file(Path("/proc/meminfo")).splitlines():
            key, value = line.split(":", 1)
            values[key] = int(value.strip().split()[0]) * 1024
        total = values["MemTotal"]
        used = max(0, total - values.get("MemAvailable", values.get("MemFree", 0)))
        return used, total, round(used * 100 / total, 3) if total else 0.0

    def _disk(self) -> tuple[int, int, float]:
        stats = self.statvfs(self.project_root)
        total = int(stats.f_blocks * stats.f_frsize)
        available = int(stats.f_bavail * stats.f_frsize)
        used = max(0, total - available)
        return used, total, round(used * 100 / total, 3) if total else 0.0

    def _network(self, timestamp: int) -> tuple[float | None, float | None]:
        rx = tx = 0
        for line in self.read_file(Path("/proc/net/dev")).splitlines()[2:]:
            interface, values_text = line.split(":", 1)
            if interface.strip() == "lo":
                continue
            values = values_text.split()
            rx += int(values[0])
            tx += int(values[8])
        previous = self._previous_network
        self._previous_network = (timestamp, rx, tx)
        if previous is None or timestamp <= previous[0] or rx < previous[1] or tx < previous[2]:
            return None, None
        elapsed = timestamp - previous[0]
        return round((rx - previous[1]) / elapsed, 3), round((tx - previous[2]) / elapsed, 3)

    def collect(self, timestamp: int | None = None) -> dict:
        timestamp = int(timestamp if timestamp is not None else time.time())
        memory_used, memory_total, memory_percent = self._memory()
        disk_used, disk_total, disk_percent = self._disk()
        rx_rate, tx_rate = self._network(timestamp)
        load1 = float(self.read_file(Path("/proc/loadavg")).split()[0])
        return {
            "timestamp": timestamp,
            "cpu_percent": self._cpu(),
            "memory_used": memory_used,
            "memory_total": memory_total,
            "memory_percent": memory_percent,
            "disk_used": disk_used,
            "disk_total": disk_total,
            "disk_percent": disk_percent,
            "load1": load1,
            "rx_bytes_per_second": rx_rate,
            "tx_bytes_per_second": tx_rate,
        }


class MetricsSampler:
    def __init__(
        self,
        store: MetricsStore,
        collector: HostMetricsCollector,
        interval: int = SAMPLE_INTERVAL_SECONDS,
        enabled_provider=None,
    ):
        self.store = store
        self.collector = collector
        self.interval = max(SAMPLE_INTERVAL_SECONDS, int(interval))
        self.enabled_provider = enabled_provider or (lambda: True)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="kvn-metrics", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                if self.enabled_provider():
                    sample = self.collector.collect()
                    self.store.record(sample)
            except (OSError, ValueError, sqlite3.Error, TypeError):
                pass
            remaining = max(0.0, self.interval - (time.monotonic() - started))
            self._stop.wait(remaining)
