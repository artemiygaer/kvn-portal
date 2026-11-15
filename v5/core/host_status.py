"""Неблокирующий снимок ресурсов Linux; без фонового сборщика и команд."""

from pathlib import Path
import shutil
import threading


class HostStatus:
    def __init__(self, proc: Path = Path("/proc"), disk: Path = Path("/")):
        self.proc = proc
        self.disk = disk
        self._lock = threading.Lock()
        self._previous_cpu = None

    def _cpu(self):
        line = (self.proc / "stat").read_text(encoding="ascii").splitlines()[0].split()
        if line[0] != "cpu" or len(line) < 6:
            raise ValueError("Нет общей строки CPU")
        counts = [int(field) for field in line[1:9]]
        current = sum(counts), counts[3] + counts[4]
        previous, self._previous_cpu = self._previous_cpu, current
        if previous is None:
            return None
        total = current[0] - previous[0]
        idle = current[1] - previous[1]
        return round((total - idle) * 100 / total, 2) if total > 0 and 0 <= idle <= total else None

    def _memory(self):
        values = {}
        for line in (self.proc / "meminfo").read_text(encoding="ascii").splitlines():
            key, _, value = line.partition(":")
            if key in ("MemTotal", "MemAvailable"):
                values[key] = int(value.split()[0]) * 1024
        return {"total_bytes": values["MemTotal"], "available_bytes": values["MemAvailable"]}

    def _network(self):
        rx = tx = 0
        for line in (self.proc / "net/dev").read_text(encoding="ascii").splitlines()[2:]:
            interface, _, counters = line.partition(":")
            if interface.strip() == "lo":
                continue
            fields = counters.split()
            rx += int(fields[0])
            tx += int(fields[8])
        return {"received_bytes": rx, "sent_bytes": tx}

    def snapshot(self):
        with self._lock:
            disk = shutil.disk_usage(self.disk)
            return {
                "cpu_percent": self._cpu(),
                "memory": self._memory(),
                "disk": {"total_bytes": disk.total, "free_bytes": disk.free},
                "network": self._network(),
                "uptime_seconds": float((self.proc / "uptime").read_text(encoding="ascii").split()[0]),
                # Состояние службы запрашивается отдельным ограниченным RPC, а не угадывается здесь.
                "history_enabled": None,
            }
