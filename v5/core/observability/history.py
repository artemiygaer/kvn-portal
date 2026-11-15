"""Ограниченная приватная история снимков без команд и окружения процессов."""

import json
import math
import os
import re
from contextlib import closing
from collections import deque
from pathlib import Path
import sqlite3
import stat

from v5.core.private_files import private_directory

WINDOWS = (1, 2, 6, 12, 24)
RETENTION = 24 * 60 * 60
MAX_SNAPSHOTS = 1441
MAX_RECORD = 48 * 1024
MAX_DATABASE_PAGES = 32768
MAX_DISPLAY_SAMPLES = 24
MAX_EVENTS = 128
SSH_FIELDS = ("id", "user", "ip", "port", "tty", "started_at", "age_seconds", "rx_bytes", "tx_bytes",
              "rx_per_second", "tx_per_second")
PROCESS_FIELDS = ("pid", "name", "user", "rss_bytes", "cpu_percent", "age_seconds")


def _project_rows(value, fields, limit):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("Недопустимый список наблюдений")
    rows = []
    for item in value:
        if not isinstance(item, dict) or any(key not in item for key in fields):
            raise ValueError("Неполное наблюдение")
        projected = {}
        for key in fields:
            field = item[key]
            if isinstance(field, str):
                if len(field) > 64 or any(ord(char) < 32 for char in field):
                    raise ValueError("Недопустимая строка наблюдения")
            elif field is not None and (type(field) not in (int, float) or not math.isfinite(field)
                                        or field < 0 or field >= 2**64):
                raise ValueError("Недопустимое значение наблюдения")
            projected[key] = field
        rows.append(projected)
    return rows


def project(snapshot):
    """Сохранять только утверждённые поля; исходные лишние поля отбрасываются."""
    if not isinstance(snapshot, dict):
        raise ValueError("Недопустимый снимок")
    stamp = snapshot.get("captured_at")
    if type(stamp) is not int or stamp < 0:
        raise ValueError("Недопустимое время")
    boot = snapshot.get("boot_id")
    if boot is not None and (not isinstance(boot, str)
                             or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot) is None):
        raise ValueError("Недопустимый идентификатор загрузки")
    result = {"captured_at": stamp, "boot_id": boot,
              "ssh": _project_rows(snapshot.get("ssh"), SSH_FIELDS, 32),
              "processes": _project_rows(snapshot.get("processes"), PROCESS_FIELDS, 150)}
    for key in ("ssh_partial", "tcp_partial", "processes_partial"):
        value = snapshot.get(key)
        if type(value) is not bool:
            raise ValueError("Не указан статус полноты")
        result[key] = value
    network = snapshot.get("network")
    if network is not None:
        if not isinstance(network, dict):
            raise ValueError("Недопустимые счётчики сети")
        result["network"] = {}
        for key in ("received_bytes", "sent_bytes"):
            value = network.get(key)
            if type(value) is not int or not 0 <= value < 2**64:
                raise ValueError("Недопустимый счётчик сети")
            result["network"][key] = value
        for key in ("rx_per_second", "tx_per_second"):
            value = network.get(key)
            if value is not None and (type(value) is not int or not 0 <= value < 2**64):
                raise ValueError("Недопустимая скорость сети")
            result["network"][key] = value
    else:
        result["network"] = None
    return result


class History:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.database = self.directory / "history.sqlite3"

    def initialize(self):
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        private_directory(self.directory)
        fd = os.open(self.database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Недопустимый файл истории")
        finally:
            os.close(fd)
        with closing(self._connect()) as connection, connection:
            connection.execute("CREATE TABLE IF NOT EXISTS snapshots (stamp INTEGER PRIMARY KEY, value TEXT NOT NULL)")

    def _connect(self, *, readonly=False):
        private_directory(self.directory)
        info = self.database.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Недопустимый файл истории")
        connection = sqlite3.connect(f"file:{self.database}?mode={'ro' if readonly else 'rw'}", uri=True, timeout=2)
        if not readonly:
            connection.execute(f"PRAGMA max_page_count={MAX_DATABASE_PAGES}")
        connection.execute("PRAGMA busy_timeout=2000")
        return connection

    def append(self, snapshot):
        clean = project(snapshot)
        raw = json.dumps(clean, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > MAX_RECORD:
            raise ValueError("Снимок превышает лимит")
        stamp = clean["captured_at"]
        with closing(self._connect()) as connection, connection:
            connection.execute("DELETE FROM snapshots WHERE stamp < ?", (stamp - RETENTION,))
            connection.execute("INSERT OR REPLACE INTO snapshots VALUES (?, ?)", (stamp, raw))
            connection.execute("DELETE FROM snapshots WHERE stamp NOT IN "
                               "(SELECT stamp FROM snapshots ORDER BY stamp DESC LIMIT ?)", (MAX_SNAPSHOTS,))

    def read(self, hours, now):
        if type(hours) is not int or hours not in WINDOWS or type(now) is not int or now < 0:
            raise ValueError("Недопустимое окно истории")
        with closing(self._connect(readonly=True)) as connection:
            rows = connection.execute("SELECT stamp, value FROM snapshots WHERE stamp BETWEEN ? AND ? "
                                      "ORDER BY stamp LIMIT ?", (now - hours * 3600, now, MAX_SNAPSHOTS)).fetchall()
        values = []
        for stamp, raw in rows:
            if len(raw.encode("utf-8")) > MAX_RECORD:
                raise ValueError("Повреждённая история")
            item = project(json.loads(raw))
            if item["captured_at"] != stamp:
                raise ValueError("Повреждённая временная метка")
            values.append(item)
        return values

    def summary(self, hours, now):
        if type(hours) is not int or hours not in WINDOWS or type(now) is not int or now < 0:
            raise ValueError("Недопустимое окно истории")
        bounds = (now - hours * 3600, now)
        with closing(self._connect(readonly=True)) as connection:
            connection.execute("BEGIN")
            count = connection.execute("SELECT COUNT(*) FROM snapshots WHERE stamp BETWEEN ? AND ?", bounds).fetchone()[0]
            if count > MAX_SNAPSHOTS:
                raise ValueError("Превышен лимит истории")
            cursor = connection.execute("SELECT stamp, value FROM snapshots WHERE stamp BETWEEN ? AND ? ORDER BY stamp", bounds)

            def documents():
                for stamp, raw in cursor:
                    if len(raw.encode("utf-8")) > MAX_RECORD:
                        raise ValueError("Повреждённая история")
                    item = project(json.loads(raw))
                    if item["captured_at"] != stamp:
                        raise ValueError("Повреждённая временная метка")
                    yield item

            return _summarize(documents(), count, hours, now)


def summarize(rows, hours, now):
    """Ограничить ответ, отдельно отмечая пропуски и подтверждённые изменения сессий."""
    return _summarize(iter(rows), len(rows), hours, now)


def _summarize(rows, count, hours, now):
    if type(hours) is not int or hours not in WINDOWS or type(now) is not int or now < 0:
        raise ValueError("Недопустимое окно истории")
    positions = (set(range(count)) if count <= MAX_DISPLAY_SAMPLES else
                 {round(index * (count - 1) / (MAX_DISPLAY_SAMPLES - 1)) for index in range(MAX_DISPLAY_SAMPLES)})
    gaps, events, selected = deque(maxlen=MAX_EVENTS), deque(maxlen=MAX_EVENTS), []
    truncated = False

    def record(target, item):
        nonlocal truncated
        truncated = truncated or len(target) == MAX_EVENTS
        target.append(item)

    previous = None
    seen = 0
    for index, row in enumerate(rows):
        seen += 1
        if index in positions:
            selected.append({key: value for key, value in row.items() if key != "boot_id"})
        stamp = row["captured_at"]
        if previous is None:
            if stamp - (now - hours * 3600) > 150:
                record(gaps, (now - hours * 3600, stamp))
        else:
            before = previous["captured_at"]
            if (stamp - before > 150 or previous["boot_id"] is None or row["boot_id"] is None
                    or previous["boot_id"] != row["boot_id"]):
                record(gaps, (before, stamp))
            elif not previous["ssh_partial"] and not row["ssh_partial"]:
                old = {(item["id"], item["user"]): item for item in previous["ssh"]}
                new = {(item["id"], item["user"]): item for item in row["ssh"]}
                for action, keys, source in (("вход", new.keys() - old.keys(), new),
                                             ("выход", old.keys() - new.keys(), old)):
                    for key in sorted(keys, key=repr):
                        record(events, {"at": stamp, "action": action, "user": source[key]["user"],
                                        "ip": source[key]["ip"]})
        previous = row
    if seen != count:
        raise ValueError("История изменилась при чтении")
    if previous is None or now - previous["captured_at"] > 150:
        record(gaps, (previous["captured_at"] if previous is not None else now - hours * 3600, now))
    return {"hours": hours, "captured_count": count, "samples": selected,
            "gaps": list(gaps), "events": list(events), "truncated": truncated}
