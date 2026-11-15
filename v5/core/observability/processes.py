"""Снимок /proc с идентичностью PID + starttime и ограничением работы."""

from dataclasses import dataclass
import heapq
import os
from pathlib import Path
import pwd
import re
import time

MAX_SCAN = 4096
MAX_ROWS = 150
MAX_STAT = 4096
_NAME = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


@dataclass(frozen=True, slots=True)
class Process:
    pid: int
    parent: int
    started: int
    name: str
    uid: int
    ticks: int
    rss: int
    tty: int = 0

    @property
    def key(self) -> tuple[int, int]:
        return self.pid, self.started


def parse_stat(raw: bytes, pid: int, uid: int, page_size: int) -> Process:
    first = raw.find(b" (")
    last = raw.rfind(b") ")
    if first < 1 or last <= first or int(raw[:first]) != pid:
        raise ValueError("Неверный stat процесса")
    name = _NAME.sub("?", raw[first + 2:last].decode("utf-8", "replace"))[:64]
    fields = raw[last + 2:].split()
    if len(fields) < 22:
        raise ValueError("Неполный stat процесса")
    parent, user, kernel, started, rss = (int(fields[i]) for i in (1, 11, 12, 19, 21))
    raw_tty = int(fields[4]) & 0xffffffff
    tty = os.makedev((raw_tty >> 8) & 0xfff, (raw_tty & 0xff) | ((raw_tty >> 12) & 0xfff00)) if raw_tty else 0
    if min(parent, user, kernel, started, rss, uid) < 0:
        raise ValueError("Недопустимые счётчики")
    return Process(pid, parent, started, name or "?", uid, user + kernel, rss * page_size, tty)


def sample(proc=Path("/proc"), *, clock=time.monotonic, budget=.75):
    """Сканировать только числовые каталоги; исчезнувшие процессы пропускать."""
    deadline = clock() + budget
    page_size = os.sysconf("SC_PAGE_SIZE")
    rows, partial = {}, False
    with os.scandir(proc) as items:
        for count, item in enumerate(items):
            if count >= MAX_SCAN or clock() >= deadline:
                partial = True
                break
            name = item.name
            if not 1 <= len(name) <= 10 or not name.isascii() or not name.isdecimal():
                continue
            try:
                with open(Path(item.path) / "stat", "rb") as stream:
                    uid = os.fstat(stream.fileno()).st_uid
                    raw = stream.read(MAX_STAT + 1)
                if len(raw) <= MAX_STAT:
                    row = parse_stat(raw, int(name), uid, page_size)
                    rows[row.pid] = row
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (OSError, ValueError):
                partial = True
    return rows, partial


def descendants(rows, leader_key):
    """Не связывать процессы с подменённым PID или устаревшим родителем."""
    leader = rows.get(leader_key[0])
    if leader is None or leader.key != leader_key:
        return frozenset()
    children = {}
    for child in rows.values():
        parent = rows.get(child.parent)
        if parent is not None and child.pid != parent.pid and child.started >= parent.started:
            children.setdefault(parent.pid, []).append(child)
    seen, stack = {leader.pid}, [leader.pid]
    while stack:
        for child in children.get(stack.pop(), ()):
            if child.pid not in seen:
                seen.add(child.pid)
                stack.append(child.pid)
    return frozenset(seen)


def project(rows, previous, elapsed, uptime, *, visible=None, ticks_per_second=None):
    frequency = os.sysconf("SC_CLK_TCK") if ticks_per_second is None else ticks_per_second
    candidates = (p for p in rows.values() if visible is None or p.pid in visible)
    selected = heapq.nsmallest(MAX_ROWS, candidates, key=lambda p: (-p.rss, p.pid))
    owners = {}
    result = []
    for row in selected:
        if row.uid not in owners:
            try:
                owners[row.uid] = _NAME.sub("?", pwd.getpwuid(row.uid).pw_name)[:64]
            except KeyError:
                owners[row.uid] = str(row.uid)
        old = previous.get(row.pid)
        cpu = None
        if old is not None and old.key == row.key and elapsed > 0 and row.ticks >= old.ticks:
            cpu = round(100 * (row.ticks - old.ticks) / (frequency * elapsed), 1)
        result.append({"pid": row.pid, "name": row.name, "user": owners[row.uid], "rss_bytes": row.rss,
                       "cpu_percent": cpu, "age_seconds": max(0, int(uptime - row.started / frequency))})
    return result
