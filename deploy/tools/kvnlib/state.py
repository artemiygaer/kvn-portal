"""Транзакционная работа с JSON-состоянием проекта."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator


class StateLockTimeout(TimeoutError):
    """Не удалось получить блокировку состояния за отведённое время."""


class StateRevisionConflict(RuntimeError):
    """Файл изменился после отображения формы пользователю."""


def _json_text(state: dict) -> str:
    return json.dumps(state, ensure_ascii=False, indent=2) + "\n"


def state_revision(state: dict) -> str:
    """Стабильная ревизия семантического содержимого JSON."""
    canonical = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class StateFileLock:
    """Межпроцессная блокировка с bounded wait для Linux и Windows."""

    _thread_locks: dict[Path, threading.Lock] = {}
    _thread_locks_guard = threading.Lock()

    def __init__(self, path: Path, timeout: float = 10.0, poll_interval: float = 0.05):
        self.path = Path(path)
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._handle = None
        self._thread_lock: threading.Lock | None = None

    @classmethod
    def _lock_for_path(cls, path: Path) -> threading.Lock:
        resolved = path.resolve()
        with cls._thread_locks_guard:
            return cls._thread_locks.setdefault(resolved, threading.Lock())

    def __enter__(self) -> "StateFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = self._lock_for_path(self.path)
        if not self._thread_lock.acquire(timeout=self.timeout):
            self._thread_lock = None
            raise StateLockTimeout(
                f"Не удалось получить потоковую блокировку {self.path} за {self.timeout:.1f} сек."
            )
        try:
            self._handle = self.path.open("a+b")
            if self.path.stat().st_size == 0:
                self._handle.write(b"0")
                self._handle.flush()
            deadline = time.monotonic() + self.timeout
            while True:
                try:
                    self._lock_nonblocking()
                    return self
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        self._handle.close()
                        self._handle = None
                        raise StateLockTimeout(
                            f"Не удалось получить блокировку {self.path} за {self.timeout:.1f} сек."
                        )
                    time.sleep(self.poll_interval)
        except Exception:
            if self._thread_lock is not None:
                self._thread_lock.release()
                self._thread_lock = None
            raise

    def _lock_nonblocking(self) -> None:
        assert self._handle is not None
        if os.name == "nt":
            import msvcrt

            self._handle.seek(0)
            msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._handle is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._handle.seek(0)
                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None
            if self._thread_lock is not None:
                self._thread_lock.release()
                self._thread_lock = None


def atomic_write_json(
    path: Path,
    state: dict,
    *,
    mode: int = 0o600,
    before_replace: Callable[[Path], None] | None = None,
) -> None:
    """Записывает JSON через temp + fsync + atomic replace и очищает temp при ошибке."""
    atomic_write_text(
        path,
        _json_text(state),
        mode=mode,
        before_replace=before_replace,
    )


def atomic_write_text(
    path: Path,
    text: str,
    *,
    mode: int = 0o600,
    before_replace: Callable[[Path], None] | None = None,
) -> None:
    """Записывает UTF-8 текст через temp + fsync + atomic replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    owner: tuple[int, int] | None = None
    if path.exists():
        current = path.stat()
        mode = stat.S_IMODE(current.st_mode)
        owner = (current.st_uid, current.st_gid)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        if owner is not None and os.name != "nt":
            os.chown(temp_path, *owner)
        if before_replace is not None:
            before_replace(temp_path)
        os.replace(temp_path, path)
        temp_path = None
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


@dataclass(frozen=True)
class TransactionResult:
    before_revision: str
    after_revision: str
    changed: bool
    before_state: dict
    state: dict


class JsonStateStore:
    """Единая точка сериализованных транзакций над JSON-файлом."""

    def __init__(self, path: Path, lock_path: Path | None = None, timeout: float = 10.0):
        self.path = Path(path)
        self.lock_path = Path(lock_path or self.path.with_name(f".{self.path.name}.lock"))
        self.timeout = timeout

    def load(self) -> dict:
        with self.path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def save(self, state: dict, expected_revision: str | None = None) -> None:
        with StateFileLock(self.lock_path, self.timeout):
            if expected_revision is not None:
                current_revision = state_revision(self.load())
                if current_revision != expected_revision:
                    raise StateRevisionConflict("Состояние изменилось. Обновите данные и повторите операцию.")
            atomic_write_json(self.path, state)

    def update(
        self,
        mutator: Callable[[dict], dict | None],
        *,
        expected_revision: str | None = None,
        before_replace: Callable[[Path], None] | None = None,
    ) -> TransactionResult:
        with StateFileLock(self.lock_path, self.timeout):
            state = self.load()
            before_revision = state_revision(state)
            if expected_revision is not None and before_revision != expected_revision:
                raise StateRevisionConflict("Состояние изменилось. Обновите данные и повторите операцию.")
            working = copy.deepcopy(state)
            replacement = mutator(working)
            if replacement is not None:
                working = replacement
            after_revision = state_revision(working)
            changed = before_revision != after_revision
            if changed:
                atomic_write_json(self.path, working, before_replace=before_replace)
            return TransactionResult(before_revision, after_revision, changed, state, working)

    @contextmanager
    def edit(self) -> Iterator[dict]:
        """Держит lock на протяжении read-modify-write блока."""
        with StateFileLock(self.lock_path, self.timeout):
            state = self.load()
            before_revision = state_revision(state)
            yield state
            if state_revision(state) != before_revision:
                atomic_write_json(self.path, state)
