"""RPC session-bound root shell без чтения или журналирования содержимого."""

from __future__ import annotations

import codecs
import base64
from dataclasses import dataclass, field
import errno
import hashlib
import os
from pathlib import Path
import select
import signal
import subprocess
import threading
import time
from types import MappingProxyType

from .contract import HandlerSpec
from portal.agent_protocol import ProtocolError

ROOT_SHELL_IDLE_SECONDS = 15 * 60
ROOT_SHELL_ABSOLUTE_SECONDS = 60 * 60
STREAM_BUFFER_BYTES = 256 * 1024
STREAM_CHUNK_BYTES = 16 * 1024


def stop_stale_shell_units() -> None:
    """После аварийного agent restart root shell нельзя оставлять бесхозным."""
    import re
    if not Path("/run/systemd/system").is_dir():
        return
    try:
        result = subprocess.run(
            ["systemctl", "list-units", "--all", "--plain", "--no-legend", "--no-pager",
             "--type=service", "kvn-portal-root-shell-*.service"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        units = [row.split()[0] for row in result.stdout[:32768].splitlines() if row.split()]
        for unit in units[:16]:
            if re.fullmatch(r"kvn-portal-root-shell-[0-9a-f]{12}\.service", unit):
                subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


@dataclass
class RootShellSession:
    """Владелец PTY и состояния потока; содержимое не входит в public metadata."""

    session_id: str
    owner: str
    pid: int
    fd: int
    created_at: float
    last_seen: float
    lock: threading.Lock
    unit: str = ""
    closed: bool = False
    exit_code: int | None = None
    rows: int = 0
    cols: int = 0
    process: subprocess.Popen | None = field(default=None, repr=False)
    stream_id: str = ""
    output: bytearray = field(default_factory=bytearray, repr=False)
    output_start: int = 0
    output_ack: int = 0
    input_seq: int = 0
    input_digest: str = field(default="", repr=False)
    pending_input: bytes = field(default=b"", repr=False)
    pending_offset: int = 0
    pending_seq: int = 0
    input_written: int = 0
    condition: threading.Condition = field(init=False, repr=False)
    reader: threading.Thread | None = field(default=None, init=False, repr=False)
    stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    decoder: codecs.IncrementalDecoder = field(
        default_factory=lambda: codecs.getincrementaldecoder("utf-8")(errors="replace"),
        init=False, repr=False,
    )

    def __post_init__(self) -> None:
        self.condition = threading.Condition(self.lock)

    def to_public(self) -> dict:
        return {"shell_id": self.session_id, "alive": not self.closed,
                "created_at": int(self.created_at), "last_seen": int(self.last_seen),
                "exit_code": self.exit_code}

    def mark_seen(self) -> None:
        self.last_seen = time.monotonic()

    def expired(self, now_value: float) -> bool:
        return (now_value - self.last_seen > ROOT_SHELL_IDLE_SECONDS
                or now_value - self.created_at > ROOT_SHELL_ABSOLUTE_SECONDS)

    def write_bytes(self, data: bytes, timeout: float = 1.0) -> int:
        """Досылает partial writes, не повторяя уже принятую часть ввода."""
        offset = 0
        deadline = time.monotonic() + timeout
        while offset < len(data) and not self.closed:
            try:
                count = os.write(self.fd, data[offset:])
                if count > 0:
                    offset += count
                    continue
            except OSError as exc:
                if exc.errno in {errno.EIO, errno.EBADF}:
                    self.closed = True
                    break
                if exc.errno not in {errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR}:
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                select.select([], [self.fd], [], min(remaining, 0.05))
            except (OSError, ValueError):
                break
        return offset

    def start_stream(self, stream_id: str) -> None:
        """Один читатель PTY; новый transport заменяет lease, но не процесс."""
        self.stream_id = stream_id
        if self.reader is None:
            self.reader = threading.Thread(target=self._pump, name="kvn-pty-output", daemon=True)
            self.reader.start()
        self.condition.notify_all()

    def _pump(self) -> None:
        try:
            while not self.stop.is_set():
                with self.condition:
                    while len(self.output) >= STREAM_BUFFER_BYTES and not self.stop.is_set():
                        self.condition.wait(0.2)
                    if self.stop.is_set():
                        break
                    capacity = min(STREAM_CHUNK_BYTES, STREAM_BUFFER_BYTES - len(self.output))
                    fd = self.fd
                try:
                    ready, _, _ = select.select([fd], [], [], 0.1)
                    if not ready:
                        continue
                    chunk = os.read(fd, capacity)
                except OSError as exc:
                    if exc.errno in {errno.EINTR, errno.EAGAIN}:
                        continue
                    break
                if not chunk:
                    break
                with self.condition:
                    self.output.extend(chunk)
                    self.condition.notify_all()
        finally:
            with self.condition:
                self.closed = True
                if self.process is not None:
                    self.exit_code = self.process.poll()
                self.condition.notify_all()

    def read_stream(self, stream_id: str, cursor: int, wait_ms: int) -> dict:
        """Cursor подтверждает только уже отрисованные байты; неподтверждённые не теряем."""
        with self.condition:
            if stream_id != self.stream_id:
                raise ProtocolError("stream_replaced", "Соединение консоли заменено новым.")
            end = self.output_start + len(self.output)
            if cursor < self.output_start or cursor > end:
                raise ProtocolError("stream_cursor_invalid", "Потеряно состояние вывода консоли.")
            discard = cursor - self.output_start
            if discard:
                del self.output[:discard]
                self.output_start = cursor
                self.output_ack = cursor
                self.condition.notify_all()
            if not self.output and not self.closed:
                self.condition.wait(wait_ms / 1000)
            if stream_id != self.stream_id:
                raise ProtocolError("stream_replaced", "Соединение консоли заменено новым.")
            chunk = bytes(self.output[:STREAM_CHUNK_BYTES])
            return {"ok": True, "shell_id": self.session_id, "alive": not self.closed,
                    "exit_code": self.exit_code, "cursor": cursor + len(chunk),
                    "output_b64": base64.b64encode(chunk).decode("ascii"),
                    "input_seq": self.input_seq}

    def ordered_write(self, stream_id: str, seq: int, data: bytes) -> dict:
        """Retry одного seq досылает только остаток, потерянный ACK не дублирует ввод."""
        if stream_id != self.stream_id:
            raise ProtocolError("stream_replaced", "Соединение консоли заменено новым.")
        digest = hashlib.sha256(data).hexdigest()
        if seq == self.input_seq and seq > 0:
            if digest != self.input_digest:
                raise ProtocolError("stream_sequence_invalid", "Повтор ввода отличается от подтверждённого.")
            return {"ok": True, "seq": seq, "written": self.input_written, "alive": not self.closed}
        if seq != self.input_seq + 1:
            raise ProtocolError("stream_sequence_invalid", "Нарушен порядок ввода консоли.")
        if self.pending_seq:
            if self.pending_seq != seq or self.pending_input != data:
                raise ProtocolError("stream_sequence_invalid", "Ожидается подтверждение предыдущего ввода.")
        else:
            self.pending_seq, self.pending_input, self.pending_offset = seq, data, 0
        self.pending_offset += self.write_bytes(data[self.pending_offset:], timeout=0.2)
        complete = self.pending_offset == len(data)
        written = self.pending_offset
        if complete:
            self.input_seq, self.input_digest, self.input_written = seq, digest, written
            self.pending_seq, self.pending_input, self.pending_offset = 0, b"", 0
        return {"ok": complete, "seq": seq, "written": written, "alive": not self.closed}

    def close(self) -> None:
        self.stop.set()
        self.closed = True
        with self.condition:
            self.condition.notify_all()
        # Condition не держим при join: reader должен закончить до закрытия/reuse fd.
        reader = self.reader
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=0.5)
        if self.unit and Path("/usr/bin/systemctl").is_file():
            for argv in (["systemctl", "kill", "--signal=SIGHUP", self.unit],
                         ["systemctl", "stop", self.unit]):
                try:
                    subprocess.run(argv, check=False, capture_output=True, timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        if self.process is not None:
            if self.process.poll() is None:
                # Interactive bash игнорирует SIGTERM; SIGHUP завершает также jobs.
                self.process.send_signal(getattr(signal, "SIGHUP", signal.SIGTERM))
            try:
                self.exit_code = self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.exit_code = self.process.wait(timeout=1)
        else:
            try:
                os.kill(self.pid, getattr(signal, "SIGHUP", signal.SIGTERM))
                waited, status = os.waitpid(self.pid, os.WNOHANG)
                if waited == self.pid:
                    self.exit_code = os.waitstatus_to_exitcode(status)
            except (ChildProcessError, OSError):
                pass
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1
        self.pending_input = b""
        self.output.clear()


def handlers(dispatcher):
    return MappingProxyType({
        "shell.open": HandlerSpec(
            dispatcher._shell_open,
            True,
            frozenset({"root_password", "session_owner", "rows", "cols", "stream"}),
        ),
        "shell.read": HandlerSpec(dispatcher._shell_read, False, frozenset({"shell_id", "session_owner", "stream_id", "attach", "cursor", "wait_ms"})),
        "shell.write": HandlerSpec(dispatcher._shell_write, True, frozenset({"shell_id", "session_owner", "data", "stream_id", "seq"})),
        "shell.resize": HandlerSpec(
            dispatcher._shell_resize,
            True,
            frozenset({"shell_id", "session_owner", "rows", "cols"}),
        ),
        "shell.close": HandlerSpec(dispatcher._shell_close, True, frozenset({"shell_id", "session_owner"})),
    })
