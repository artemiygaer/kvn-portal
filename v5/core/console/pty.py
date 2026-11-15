"""Управляющий PTY без forkpty в многопоточном агенте."""

import errno
import fcntl
import os
import select
import signal
import struct
import subprocess
import termios
import time

from .protocol import INPUT, MAX_FRAME, OUTPUT, RESIZE, SIZE, frame, read_frame, terminal_size

_CHILD = (
    "import fcntl, os, termios;"
    "fcntl.ioctl(0, termios.TIOCSCTTY, 0);"
    "os.execv('/bin/bash', ('/bin/bash', '--noprofile', '--norc', '-i'))"
)
_WINSIZE = struct.Struct("HHHH")


class Terminal:
    def __init__(self, rows, columns, *, home="/root"):
        if not terminal_size(rows, columns):
            raise ValueError("invalid_size")
        self.master, slave = os.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, _WINSIZE.pack(rows, columns, 0, 0))
            self.process = subprocess.Popen(
                ["/usr/bin/python3", "-I", "-c", _CHILD], stdin=slave, stdout=slave, stderr=slave,
                cwd=home, start_new_session=True,
                env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                     "HOME": home, "USER": "root", "LOGNAME": "root", "SHELL": "/bin/bash",
                     "TERM": "xterm-256color", "LANG": "C.UTF-8", "HISTFILE": "/dev/null"},
            )
            os.set_blocking(self.master, False)
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)

    def _input(self, data):
        until = time.monotonic() + 1
        while data:
            remaining = until - time.monotonic()
            if remaining <= 0 or not select.select([], [self.master], [], remaining)[1]:
                raise TimeoutError
            try:
                data = data[os.write(self.master, data):]
            except BlockingIOError:
                continue

    def relay(self, connection, lease, *, clock=time.monotonic):
        connection.settimeout(2)
        while not lease.cancelled.is_set() and clock() < lease.until:
            ready = select.select([connection, self.master], [], [], .2)[0]
            if lease.cancelled.is_set():
                return
            if connection in ready:
                kind, data = read_frame(connection)
                if lease.cancelled.is_set() or clock() >= lease.until:
                    return
                if kind == RESIZE:
                    rows, columns = SIZE.unpack(data)
                    if not terminal_size(rows, columns):
                        raise ValueError("invalid_size")
                    fcntl.ioctl(self.master, termios.TIOCSWINSZ, _WINSIZE.pack(rows, columns, 0, 0))
                elif kind == INPUT:
                    self._input(data)
                else:
                    raise ValueError("invalid_frame")
            if self.master in ready:
                try:
                    data = os.read(self.master, MAX_FRAME)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if exc.errno == errno.EIO:
                        return
                    raise
                if not data:
                    return
                connection.sendall(frame(OUTPUT, data))

    def close(self):
        os.close(self.master)
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=2)
