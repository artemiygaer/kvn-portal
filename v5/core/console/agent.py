"""Root-агент PTY. Слушатель может выдать только явная socket activation."""

import argparse
import os
import socket
import struct
from threading import BoundedSemaphore, Thread

from v5.core import audit

from . import AGENT_SOCKET
from .auth import verify_root
from .leases import Leases
from .protocol import read_line, send_line, terminal_size
from .pty import Terminal

_PEER = struct.Struct("3i")
_SCHEMAS = {
    "authorize": {"op", "session", "password"},
    "attach": {"op", "session", "grant", "rows", "columns"},
    "revoke": {"op", "session"},
}
_ERRORS = {"invalid_request", "console_session_revoked", "console_busy", "console_auth_failed",
           "console_grant_invalid", "console_unavailable"}


class ConsoleAgent:
    def __init__(self, web_uid, *, leases=None, terminal=Terminal):
        self.web_uid = web_uid
        self.leases = leases if leases is not None else Leases(verify_root)
        self.terminal = terminal

    def handle(self, connection):
        connection.settimeout(3)
        request = None
        streaming = False
        try:
            _, uid, _ = _PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size))
            if uid != self.web_uid:
                send_line(connection, {"ok": False, "error": "forbidden"})
                return
            request = read_line(connection)
            op = request.get("op")
            if not isinstance(op, str) or set(request) != _SCHEMAS.get(op):
                raise ValueError("invalid_request")
            if op == "authorize":
                password = request.pop("password")
                try:
                    grant = self.leases.issue(request["session"], password)
                finally:
                    del password
                send_line(connection, {"ok": True, "grant": grant})
                audit.record("console.authorize", True)
            elif op == "revoke":
                self.leases.revoke(request["session"])
                send_line(connection, {"ok": True})
            else:
                rows, columns = request["rows"], request["columns"]
                if not terminal_size(rows, columns):
                    raise ValueError("invalid_request")
                lease = self.leases.consume(request["session"], request["grant"])
                try:
                    terminal = self.terminal(rows, columns)
                    try:
                        if lease.cancelled.is_set():
                            raise ValueError("console_session_revoked")
                        send_line(connection, {"ok": True})
                        streaming = True
                        audit.record("console.attach", True)
                        terminal.relay(connection, lease)
                    finally:
                        terminal.close()
                finally:
                    self.leases.release(lease)
        except (EOFError, ValueError, OSError, RuntimeError, RecursionError) as exc:
            if not streaming:
                # Никогда не включать исключение, JSON, реквизиты или терминал в журнал.
                if request is not None and request.get("op") == "authorize":
                    audit.record("console.authorize", False)
                error = str(exc) if isinstance(exc, ValueError) and str(exc) in _ERRORS else "console_unavailable"
                try:
                    send_line(connection, {"ok": False, "error": error})
                except OSError:
                    pass


def serve(listener, agent):
    slots = BoundedSemaphore(4)

    def handle(connection):
        try:
            with connection:
                agent.handle(connection)
        finally:
            slots.release()

    while True:
        connection, _ = listener.accept()
        if not slots.acquire(blocking=False):
            connection.close()
            continue
        worker = Thread(target=handle, args=(connection,), daemon=True)
        worker.start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-uid", type=int, required=True)
    args = parser.parse_args()
    if (os.geteuid() != 0 or args.web_uid <= 0 or os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"):
        return 1
    with socket.socket(fileno=3) as listener:
        if (listener.family != socket.AF_UNIX or listener.getsockname() != str(AGENT_SOCKET)
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            return 1
        serve(listener, ConsoleAgent(args.web_uid))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
