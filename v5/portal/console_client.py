"""Непривилегированный клиент допуска: пароль только в теле локального RPC."""

import socket
import stat

from v5.core.console import AGENT_SOCKET, WEB_SOCKET
from v5.core.console.protocol import read_line, send_line

AUTHORIZE_TIMEOUT = 7


def _ready(path):
    try:
        attrs = path.lstat()
    except OSError:
        return False
    return stat.S_ISSOCK(attrs.st_mode) and attrs.st_uid == 0 and stat.S_IMODE(attrs.st_mode) == 0o660


class ConsoleClient:
    def available(self):
        return _ready(AGENT_SOCKET) and _ready(WEB_SOCKET)

    def _request(self, message, timeout):
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                connection.connect(str(AGENT_SOCKET))
                send_line(connection, message)
                return read_line(connection, timeout)
        except (OSError, ValueError, EOFError, RecursionError):
            return {"ok": False, "error": "console_unavailable"}

    def authorize(self, session, password):
        # Первый запрос запускает отдельный systemd-агент; бюджет меньше тайм-аута nginx.
        return self._request({"op": "authorize", "session": session, "password": password}, AUTHORIZE_TIMEOUT)

    def revoke(self, session):
        if self.available():
            self._request({"op": "revoke", "session": session}, 0.4)
