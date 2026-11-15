"""Одноразовый root-only источник владельцев TCP без настраиваемых команд."""

import socket
import struct
from subprocess import SubprocessError

from .ssh import SS_COMMAND, _query


def main():
    with socket.socket(fileno=0) as connection:
        try:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                return
            raw = _query(SS_COMMAND).encode("utf-8")
            connection.sendall(b"OK\n" + raw)
        except (OSError, ValueError, SubprocessError):
            try:
                connection.sendall(b"ERR\n")
            except OSError:
                pass


if __name__ == "__main__":
    main()
