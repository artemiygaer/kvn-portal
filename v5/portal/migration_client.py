"""Клиент отдельного Unix-сокета. На диск открытый архив не попадает."""

import json
import socket

from v5.core.contracts import CORE_API_VERSION
from v5.core.migration import MAX_ENCRYPTED, MAX_MIGRATION_REPLY, MIGRATION_SOCKET

from .rpc import AgentRejected, AgentUnavailable


class MigrationClient:
    def __init__(self, path=MIGRATION_SOCKET):
        self.path = path

    def request(self, action, *, body=None, **params):
        request = {"version": CORE_API_VERSION, "method": f"migration.{action}", "params": params}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(135)
                connection.connect(str(self.path))
                connection.sendall(json.dumps(request).encode("ascii") + b"\n")
                if body is not None:
                    connection.sendall(body)
                connection.shutdown(socket.SHUT_WR)
                with connection.makefile("rb") as stream:
                    line = stream.readline(MAX_MIGRATION_REPLY + 1)
                    if len(line) > MAX_MIGRATION_REPLY or not line.endswith(b"\n"):
                        raise ValueError
                    response = json.loads(line)
                    if response.get("ok") is False and isinstance(response.get("error"), str):
                        raise AgentRejected(response["error"])
                    if response.get("ok") is not True or not isinstance(result := response.get("result"), dict):
                        raise ValueError
                    if action == "export":
                        size = result.get("size")
                        if type(size) is not int or not 0 < size <= MAX_ENCRYPTED:
                            raise ValueError
                        result = stream.read(size)
                        if len(result) != size:
                            raise ValueError
                    if stream.read(1):
                        raise ValueError
                    return result
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            raise AgentUnavailable("migration_unavailable") from None
