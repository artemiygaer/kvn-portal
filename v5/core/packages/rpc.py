"""Отдельная сокет-активируемая служба пакетов; не умеет запускать модули."""

import argparse
import json
import socket
import sqlite3
import struct
from dataclasses import asdict

from v5.core.contracts import CORE_API_VERSION
from v5.core.audit import outcome

from .dependencies import dependencies
from .github import GitHubPackages
from .manifest import MAX_PACKAGE, PackageError, json_object, reject
from .registry import PackageRegistry
from .signature import load_publisher
from .status import PACKAGE_STATE

_LINE_LIMIT = 4096
_PEER = struct.Struct("3i")
_METHODS = {
    "package.status": frozenset(),
    "package.upload": frozenset({"size"}),
    "package.github": frozenset({"module", "version", "tag"}),
    "package.install": frozenset({"ticket"}),
    "package.rollback": frozenset({"module"}),
    "package.remove": frozenset({"module"}),
}


class _Body:
    def __init__(self, stream, size):
        self.stream, self.remaining = stream, size

    def read(self, size):
        if self.remaining == 0:
            if self.stream.read(1):
                reject("package_body_length")
            return b""
        data = self.stream.read(min(self.remaining, size))
        if not data:
            reject("package_body_length")
        self.remaining -= len(data)
        return data


class PackageApplication:
    def __init__(self, web_uid: int, registry_factory, github=None, clock=None):
        self.web_uid, self.registry_factory = web_uid, registry_factory
        self.github, self.clock = github or GitHubPackages(), clock

    def dispatch(self, request, stream):
        if request.keys() != {"version", "method", "params"}:
            reject("invalid_request")
        method, params = request["method"], request["params"]
        if (type(request["version"]) is not int or request["version"] != CORE_API_VERSION
                or not isinstance(method, str) or method not in _METHODS
                or not isinstance(params, dict) or params.keys() != _METHODS[method]):
            reject("invalid_request")
        if method == "package.upload":
            if type(params["size"]) is not int or not 0 < params["size"] <= MAX_PACKAGE:
                reject("package_body_length")
        elif stream.read(1):
            reject("invalid_request")
        store = self.registry_factory()
        now = self.clock() if self.clock is not None else None
        if method == "package.status":
            return {"installed": store.public_status()}
        if method == "package.install":
            manifest = store.install(params["ticket"], now=now)
            return {"module": manifest.module_id, "version": manifest.version, "enabled": False}
        if method == "package.rollback":
            manifest = store.rollback(params["module"], now=now)
            return {"module": manifest.module_id, "version": manifest.version, "enabled": False}
        if method == "package.remove":
            cleaned = store.remove(params["module"], now=now)
            return {"removed": True, "cleanup_pending": not cleaned}
        if method == "package.github":
            result = self.github.prepare(store, params["module"], params["version"], tag=params["tag"], now=now)
        else:
            result = store.prepare(_Body(stream, params["size"]), now=now)
        manifest = result.package.manifest
        return {"ticket": result.ticket, "module": manifest.module_id, "version": manifest.version,
                "sha256": result.package.archive_sha256, "dependencies": asdict(dependencies(manifest))}

    def handle(self, connection: socket.socket) -> None:
        connection.settimeout(12)
        request = None
        try:
            _, uid, _ = _PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size))
            if uid != self.web_uid:
                reject("forbidden")
            with connection.makefile("rb") as stream:
                line = stream.readline(_LINE_LIMIT + 1)
                if len(line) > _LINE_LIMIT or not line.endswith(b"\n"):
                    reject("invalid_request")
                request = json_object(line)
                result = self.dispatch(request, stream)
            response = {"ok": True, "result": result}
        except PackageError as exc:
            response = {"ok": False, "error": str(exc)}
        except (OSError, sqlite3.Error, RecursionError):
            response = {"ok": False, "error": "package_store_unavailable"}
        if request is not None:
            outcome(request, response)
        try:
            connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-uid", type=int, required=True)
    args = parser.parse_args()
    app = PackageApplication(args.web_uid, lambda: PackageRegistry(PACKAGE_STATE, load_publisher()))
    with socket.socket(fileno=0) as connection:
        app.handle(connection)


if __name__ == "__main__":
    main()
