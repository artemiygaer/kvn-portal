"""Узкий Unix RPC переноса. Только заявленный объём и один запрос на сокет."""

import argparse
from dataclasses import asdict
import json
import re
import socket
import sqlite3
import struct

from v5.core.contracts import CORE_API_VERSION
from v5.core.audit import outcome
from v5.core.packages.manifest import PackageError, json_object
from v5.core.users.store import UserStore

from .crypto import ArchiveError, MAX_ENCRYPTED
from .export import MigrationExporter
from .repository import MigrationRepository
from .service import MigrationService
from .target import MigrationTarget

_LIMIT = 4096
_PEER = struct.Struct("3i")
_METHODS = {
    "migration.preview": {"size", "phrase", "mode", "owner"},
    "migration.commit": {"ticket", "owner"},
    "migration.rollback": {"snapshot"},
    "migration.export": {"phrase"},
}


def build_service(target=None):
    target = target if target is not None else MigrationTarget()
    repository = MigrationRepository(UserStore(target.packages.parent / "users"), guard=target.guard,
                                     restore_ready=target.restore_ready, check_target=target.check_archive,
                                     target_revision=target.revision)
    return MigrationService(repository, export_data=MigrationExporter(repository, target).collect)


class MigrationApplication:
    def __init__(self, web_uid, factory=build_service):
        self.web_uid, self.factory = web_uid, factory

    def dispatch(self, request, stream):
        if request.keys() != {"version", "method", "params"} or type(request["version"]) is not int or request["version"] != CORE_API_VERSION:
            raise ArchiveError("invalid_request")
        method, params = request["method"], request["params"]
        if not isinstance(method, str) or method not in _METHODS or not isinstance(params, dict) or params.keys() != _METHODS[method]:
            raise ArchiveError("invalid_request")
        data = None
        if method == "migration.preview":
            size = params["size"]
            if type(size) is not int or not 0 < size <= MAX_ENCRYPTED:
                raise ArchiveError("migration_archive_size")
            data = stream.read(size)
            if len(data) != size:
                raise ArchiveError("migration_body_length")
        if stream.read(1):
            raise ArchiveError("migration_body_length")
        service = self.factory()
        if method == "migration.preview":
            return asdict(service.preview(data, params["phrase"], mode=params["mode"], owner=params["owner"])), None
        if method == "migration.commit":
            return {"snapshot": service.commit(params["ticket"], owner=params["owner"])}, None
        if method == "migration.rollback":
            return {"removed": service.rollback(params["snapshot"])}, None
        data = service.export(params["phrase"])
        return {"size": len(data)}, data

    def handle(self, connection):
        connection.settimeout(12)
        request = payload = None
        try:
            _, uid, _ = _PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size))
            if uid != self.web_uid:
                raise ArchiveError("forbidden")
            with connection.makefile("rb") as stream:
                line = stream.readline(_LIMIT + 1)
                if len(line) > _LIMIT or not line.endswith(b"\n"):
                    raise ArchiveError("invalid_request")
                request = json_object(line)
                result, payload = self.dispatch(request, stream)
            response = {"ok": True, "result": result}
        except (ArchiveError, PackageError) as exc:
            code = str(exc)
            response = {"ok": False, "error": code if re.fullmatch(r"[a-z0-9_]{1,64}", code) else "migration_unavailable"}
        except (OSError, ValueError, sqlite3.Error, RecursionError):
            response = {"ok": False, "error": "migration_unavailable"}
        if request is not None:
            outcome(request, response)
        try:
            connection.sendall(json.dumps(response, separators=(",", ":")).encode("ascii") + b"\n")
            if payload is not None:
                connection.sendall(payload)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-uid", type=int, required=True)
    args = parser.parse_args()
    with socket.socket(fileno=0) as connection:
        MigrationApplication(args.web_uid).handle(connection)


if __name__ == "__main__":
    main()
