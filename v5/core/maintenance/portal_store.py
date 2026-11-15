"""Подготовка подписанного обновления ядра без изменения работающей системы."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tempfile
import time

from v5.core.packages.signature import load_publisher
from v5.core.private_files import private_directory, read_private, write_private
from v5.core.release import CORE_PIN, LIVE, installed_version, stable_version, verified_release

from .core_bundle import MAX_BUNDLE, unpack
from .core_stage import stage_archive
from .core_update import Systemd
from .access import _sync_dir

ROOT = Path("/var/lib/kvn-v5/core-updates")
TICKET = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_TEMPORARY = re.compile(r"\.prepare-[a-z0-9_]{8}\Z", re.ASCII)
MAX_RECORDS = 3
LIFETIME = 86400


class UpdateStoreError(ValueError):
    """Безопасный код отказа без раскрытия путей или содержимого."""


class PortalUpdateStore:
    def __init__(self, uid, *, root=ROOT, pin=CORE_PIN, live=LIVE, clock=time.time, checker=None):
        self.uid, self.root, self.pin, self.live, self.clock = uid, Path(root), Path(pin), Path(live), clock
        self.checker = checker if checker is not None else Systemd().validate

    @contextmanager
    def locked(self):
        private_directory(self.root)
        if self.root.resolve(strict=True) != self.root:
            raise UpdateStoreError("core_store_invalid")
        fd = os.open(self.root / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise UpdateStoreError("core_store_invalid")
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UpdateStoreError("core_update_busy") from exc
            yield

    def _directory(self, ticket):
        if not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None:
            raise UpdateStoreError("core_ticket_invalid")
        path = self.root / ticket
        private_directory(path)
        if path.resolve(strict=True) != path:
            raise UpdateStoreError("core_store_invalid")
        return path

    def record(self, ticket):
        try:
            directory = self._directory(ticket)
            value = json.loads(read_private(directory / "state.json", 4096))
        except FileNotFoundError as exc:
            raise UpdateStoreError("core_ticket_missing") from exc
        if (not isinstance(value, dict) or set(value) != {"ticket", "version", "sha256", "created", "updated", "status"}
                or value["ticket"] != ticket or type(value["created"]) is not int or value["created"] < 0
                or type(value["updated"]) is not int or value["updated"] < 0
                or not isinstance(value["version"], str) or not isinstance(value["sha256"], str)
                or TICKET.fullmatch(value["sha256"]) is None
                or value["status"] not in ("ready", "queued", "running", "applied", "failed")):
            raise UpdateStoreError("core_store_invalid")
        stable_version(value["version"])
        return value

    def records(self):
        private_directory(self.root)
        with os.scandir(self.root) as entries:
            names = [entry.name for entry in entries if TICKET.fullmatch(entry.name)]
        if len(names) > MAX_RECORDS:
            raise UpdateStoreError("core_store_invalid")
        return sorted((self.record(name) for name in names), key=lambda item: item["created"], reverse=True)

    def _clean(self):
        with os.scandir(self.root) as entries:
            abandoned = [entry.name for entry in entries if _TEMPORARY.fullmatch(entry.name)]
        if len(abandoned) > MAX_RECORDS:
            raise UpdateStoreError("core_store_invalid")
        for name in abandoned:
            path = self.root / name
            private_directory(path)
            if path.resolve(strict=True) != path:
                raise UpdateStoreError("core_store_invalid")
            shutil.rmtree(path)
        for item in self.records():
            if item["status"] not in ("queued", "running") and self.clock() - item["created"] >= LIFETIME:
                shutil.rmtree(self._directory(item["ticket"]))

    def discard(self, ticket):
        with self.locked():
            item = self.record(ticket)
            if item["status"] in ("queued", "running"):
                raise UpdateStoreError("core_update_busy")
            shutil.rmtree(self._directory(ticket))

    def _verify(self, payload, work):
        private_directory(self.pin.parent)
        release, raw = verified_release(payload, load_publisher(self.pin), work)
        current = installed_version(self.live)
        if current is not None and stable_version(release.version) <= stable_version(current):
            raise UpdateStoreError("core_version_not_newer")
        validation = work / "validation"
        validation.mkdir(mode=0o700)
        stage_archive(raw, release.version, validation, self.uid)
        self.checker(validation / "new-units")
        return release

    def prepare(self, stream, size, *, expected_version=None):
        if type(size) is not int or not 0 < size <= MAX_BUNDLE:
            raise UpdateStoreError("core_bundle_size")
        if expected_version is not None:
            stable_version(expected_version)
        with self.locked():
            self._clean()
            if len(self.records()) >= MAX_RECORDS:
                raise UpdateStoreError("core_prepared_limit")
            with tempfile.TemporaryDirectory(prefix=".prepare-", dir=self.root) as temporary:
                stage = Path(temporary)
                bundle = stage / "bundle.tar"
                with bundle.open("xb") as output:
                    os.fchmod(output.fileno(), 0o600)
                    remaining = size
                    while remaining:
                        chunk = stream.read(min(128 * 1024, remaining))
                        if not chunk or len(chunk) > remaining:
                            raise UpdateStoreError("core_bundle_size")
                        output.write(chunk)
                        remaining -= len(chunk)
                    if stream.read(1):
                        raise UpdateStoreError("core_bundle_size")
                    output.flush()
                    os.fsync(output.fileno())
                payload = stage / "payload"
                payload.mkdir(mode=0o700)
                unpack(bundle, payload)
                work = stage / "work"
                work.mkdir(mode=0o700)
                release = self._verify(payload, work)
                if expected_version is not None and release.version != expected_version:
                    raise UpdateStoreError("core_github_version")
                ticket = secrets.token_hex(32)
                now = int(self.clock())
                record = {"ticket": ticket, "version": release.version, "sha256": release.sha256,
                          "created": now, "updated": now, "status": "ready"}
                bundle.unlink()
                shutil.rmtree(work)
                write_private(stage / "state.json", json.dumps(record, separators=(",", ":")).encode())
                os.rename(stage, self.root / ticket)
                _sync_dir(self.root)
                return record

    def set_status(self, ticket, status):
        if status not in ("ready", "queued", "running", "applied", "failed"):
            raise UpdateStoreError("core_store_invalid")
        record = self.record(ticket)
        record["status"] = status
        record["updated"] = int(self.clock())
        write_private(self._directory(ticket) / "state.json", json.dumps(record, separators=(",", ":")).encode())
        return record
