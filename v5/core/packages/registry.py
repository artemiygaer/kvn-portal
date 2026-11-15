"""Хранилище подписанных пакетов и атомарный журнал действий без запуска VPN."""

import fcntl
import hashlib
import os
import secrets
import shutil
import sqlite3
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from v5.core.contracts import MODULE_IDS, USER_PENDING_NAME, validate_module_id
from v5.core.lifecycle.journal import PENDING_NAME

from .archive import CHUNK, VerifiedPackage, verify_archive
from .lock import runtime_lock
from .manifest import MAX_MANIFEST, SHA256, Manifest, parse_manifest, reject, version_key
from .signature import Publisher
from .status import INSTALLED_SQL, installed_view

_STAGE_TTL = 24 * 60 * 60
_STAGE_LIMIT = 8
_SCHEMA = """
CREATE TABLE IF NOT EXISTS staged (
    ticket TEXT PRIMARY KEY, archive TEXT NOT NULL, created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS modules (
    module TEXT PRIMARY KEY, current TEXT, previous TEXT, version TEXT,
    highest_version TEXT NOT NULL, highest_manifest TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1))
);
CREATE TABLE IF NOT EXISTS journal (
    id INTEGER PRIMARY KEY, at INTEGER NOT NULL, action TEXT NOT NULL,
    module TEXT NOT NULL, archive TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS module_upgrade (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    module TEXT NOT NULL, ticket TEXT NOT NULL,
    old_archive TEXT NOT NULL, old_version TEXT NOT NULL,
    candidate TEXT NOT NULL, candidate_version TEXT NOT NULL, candidate_manifest TEXT NOT NULL
);
"""


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        reject("insecure_package_store")


def _fsync(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _module(value: str) -> str:
    try:
        return validate_module_id(value)
    except ValueError:
        reject("unsupported_module")


@dataclass(frozen=True)
class Prepared:
    ticket: str
    package: VerifiedPackage


@dataclass(frozen=True, slots=True)
class PendingUpgrade:
    module: str
    ticket: str


class PackageRegistry:
    """Отдельно от пользовательских конфигов; записи готовности действуют сутки."""

    def __init__(self, root: Path, publisher: Publisher):
        self.root, self.publisher = root, publisher
        self.objects = root / "objects"
        self.work = root / "work"
        for directory in (root, self.objects, self.work):
            _private_directory(directory)
        self.database = root / "registry.sqlite3"
        fd = os.open(self.database, os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDWR, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                reject("insecure_package_store")
        finally:
            os.close(fd)
        with self._connection() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _connection(self, *, write: bool = False):
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                if write:
                    db.execute("BEGIN IMMEDIATE")
                yield db
        finally:
            db.close()

    def runtime_guard(self):
        """Один владелец изменения версии или работающего состояния пакета."""
        return runtime_lock(self.root)

    def commit_enabled(self, previous: frozenset[str], desired: frozenset[str]) -> None:
        """Зафиксировать желаемое состояние после успешного apply под runtime_guard."""
        with self._connection(write=True) as db:
            rows = {row["module"]: row for row in db.execute(INSTALLED_SQL)}
            observed = frozenset(module for module, row in rows.items() if row["enabled"])
            if observed != previous or not desired <= rows.keys():
                reject("module_revision_changed")
            at = int(datetime.now(timezone.utc).timestamp())
            for module in sorted(previous ^ desired):
                enabled = module in desired
                db.execute("UPDATE modules SET enabled=? WHERE module=?", (int(enabled), module))
                self._record(db, at, "enable" if enabled else "disable", module, rows[module]["current"])

    def require_network_idle(self, *, allow_user_recovery: bool = False) -> None:
        if type(allow_user_recovery) is not bool:
            reject("invalid_request")
        pending = self.root / PENDING_NAME
        if pending.exists() or pending.is_symlink() or self.pending_upgrade() is not None:
            reject("module_reconcile_required")
        if not allow_user_recovery:
            self.require_user_idle()

    def require_user_idle(self) -> None:
        modules = self.root.parent / "modules"
        for name in MODULE_IDS:
            user_pending = modules / name / USER_PENDING_NAME
            if user_pending.exists() or user_pending.is_symlink():
                reject("user_recovery_required")

    def pending_upgrade(self) -> PendingUpgrade | None:
        with self._connection() as db:
            row = db.execute("SELECT module,ticket FROM module_upgrade WHERE singleton=1").fetchone()
        return PendingUpgrade(row["module"], row["ticket"]) if row else None

    @staticmethod
    def _upgrade_row(db, pending: PendingUpgrade):
        row = db.execute("SELECT * FROM module_upgrade WHERE singleton=1 AND module=? AND ticket=?",
                         (pending.module, pending.ticket)).fetchone()
        if row is None:
            reject("module_revision_changed")
        return row

    def begin_upgrade(self, module: str, ticket: str) -> PendingUpgrade:
        """Сохранить намерение до остановки работающего модуля под runtime_guard."""
        module = _module(module)
        if not isinstance(ticket, str) or not SHA256.fullmatch(ticket):
            reject("unknown_prepared_package")
        self.require_network_idle()
        now = datetime.now(timezone.utc)
        at = int(now.timestamp())
        with self._connection(write=True) as db:
            current = db.execute("SELECT * FROM modules WHERE module=? AND current IS NOT NULL", (module,)).fetchone()
            if current is None or not current["enabled"]:
                reject("module_must_be_enabled")
            staged = db.execute("SELECT archive FROM staged WHERE ticket=? AND created>?",
                                (ticket, at - _STAGE_TTL)).fetchone()
            if staged is None:
                reject("unknown_prepared_package")
            manifest, digest = self._stored(staged["archive"], now)
            if manifest.module_id != module:
                reject("release_manifest_mismatch")
            if version_key(manifest.version) <= version_key(current["highest_version"]):
                reject("package_downgrade")
            db.execute("INSERT INTO module_upgrade VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
                       (module, ticket, current["current"], current["version"],
                        staged["archive"], manifest.version, digest))
            self._record(db, at, "upgrade-begin", module, staged["archive"])
        return PendingUpgrade(module, ticket)

    def select_upgrade(self, pending: PendingUpgrade, *, rollback: bool = False) -> None:
        with self._connection(write=True) as db:
            row = self._upgrade_row(db, pending)
            archive, version = ((row["old_archive"], row["old_version"]) if rollback
                                else (row["candidate"], row["candidate_version"]))
            db.execute("UPDATE modules SET current=?,version=? WHERE module=?", (archive, version, pending.module))

    def candidate_selected(self, pending: PendingUpgrade) -> bool:
        with self._connection() as db:
            row = self._upgrade_row(db, pending)
            current = db.execute("SELECT current FROM modules WHERE module=?", (pending.module,)).fetchone()
            if current is None or current["current"] not in (row["old_archive"], row["candidate"]):
                reject("module_revision_changed")
            return current["current"] == row["candidate"]

    def verified_candidate(self, pending: PendingUpgrade) -> tuple[Manifest, Path]:
        with self._connection() as db:
            row = self._upgrade_row(db, pending)
            manifest, digest = self._stored(row["candidate"], datetime.now(timezone.utc))
            if manifest.module_id != pending.module or digest != row["candidate_manifest"]:
                reject("corrupt_package_store")
            return manifest, self.objects / row["candidate"]

    def finish_upgrade(self, pending: PendingUpgrade, *, commit: bool) -> None:
        at = int(datetime.now(timezone.utc).timestamp())
        with self._connection(write=True) as db:
            row = self._upgrade_row(db, pending)
            archive = row["candidate"] if commit else row["old_archive"]
            current = db.execute("SELECT current FROM modules WHERE module=?", (pending.module,)).fetchone()
            if current is None or current["current"] != archive:
                reject("module_revision_changed")
            if commit:
                db.execute("UPDATE modules SET previous=?,highest_version=?,highest_manifest=? WHERE module=?",
                           (row["old_archive"], row["candidate_version"], row["candidate_manifest"], pending.module))
            db.execute("DELETE FROM staged WHERE ticket=?", (pending.ticket,))
            db.execute("DELETE FROM module_upgrade WHERE singleton=1")
            self._record(db, at, "upgrade" if commit else "upgrade-rollback", pending.module, archive)

    def prepare(self, source: BinaryIO, *, expected_sha256: str | None = None,
                expected_module: str | None = None, expected_version: str | None = None,
                now: datetime | None = None) -> Prepared:
        current_time = now or datetime.now(timezone.utc)
        with (self.root / "prepare.lock").open("ab") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                reject("package_prepare_busy")
            for path in self.work.glob("incoming-*"):
                if stat.S_ISDIR(path.lstat().st_mode):
                    shutil.rmtree(path)
            self.collect(now=current_time)
            with self._connection() as db:
                if db.execute("SELECT count(*) FROM staged").fetchone()[0] >= _STAGE_LIMIT:
                    reject("prepared_package_limit")
            return self._prepare(source, expected_sha256, expected_module, expected_version, current_time)

    def _prepare(self, source: BinaryIO, expected_sha256: str | None,
                 expected_module: str | None, expected_version: str | None,
                 current_time: datetime) -> Prepared:
        at = int(current_time.timestamp())
        with tempfile.TemporaryDirectory(dir=self.work, prefix="incoming-") as directory:
            staging = Path(directory) / "object"
            staging.mkdir(mode=0o700)
            checked = verify_archive(source, self.publisher, staging,
                                     expected_sha256=expected_sha256, now=current_time)
            manifest = checked.manifest
            if ((expected_module is not None and manifest.module_id != expected_module)
                    or (expected_version is not None and manifest.version != expected_version)):
                reject("release_manifest_mismatch")
            for item in (staging / "manifest.json", staging / "manifest.sig",
                         *(staging / resource.path for resource in manifest.resources)):
                _fsync(item)
            if manifest.resources:
                _fsync_dir(staging / "payload")
            _fsync_dir(staging)
            ticket = secrets.token_hex(32)
            with self._connection(write=True) as db:
                target = self.objects / checked.archive_sha256
                if not target.exists():
                    os.rename(staging, target)
                    _fsync_dir(self.objects)
                db.execute("INSERT INTO staged VALUES (?, ?, ?)", (ticket, checked.archive_sha256, at))
                self._record(db, at, "prepare", manifest.module_id, checked.archive_sha256)
            return Prepared(ticket, checked)

    @staticmethod
    def _drop_expired(db, at: int) -> None:
        db.execute("DELETE FROM staged WHERE created <= ?", (at - _STAGE_TTL,))

    @staticmethod
    def _record(db, at: int, action: str, module: str, archive: str) -> None:
        db.execute("INSERT INTO journal (at, action, module, archive) VALUES (?, ?, ?, ?)",
                   (at, action, module, archive))
        db.execute("DELETE FROM journal WHERE id <= (SELECT max(id) - 512 FROM journal)")

    def _stored(self, archive: str, now: datetime, *, installed: bool = False) -> tuple[Manifest, str]:
        if not SHA256.fullmatch(archive):
            reject("corrupt_package_store")
        path = self.objects / archive
        try:
            with (path / "manifest.json").open("rb") as handle:
                raw = handle.read(MAX_MANIFEST + 1)
            with (path / "manifest.sig").open("rb") as handle:
                signature = handle.read(65)
            if len(raw) > MAX_MANIFEST:
                reject("manifest_size")
            self.publisher.verify(raw, signature, self.work)
            manifest = parse_manifest(raw, now, installed=installed)
            for resource in manifest.resources:
                digest, size = hashlib.sha256(), 0
                with (path / resource.path).open("rb") as handle:
                    while chunk := handle.read(CHUNK):
                        size += len(chunk)
                        if size > resource.size:
                            reject("resource_hash_mismatch")
                        digest.update(chunk)
                if size != resource.size or digest.hexdigest() != resource.sha256:
                    reject("resource_hash_mismatch")
        except OSError:
            reject("corrupt_package_store")
        return manifest, hashlib.sha256(raw).hexdigest()

    def install(self, ticket: str, *, now: datetime | None = None) -> Manifest:
        if not isinstance(ticket, str) or not SHA256.fullmatch(ticket):
            reject("unknown_prepared_package")
        current_time = now or datetime.now(timezone.utc)
        at = int(current_time.timestamp())
        with self.runtime_guard(), self._connection(write=True) as db:
            self.require_network_idle()
            staged = db.execute("SELECT archive FROM staged WHERE ticket=? AND created>?",
                                (ticket, at - _STAGE_TTL)).fetchone()
            if staged is None:
                reject("unknown_prepared_package")
            archive = staged["archive"]
            manifest, manifest_hash = self._stored(archive, current_time)
            module = manifest.module_id
            row = db.execute("SELECT * FROM modules WHERE module=?", (module,)).fetchone()
            action = "install"
            if row:
                if row["enabled"]:
                    reject("module_must_be_disabled")
                incoming, highest = version_key(manifest.version), version_key(row["highest_version"])
                if incoming < highest:
                    reject("package_downgrade")
                if incoming == highest and manifest_hash != row["highest_manifest"]:
                    reject("module_version_conflict")
                if row["current"] and row["version"] == manifest.version:
                    action = "already_installed"
                else:
                    db.execute("""UPDATE modules SET previous=current, current=?, version=?,
                                  highest_version=?, highest_manifest=? WHERE module=?""",
                               (archive, manifest.version, manifest.version, manifest_hash, module))
                    if row["current"]:
                        action = "upgrade"
            else:
                db.execute("""INSERT INTO modules (module, current, version, highest_version, highest_manifest)
                              VALUES (?, ?, ?, ?, ?)""",
                           (module, archive, manifest.version, manifest.version, manifest_hash))
            db.execute("DELETE FROM staged WHERE ticket=?", (ticket,))
            self._record(db, at, action, module, archive)
        return manifest

    def rollback(self, module: str, *, now: datetime | None = None) -> Manifest:
        module = _module(module)
        current_time = now or datetime.now(timezone.utc)
        with self.runtime_guard(), self._connection(write=True) as db:
            self.require_network_idle()
            row = db.execute("SELECT * FROM modules WHERE module=?", (module,)).fetchone()
            if not row or not row["previous"]:
                reject("no_rollback_package")
            if row["enabled"]:
                reject("module_must_be_disabled")
            archive = row["previous"]
            manifest, _ = self._stored(archive, current_time, installed=True)
            if manifest.module_id != module:
                reject("corrupt_package_store")
            db.execute("UPDATE modules SET current=?, previous=NULL, version=? WHERE module=?",
                       (archive, manifest.version, module))
            self._record(db, int(current_time.timestamp()), "rollback", module, archive)
        return manifest

    def remove(self, module: str, *, now: datetime | None = None) -> bool:
        module = _module(module)
        current_time = now or datetime.now(timezone.utc)
        with self.runtime_guard(), self._connection(write=True) as db:
            self.require_network_idle()
            row = db.execute("SELECT * FROM modules WHERE module=?", (module,)).fetchone()
            if not row or not row["current"]:
                reject("module_not_installed")
            if row["enabled"]:
                reject("module_must_be_disabled")
            db.execute("UPDATE modules SET current=NULL, previous=NULL, version=NULL WHERE module=?", (module,))
            self._record(db, int(current_time.timestamp()), "remove", module, row["current"])
        try:
            self.collect(now=current_time)
        except (OSError, sqlite3.Error):
            # Удаление из реестра уже зафиксировано; подготовка повторит сборку мусора.
            return False
        return True

    def collect(self, *, now: datetime | None = None) -> None:
        """Удалить лишь объекты без ссылок; конфиги лежат вне этого дерева."""
        at = int((now or datetime.now(timezone.utc)).timestamp())
        with self._connection(write=True) as db:
            self._drop_expired(db, at)
        with self._connection(write=True) as db:
            live = {row[0] for row in db.execute(
                "SELECT archive FROM staged UNION SELECT current FROM modules UNION SELECT previous FROM modules "
                "UNION SELECT old_archive FROM module_upgrade UNION SELECT candidate FROM module_upgrade")}
            for path in self.objects.iterdir():
                if path.name not in live and SHA256.fullmatch(path.name) and stat.S_ISDIR(path.lstat().st_mode):
                    shutil.rmtree(path)
            _fsync_dir(self.objects)

    def installed(self) -> tuple[dict, ...]:
        with self._connection() as db:
            return tuple(dict(row) for row in db.execute(INSTALLED_SQL))

    def public_status(self) -> tuple[dict, ...]:
        with self._connection() as db:
            return installed_view(db)

    def verified_install(self, module: str) -> tuple[Manifest, Path]:
        """Материалы текущей версии для адаптера, после повторной проверки подписи."""
        module = _module(module)
        with self._connection() as db:
            row = db.execute("SELECT current FROM modules WHERE module=? AND current IS NOT NULL", (module,)).fetchone()
            if row is None:
                reject("module_not_installed")
            manifest, _ = self._stored(row["current"], datetime.now(timezone.utc), installed=True)
            if manifest.module_id != module:
                reject("corrupt_package_store")
            return manifest, self.objects / row["current"]

    def journal(self) -> tuple[dict, ...]:
        with self._connection() as db:
            return tuple(dict(row) for row in db.execute("SELECT * FROM journal ORDER BY id"))
