"""Наблюдать назначение и сериализовать перенос с apply, не устанавливая пакеты."""

from contextlib import contextmanager, closing
import hashlib
import os
from pathlib import Path
import sqlite3
import stat

from v5.core.contracts import MODULE_IDS, USER_PENDING_NAME
from v5.core.lifecycle.journal import PENDING_NAME
from v5.core.packages.lock import runtime_lock
from v5.core.packages.manifest import canonical_json
from v5.core.packages.status import PACKAGE_STATE, installed_view
from v5.core.private_files import private_directory, read_private

from .compatibility import check_archive
from .crypto import ArchiveError

_MAX_FILE = 512 * 1024
_MODULE_FILES = ("settings.json", "runtime.json", "reality.json", "idle-auth.json")
_GATEWAY_FILES = ("identities.json", "nginx.conf")


def _digest(path):
    try:
        return hashlib.sha256(read_private(path, _MAX_FILE)).hexdigest()
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise ArchiveError("migration_target_unavailable") from None


def _exists(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


class MigrationTarget:
    def __init__(self, packages: Path = PACKAGE_STATE, gateway: Path = Path("/etc/kvn-v5/gateway")):
        self.packages, self.gateway = packages, gateway
        self.modules = packages.parent / "modules"

    def _inventory(self):
        database = self.packages / "registry.sqlite3"
        try:
            info = database.lstat()
        except FileNotFoundError:
            return (), 0
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ArchiveError("migration_target_unavailable")
        try:
            with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1)) as db:
                db.row_factory = sqlite3.Row
                db.execute("BEGIN")
                installed = installed_view(db)
                upgrade_table = db.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='module_upgrade'").fetchone()
                if upgrade_table and db.execute("SELECT 1 FROM module_upgrade LIMIT 1").fetchone():
                    raise ArchiveError("migration_target_busy")
                # Учитываем и цикл включения/отключения, после которого список модулей тот же.
                revision = db.execute("SELECT COALESCE(MAX(id),0) FROM journal").fetchone()[0]
                return installed, revision
        except sqlite3.Error:
            raise ArchiveError("migration_target_unavailable") from None

    def _configuration(self):
        result = {}
        if not _exists(self.modules):
            return result
        private_directory(self.modules)
        for name in sorted(MODULE_IDS):
            root = self.modules / name
            if not _exists(root):
                continue
            private_directory(root)
            for file in _MODULE_FILES:
                if (digest := _digest(root / file)) is not None:
                    result[f"{name}/{file}"] = digest
        return result

    @contextmanager
    def guard(self):
        with runtime_lock(self.packages):
            if _exists(self.packages / PENDING_NAME):
                raise ArchiveError("migration_target_busy")
            if _exists(self.modules):
                private_directory(self.modules)
                for name in MODULE_IDS:
                    root = self.modules / name
                    if _exists(root):
                        private_directory(root)
                        if _exists(root / USER_PENDING_NAME):
                            raise ArchiveError("migration_target_busy")
            self._inventory()
            yield

    def restore_ready(self) -> bool:
        installed, _ = self._inventory()
        return not any(row["enabled"] for row in installed) and not self._configuration()

    def check_archive(self, archive, mode, before) -> None:
        check_archive(self.modules, archive, mode, before)

    def revision(self) -> str:
        installed, serial = self._inventory()
        gateway = {name: _digest(self.gateway / name) for name in _GATEWAY_FILES}
        return hashlib.sha256(canonical_json({"packages": installed, "serial": serial,
                                              "modules": self._configuration(), "gateway": gateway})).hexdigest()
