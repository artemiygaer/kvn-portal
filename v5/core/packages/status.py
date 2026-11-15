"""Чтение карточек без активации обработчика и без создания реестра."""

import os
import sqlite3
import stat
from pathlib import Path

from .manifest import reject
from .signature import load_publisher

PACKAGE_STATE = Path("/var/lib/kvn-v5/packages")
INSTALLED_SQL = (
    "SELECT module, current, previous, version, highest_version, enabled FROM modules "
    "WHERE current IS NOT NULL ORDER BY module"
)


def installed_view(db) -> tuple[dict, ...]:
    # Старый реестр читается без миграции до первого запуска службы пакетов.
    if db.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='module_upgrade'").fetchone() is None:
        return tuple(dict(row) for row in db.execute(INSTALLED_SQL))
    sql = """SELECT m.module, COALESCE(u.old_archive, m.current) AS current, m.previous,
                    COALESCE(u.old_version, m.version) AS version, m.highest_version, m.enabled,
                    (u.module IS NOT NULL) AS updating
             FROM modules m LEFT JOIN module_upgrade u ON u.module=m.module
             WHERE m.current IS NOT NULL ORDER BY m.module"""
    return tuple(dict(row) for row in db.execute(sql))


def package_status() -> dict:
    load_publisher()
    database = PACKAGE_STATE / "registry.sqlite3"
    try:
        info = database.lstat()
    except FileNotFoundError:
        return {"installed": []}
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        reject("insecure_package_store")
    try:
        db = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=0.2)
        try:
            db.row_factory = sqlite3.Row
            installed = list(installed_view(db))
        finally:
            db.close()
    except sqlite3.Error:
        reject("package_store_unavailable")
    return {"installed": installed}
