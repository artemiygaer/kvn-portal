"""Единая транзакция карточек, переносимых ключей, preview и приватного отката."""

from dataclasses import dataclass
import re
from secrets import token_hex
import sqlite3
import time

from v5.core.packages.manifest import json_object
from v5.core.users.store import UserStore

from .crypto import ArchiveError
from .legacy import FORMAT
from .portable import PortableArchive

_ID = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_TTL = 600
_MAX_PREVIEWS = 4
_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS migration_revision(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL)",
    "INSERT OR IGNORE INTO migration_revision(id,revision) VALUES(1,0)",
    "CREATE TABLE IF NOT EXISTS migration_skipped(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE)",
    "CREATE TABLE IF NOT EXISTS migration_seeds(module TEXT PRIMARY KEY, body BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS migration_previews(ticket TEXT PRIMARY KEY, owner TEXT UNIQUE NOT NULL, "
    "mode TEXT NOT NULL CHECK(mode IN ('merge','restore')), revision INTEGER NOT NULL, host TEXT NOT NULL, "
    "expiry INTEGER NOT NULL, body BLOB NOT NULL)",
    "CREATE TABLE IF NOT EXISTS migration_backup(id INTEGER PRIMARY KEY CHECK(id=1), ticket TEXT NOT NULL, "
    "revision INTEGER NOT NULL, host TEXT NOT NULL, body BLOB NOT NULL, created INTEGER NOT NULL)",
)
_WATCHED = ("users", "grants", "module_epochs", "migration_credentials", "migration_skipped", "migration_seeds")


@dataclass(frozen=True, slots=True)
class Preview:
    ticket: str
    users: int
    skipped_openconnect: tuple[str, ...]
    ignored_server_keys: tuple[str, ...]
    expires: int


def _id(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ArchiveError("migration_ticket_invalid")
    return value


class MigrationRepository:
    def __init__(self, users: UserStore, *, guard, restore_ready, check_target, target_revision, clock=time.time):
        self.users, self.guard, self.restore_ready, self.check_target = users, guard, restore_ready, check_target
        self.clock, self.target_revision = clock, target_revision
        with self.users._connection(write=True) as db:
            for statement in _SCHEMA:
                db.execute(statement)
            for table in _WATCHED:
                for operation in ("INSERT", "UPDATE", "DELETE"):
                    # Имена и операции заданы константами, параметры архива не входят в DDL.
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS migration_{table}_{operation.lower()} "
                               f"AFTER {operation} ON {table} BEGIN "
                               "UPDATE migration_revision SET revision=revision+1 WHERE id=1; END")

    @staticmethod
    def _revision(db):
        return db.execute("SELECT revision FROM migration_revision WHERE id=1").fetchone()[0]

    @staticmethod
    def _export(db):
        rows = {}
        for user in db.execute("SELECT id,name,enabled,token_digest FROM users ORDER BY id"):
            rows[user[0]] = {"id": user[0], "name": user[1], "enabled": bool(user[2]),
                             "token_digest": user[3].hex() if user[3] is not None else None,
                             "grants": {}, "credentials": {}, "skipped": []}
        for user_id, module, desired in db.execute("SELECT user_id,module,desired FROM grants ORDER BY module"):
            rows[user_id]["grants"][module] = bool(desired)
        for user_id, module, body in db.execute("SELECT user_id,module,body FROM migration_credentials ORDER BY module"):
            rows[user_id]["credentials"][module] = json_object(body)
        for (user_id,) in db.execute("SELECT user_id FROM migration_skipped"):
            rows[user_id]["skipped"] = ["ocserv"]
        seeds = {module: json_object(body) for module, body in db.execute("SELECT module,body FROM migration_seeds")}
        return PortableArchive.parse({"format": FORMAT, "version": 2, "users": list(rows.values()), "seeds": seeds})

    def current(self):
        with self.users._connection() as db:
            db.execute("BEGIN")
            return self._export(db)

    def _candidate(self, db, archive, mode):
        before = self._export(db)
        if mode == "restore":
            if before.users or before.seeds or not self.restore_ready():
                raise ArchiveError("migration_restore_not_empty")
            candidate = archive
        elif mode == "merge":
            # В merge параметры и ключи сервера назначения не трогаются.
            candidate = PortableArchive.parse({"format": FORMAT, "version": 2,
                "users": [item.document() for item in (*before.users, *archive.users)],
                "seeds": {name: json_object(body) for name, body in before.seeds}})
        else:
            raise ArchiveError("migration_mode_invalid")
        candidate.encode()
        self.check_target(archive, mode, before)
        return before

    def preview(self, archive: PortableArchive, *, mode: str, owner: str) -> Preview:
        _id(owner)
        # Повторная типизация не позволяет передать невалидную напрямую созданную dataclass.
        archive = PortableArchive.parse(archive.document())
        if not archive.users:
            raise ArchiveError("migration_archive_empty")
        now, ticket = int(self.clock()), token_hex(32)
        with self.guard(), self.users._connection(write=True) as db:
            self._candidate(db, archive, mode)
            db.execute("DELETE FROM migration_previews WHERE expiry<=? OR owner=?", (now, owner))
            if db.execute("SELECT count(*) FROM migration_previews").fetchone()[0] >= _MAX_PREVIEWS:
                raise ArchiveError("migration_preview_limit")
            db.execute("INSERT INTO migration_previews VALUES(?,?,?,?,?,?,?)",
                       (ticket, owner, mode, self._revision(db), _id(self.target_revision()), now + _TTL, archive.encode()))
        return Preview(ticket, len(archive.users), tuple(row.user.name for row in archive.users if row.skipped),
                       tuple(name for name, _ in archive.seeds) if mode == "merge" else (), now + _TTL)

    def commit(self, ticket: str, *, owner: str) -> str:
        _id(ticket)
        _id(owner)
        now, snapshot = int(self.clock()), token_hex(32)
        try:
            with self.guard(), self.users._connection(write=True) as db:
                staged = db.execute("SELECT mode,revision,host,expiry,body FROM migration_previews WHERE ticket=? AND owner=?",
                                    (ticket, owner)).fetchone()
                if staged is None or staged["expiry"] <= now:
                    raise ArchiveError("migration_ticket_invalid")
                host = _id(self.target_revision())
                if staged["revision"] != self._revision(db) or staged["host"] != host:
                    raise ArchiveError("migration_preview_stale")
                archive = PortableArchive.parse(json_object(staged["body"]))
                before = self._candidate(db, archive, staged["mode"])
                for row in archive.users:
                    user = row.user
                    db.execute("INSERT INTO users(id,name,enabled,token_digest) VALUES(?,?,?,?)",
                               (user.id, user.name, int(user.enabled), row.token_digest))
                    db.executemany("INSERT INTO grants(user_id,module,desired,applied,error) VALUES(?,?,?,0,0)",
                                   ((user.id, module, int(desired)) for module, desired in row.grants))
                    db.executemany("INSERT INTO migration_credentials VALUES(?,?,?)",
                                   ((user.id, name, body) for name, body in row.credentials))
                    if row.skipped:
                        db.execute("INSERT INTO migration_skipped VALUES(?)", (user.id,))
                if staged["mode"] == "restore":
                    db.executemany("INSERT INTO migration_seeds VALUES(?,?)", archive.seeds)
                db.execute("DELETE FROM migration_previews WHERE ticket=?", (ticket,))
                db.execute("INSERT OR REPLACE INTO migration_backup VALUES(1,?,?,?,?,?)",
                           (snapshot, self._revision(db), host, before.encode(), now))
        except sqlite3.IntegrityError:
            raise ArchiveError("migration_identity_conflict") from None
        return snapshot

    def rollback(self, snapshot: str) -> int:
        _id(snapshot)
        with self.guard(), self.users._connection(write=True) as db:
            saved = db.execute("SELECT revision,host,body FROM migration_backup WHERE id=1 AND ticket=?", (snapshot,)).fetchone()
            if saved is None:
                raise ArchiveError("migration_snapshot_missing")
            if saved["revision"] != self._revision(db) or saved["host"] != _id(self.target_revision()):
                # После применения права нельзя откатывать только БД, оставляя доступ в runtime.
                raise ArchiveError("migration_rollback_stale")
            before = PortableArchive.parse(json_object(saved["body"]))
            before_users = {row.user.id for row in before.users}
            before_modules = {name for name, _ in before.seeds}
            remove = tuple(row[0] for row in db.execute("SELECT id FROM users") if row[0] not in before_users)
            remove_seeds = tuple(row[0] for row in db.execute("SELECT module FROM migration_seeds") if row[0] not in before_modules)
            db.executemany("DELETE FROM users WHERE id=?", ((item,) for item in remove))
            db.executemany("DELETE FROM migration_seeds WHERE module=?", ((item,) for item in remove_seeds))
            if self._export(db).encode() != before.encode():
                raise ArchiveError("migration_snapshot_mismatch")
            db.execute("DELETE FROM migration_backup WHERE id=1 AND ticket=?", (snapshot,))
            return len(remove)
