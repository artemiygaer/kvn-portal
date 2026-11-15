"""Root-only реестр пользователей и подтверждённых состояний доступов."""

from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import sqlite3
import stat

from v5.core.contracts import UserGrant, validate_module_id
from v5.core.private_files import private_directory

from .model import GrantState, SubscriptionToken, User

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), revision INTEGER NOT NULL DEFAULT 1,
    token_digest BLOB UNIQUE
);
CREATE TABLE IF NOT EXISTS grants (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module TEXT NOT NULL, desired INTEGER NOT NULL CHECK(desired IN (0,1)),
    applied INTEGER NOT NULL CHECK(applied IN (0,1)), error INTEGER NOT NULL CHECK(error IN (0,1)),
    generation TEXT,
    PRIMARY KEY(user_id,module)
);
CREATE TABLE IF NOT EXISTS module_epochs (
    module TEXT PRIMARY KEY, generation TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS migration_credentials (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module TEXT NOT NULL, body BLOB NOT NULL,
    PRIMARY KEY(user_id,module)
);
"""
MAX_USERS = 512


class UserStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, exist_ok=True)
        private_directory(self.root)
        self.database = self.root / "users.sqlite3"
        fd = os.open(self.database, os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDWR, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Недопустимые права реестра пользователей")
        finally:
            os.close(fd)
        with self._connection() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _connection(self, *, write=False):
        db = sqlite3.connect(self.database, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            with db:
                if write:
                    db.execute("BEGIN IMMEDIATE")
                yield db
        finally:
            db.close()

    def create(self, user: User):
        if not isinstance(user, User):
            raise ValueError("Некорректный VPN-пользователь")
        try:
            with self._connection(write=True) as db:
                if db.execute("SELECT count(*) FROM users").fetchone()[0] >= MAX_USERS:
                    raise ValueError("Достигнут лимит пользователей")
                db.execute("INSERT INTO users(id,name,enabled) VALUES(?,?,?)",
                           (user.id, user.name, int(user.enabled)))
        except sqlite3.IntegrityError as exc:
            raise ValueError("Пользователь уже существует") from exc

    def list_users(self, *, offset: int = 0, limit: int = 50) -> tuple[dict, ...]:
        if type(offset) is not int or type(limit) is not int or offset < 0 or not 1 <= limit <= 100:
            raise ValueError("Некорректная страница пользователей")
        with self._connection() as db:
            rows = db.execute("SELECT id,name,enabled,revision FROM users ORDER BY id LIMIT ? OFFSET ?",
                              (limit, offset)).fetchall()
            return tuple({"id": row["id"], "name": row["name"], "enabled": bool(row["enabled"]),
                          "revision": row["revision"]} for row in rows)

    def get(self, user_id: str):
        with self._connection() as db:
            row = db.execute("SELECT id,name,enabled,revision FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None:
                return None
            user = User(row["id"], row["name"], bool(row["enabled"]))
            grants = tuple(GrantState(UserGrant(user.id, item["module"], bool(item["desired"])),
                                      bool(item["applied"]), bool(item["error"]), item["generation"])
                           for item in db.execute("SELECT * FROM grants WHERE user_id=? ORDER BY module", (user_id,)))
            return user, row["revision"], grants

    @staticmethod
    def _revision(db, user_id, expected):
        if type(expected) is not int or expected < 1:
            raise ValueError("Некорректная ревизия")
        row = db.execute("SELECT revision FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None or row["revision"] != expected:
            raise ValueError("Пользователь отсутствует или ревизия изменилась")

    def set_grant(self, grant: UserGrant, *, revision: int) -> int:
        if not isinstance(grant, UserGrant):
            raise ValueError("Некорректный доступ")
        with self._connection(write=True) as db:
            self._revision(db, grant.user_id, revision)
            db.execute("INSERT INTO grants(user_id,module,desired,applied,error) VALUES(?,?,?,0,0) "
                       "ON CONFLICT(user_id,module) DO UPDATE SET desired=excluded.desired,error=0,"
                       "applied=CASE WHEN excluded.desired=1 THEN 0 ELSE grants.applied END,"
                       "generation=CASE WHEN excluded.desired=1 THEN NULL ELSE grants.generation END",
                       (grant.user_id, grant.module_id, int(grant.enabled)))
            db.execute("UPDATE users SET revision=revision+1 WHERE id=?", (grant.user_id,))
            return revision + 1

    def confirm_grant(self, grant: UserGrant, *, revision: int, generation: str | None = None,
                      error: bool = False):
        if not isinstance(grant, UserGrant) or type(error) is not bool:
            raise ValueError("Некорректное подтверждение")
        if not error and grant.enabled:
            GrantState(grant, True, generation=generation)
            if generation is None:
                raise ValueError("Для подтверждения доступа нужно поколение модуля")
        elif generation is not None:
            raise ValueError("Неожиданное поколение подтверждения")
        with self._connection(write=True) as db:
            self._revision(db, grant.user_id, revision)
            row = db.execute("SELECT desired FROM grants WHERE user_id=? AND module=?",
                             (grant.user_id, grant.module_id)).fetchone()
            if row is None or bool(row["desired"]) != grant.enabled:
                raise ValueError("Состояние доступа изменилось")
            if error:
                db.execute("UPDATE grants SET error=1 WHERE user_id=? AND module=?",
                           (grant.user_id, grant.module_id))
            else:
                db.execute("UPDATE grants SET applied=desired,error=0,generation=? WHERE user_id=? AND module=?",
                           (generation, grant.user_id, grant.module_id))
            db.execute("UPDATE users SET revision=revision+1 WHERE id=?", (grant.user_id,))
            return revision + 1

    def rotate_token(self, user_id: str, *, revision: int) -> SubscriptionToken:
        token = SubscriptionToken.create()
        with self._connection(write=True) as db:
            self._revision(db, user_id, revision)
            db.execute("UPDATE users SET token_digest=?,revision=revision+1 WHERE id=?", (token.digest(), user_id))
        return token

    def revoke_token(self, user_id: str, *, revision: int) -> int:
        with self._connection(write=True) as db:
            self._revision(db, user_id, revision)
            db.execute("UPDATE users SET token_digest=NULL,revision=revision+1 WHERE id=?", (user_id,))
        return revision + 1

    def subscription_owner(self, token: SubscriptionToken) -> str | None:
        if not isinstance(token, SubscriptionToken):
            raise ValueError("Некорректный токен подписки")
        with self._connection() as db:
            row = db.execute("SELECT id FROM users WHERE token_digest=? AND enabled=1", (token.digest(),)).fetchone()
            return row["id"] if row else None

    def invalidate_module(self, module: str):
        """Вызывать под общим runtime guard до изменения работающего модуля."""
        validate_module_id(module)
        with self._connection(write=True) as db:
            db.execute("DELETE FROM module_epochs WHERE module=?", (module,))

    def module_policy(self, module: str) -> tuple[tuple[str, bool], ...]:
        validate_module_id(module)
        with self._connection() as db:
            return self._module_policy(db, module)

    @staticmethod
    def _module_policy(db, module):
        return tuple((row[0], bool(row[1])) for row in db.execute(
            "SELECT g.user_id,g.desired AND u.enabled FROM grants g JOIN users u ON u.id=g.user_id "
            "WHERE g.module=? ORDER BY g.user_id", (module,)))

    def confirm_module(self, module: str, *, policy=None) -> str:
        """Вызывать под runtime guard только после проверки нового runtime."""
        validate_module_id(module)
        generation = secrets.token_hex(32)
        try:
            with self._connection(write=True) as db:
                if policy is not None and policy != self._module_policy(db, module):
                    raise ValueError("Политика доступа изменилась во время запуска")
                db.execute("INSERT INTO module_epochs(module,generation) VALUES(?,?)", (module, generation))
                if policy is not None:
                    for user_id, enabled in policy:
                        db.execute("UPDATE grants SET applied=?,error=0,generation=? WHERE module=? AND user_id=?",
                                   (int(enabled), generation if enabled else None, module, user_id))
                        db.execute("UPDATE users SET revision=revision+1 WHERE id=?", (user_id,))
        except sqlite3.IntegrityError:
            raise ValueError("Перед новым поколением требуется инвалидация") from None
        return generation

    def module_generation(self, module: str) -> str | None:
        validate_module_id(module)
        with self._connection() as db:
            row = db.execute("SELECT generation FROM module_epochs WHERE module=?", (module,)).fetchone()
            return row["generation"] if row else None
