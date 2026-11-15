"""Сохранять клиентский материал один раз в общей закрытой БД пользователей."""

from v5.core.contracts import UserGrant
from v5.core.packages.manifest import canonical_json, json_object

from .store import MAX_USERS

MAX_CREDENTIAL_BYTES = 16 * 1024


class StoredCredentials:
    """Нормализатор и фабрика принадлежат модулю; вызов только под runtime guard."""

    def __init__(self, users, normalize):
        self.users, self.normalize = users, normalize

    def _decode(self, module, body):
        if not isinstance(body, bytes) or not 1 <= len(body) <= MAX_CREDENTIAL_BYTES:
            raise ValueError("Недопустимый материал пользователя")
        return self.normalize(module, json_object(body))

    def ensure(self, user_id, module, factory):
        UserGrant(user_id, module, True)
        with self.users._connection(write=True) as db:
            if not db.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
                raise ValueError("Пользователь не найден")
            saved = db.execute("SELECT body FROM migration_credentials WHERE user_id=? AND module=?",
                               (user_id, module)).fetchone()
            if saved is not None:
                return self._decode(module, saved[0])
            rows = db.execute("SELECT body FROM migration_credentials WHERE module=? LIMIT ?",
                              (module, MAX_USERS + 1)).fetchall()
            if len(rows) >= MAX_USERS:
                raise ValueError("Достигнут лимит ключей модуля")
            occupied = tuple(self._decode(module, row[0]) for row in rows)
            candidate = self.normalize(module, factory(occupied))
            body = canonical_json(candidate)
            if not 1 <= len(body) <= MAX_CREDENTIAL_BYTES:
                raise ValueError("Слишком большой материал пользователя")
            db.execute("INSERT INTO migration_credentials VALUES(?,?,?)", (user_id, module, body))
            return candidate
