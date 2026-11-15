"""Только чтение переносимых ключей для типизированных адаптеров модулей."""

from v5.core.contracts import UserGrant, validate_module_id
from v5.core.packages.manifest import PackageError, json_object

from .crypto import ArchiveError
from .portable import normalize_credential, normalize_seed

_CREDENTIAL = "migration_credentials"
_SEED = "migration_seeds"
_MAX_MATERIAL = 256 * 1024


class MigrationMaterial:
    def __init__(self, users):
        self.users = users

    def credential(self, user_id: str, module: str):
        UserGrant(user_id, module, True)
        return self._read(_CREDENTIAL, "SELECT body FROM migration_credentials WHERE user_id=? AND module=?",
                          (user_id, module), normalize_credential, module)

    def server_seed(self, module: str):
        validate_module_id(module)
        return self._read(_SEED, "SELECT body FROM migration_seeds WHERE module=?", (module,), normalize_seed, module)

    def _read(self, table, query, params, normalize, module):
        with self.users._connection() as db:
            db.execute("BEGIN")
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                return None
            row = db.execute(query, params).fetchone()
        if row is None:
            return None
        try:
            body = row[0]
            if not isinstance(body, bytes) or not 0 < len(body) <= _MAX_MATERIAL:
                raise ValueError
            return normalize(module, json_object(body))
        except (PackageError, ValueError, TypeError):
            raise ArchiveError("migration_material_invalid") from None
