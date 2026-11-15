"""Восстановление конфигурации backend до подтверждения пользовательского apply."""

from typing import Protocol

from v5.core.contracts import UserGrant

from .journal import PendingUserApply, UserApplyJournal


class UserBackend(Protocol):
    module: str

    def snapshot(self) -> bytes: ...
    def apply_user(self, grant: UserGrant) -> None: ...
    def verify_user(self, grant: UserGrant) -> None: ...
    def restore(self, snapshot: bytes) -> None: ...
    def verify_snapshot(self, snapshot: bytes) -> None: ...
    def restore_offline(self, snapshot: bytes) -> None: ...


class TransactionError(RuntimeError):
    """Коды без приватных конфигураций и текста ошибок backend."""


class UserTransaction:
    def __init__(self, journal: UserApplyJournal, backend: UserBackend):
        self.journal, self.backend = journal, backend

    def recover(self) -> bool:
        pending = self.journal.read()
        if pending is None:
            return False
        if pending.grant.module_id != self.backend.module:
            raise TransactionError("user_journal_module_mismatch")
        try:
            self.backend.restore(pending.previous)
            self.backend.verify_snapshot(pending.previous)
        except Exception:
            raise TransactionError("user_rollback_unconfirmed") from None
        self.journal.clear()
        return True

    def recover_offline(self) -> bool:
        pending = self.journal.read()
        if pending is None:
            return False
        if pending.grant.module_id != self.backend.module:
            raise TransactionError("user_journal_module_mismatch")
        try:
            self.backend.restore_offline(pending.previous)
        except Exception:
            raise TransactionError("user_rollback_unconfirmed") from None
        self.journal.clear()
        return True

    def apply(self, grant: UserGrant, *, revision: int) -> None:
        if not isinstance(grant, UserGrant) or grant.module_id != self.backend.module:
            raise ValueError("Некорректный модуль пользовательской операции")
        if self.journal.read() is not None:
            raise TransactionError("user_recovery_required")
        try:
            snapshot = self.backend.snapshot()
        except Exception:
            raise TransactionError("user_snapshot_failed") from None
        self.journal.write(PendingUserApply(grant, revision, snapshot))
        try:
            self.backend.apply_user(grant)
            self.backend.verify_user(grant)
        except Exception:
            self.recover()
            raise TransactionError("user_apply_rolled_back") from None
        self.journal.clear()
