"""Связать конфиг модуля, общий runtime guard и пользовательский журнал."""

from contextlib import contextmanager

from v5.core.contracts import UserGrant

from .controller import UserApplyError
from .model import ModuleState, User
from .transaction import UserTransaction


class SettingsUserModule:
    def __init__(self, store, packages, backend, journal, exporter, *, config_exporter=None):
        self.store, self.packages = store, packages
        self.backend, self.journal, self.exporter = backend, journal, exporter
        self.config_exporter = config_exporter
        self.module = backend.module
        self.transaction = UserTransaction(journal, backend)

    @contextmanager
    def guard(self):
        with self.packages.runtime_guard():
            self.packages.require_network_idle()
            if self.journal.read() is not None:
                raise UserApplyError("user_recovery_required")
            yield

    def state(self) -> ModuleState:
        if self.journal.read() is not None:
            raise UserApplyError("user_recovery_required")
        row = next((item for item in self.packages.installed() if item["module"] == self.module), None)
        if row is None:
            return ModuleState(self.module, False, False)
        if not row["enabled"]:
            return ModuleState(self.module, True, False)
        try:
            adapter = self.backend.adapter
            getattr(adapter, "verify_export", adapter.verify)()
            generation = self.store.module_generation(self.module)
        except Exception:
            raise UserApplyError("user_module_unavailable") from None
        return ModuleState(self.module, True, True, generation)

    def apply_user(self, user: User, enabled: bool):
        current = self.store.get(user.id)
        if current is None:
            raise ValueError("Пользователь не найден")
        self.transaction.apply(UserGrant(user.id, self.module, enabled), revision=current[1])

    def subscription_uris(self, user: User) -> tuple[str, ...]:
        return self.exporter(user, self.backend.adapter.settings())

    def client_config(self, user: User) -> bytes:
        if self.config_exporter is None:
            return b""
        return self.config_exporter(user, self.backend.adapter.settings())

    def recover(self) -> bool:
        with self.packages.runtime_guard():
            self.packages.require_network_idle(allow_user_recovery=True)
            if self.journal.read() is None:
                return False
            row = next((item for item in self.packages.installed() if item["module"] == self.module), None)
            if row is None or not row["enabled"]:
                raise UserApplyError("user_recovery_requires_enabled_module")
            self.store.invalidate_module(self.module)
            restored = self.transaction.recover()
            self.backend.adapter.verify()
            self.store.confirm_module(self.module)
            return restored
