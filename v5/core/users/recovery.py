"""Восстановить пользовательские конфиги до запуска сетевого reconcile."""


class UserRecovery:
    def __init__(self, packages, store, modules):
        self.packages, self.store, self.modules = packages, store, dict(modules)

    def project_locked(self, module: str):
        if module not in self.modules:
            return None
        policy = self.store.module_policy(module)
        self.modules[module].backend.project_before_start(policy)
        return policy

    def recover_offline_locked(self) -> None:
        """Вызывается только под общим runtime guard."""
        if not any(module.journal.read() is not None for module in self.modules.values()):
            self.packages.require_user_idle()
            return
        self.packages.require_network_idle(allow_user_recovery=True)
        for name, module in sorted(self.modules.items()):
            if module.module != name:
                raise ValueError("Некорректный адаптер восстановления пользователя")
            if module.journal.read() is None:
                continue
            self.store.invalidate_module(name)
            module.transaction.recover_offline()
        # Не пропускать журнал неподдерживаемого ещё модуля.
        self.packages.require_user_idle()
