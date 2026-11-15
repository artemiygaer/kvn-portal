"""Применять права туннеля через syncconf, сохраняя журнал восстановления."""

from v5.core.contracts import UserGrant
from v5.core.users.settings_backend import SettingsBackend


class TunnelUserBackend(SettingsBackend):
    def __init__(self, adapter, transform):
        super().__init__(adapter.spec.module, adapter, transform, lambda state: state.server())

    def apply_user(self, grant: UserGrant) -> None:
        if not isinstance(grant, UserGrant) or grant.module_id != self.module:
            raise ValueError("Некорректный доступ туннеля")
        before = self.adapter.settings()
        self.expected = self.transform(before, grant.user_id, grant.enabled)
        self.validate(self.expected)
        if self.expected == before:
            return
        # Журнал уже записан UserTransaction. Не входить повторно в runtime guard.
        self.adapter.runtime.sync(before, self.expected)
        try:
            self.expected.save(self.path)
        except BaseException:
            self.adapter.runtime.sync(self.expected, before)
            raise

    def restore(self, snapshot: bytes) -> None:
        # После гибели процесса settings.json может быть старым, а kernel — уже
        # новым. Если runtime не подтвердил снимок, закрыть свой интерфейс.
        if self.snapshot() == snapshot and self.adapter.running():
            try:
                self.adapter.verify()
            except Exception:
                pass
            else:
                return
        if self.adapter.running():
            self.adapter.stop()
        super().restore(snapshot)
