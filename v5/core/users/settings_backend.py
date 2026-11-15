"""Атомарное применение проверенных настроек через существующий адаптер."""

from v5.core.contracts import UserGrant, validate_module_id
from v5.core.private_files import read_private, write_private

from .journal import MAX_SNAPSHOT


class SettingsBackend:
    """Используется только под общим runtime guard и UserTransaction."""

    def __init__(self, module, adapter, transform, validate):
        self.module = validate_module_id(module)
        if getattr(adapter, "module", None) != self.module:
            raise ValueError("Адаптер не соответствует модулю")
        self.adapter, self.transform, self.validate = adapter, transform, validate
        self.path = adapter.root / "settings.json"
        self.expected = None

    def snapshot(self) -> bytes:
        return read_private(self.path, MAX_SNAPSHOT)

    def project_before_start(self, policy: tuple[tuple[str, bool], ...]) -> None:
        """Атомарная запись желаемых прав под общей блокировкой до запуска."""
        if not policy:
            return
        before = self.adapter.settings()
        candidate = before
        for user_id, enabled in policy:
            candidate = self.transform(candidate, user_id, enabled)
        if candidate == before:
            return
        self.validate(candidate)
        if self.adapter.running():
            self.adapter.stop()
        candidate.save(self.path)

    def apply_user(self, grant: UserGrant) -> None:
        if not isinstance(grant, UserGrant) or grant.module_id != self.module:
            raise ValueError("Некорректный доступ модуля")
        before = self.adapter.settings()
        self.expected = self.transform(before, grant.user_id, grant.enabled)
        self.validate(self.expected)
        if self.expected == before:
            return
        # Конфиг проверяется до остановки; старт дополнительно проверяет образ и runtime.
        self.adapter.stop()
        self.expected.save(self.path)
        self.adapter.start()

    def verify_user(self, grant: UserGrant) -> None:
        if self.expected is None or self.adapter.settings() != self.expected:
            raise ValueError("Настройки пользователя не подтверждены")
        self.adapter.verify()

    def restore(self, snapshot: bytes) -> None:
        if self.snapshot() == snapshot and self.adapter.running():
            self.adapter.verify()
            return
        if self.adapter.running():
            self.adapter.stop()
        write_private(self.path, snapshot)
        self.adapter.start()

    def verify_snapshot(self, snapshot: bytes) -> None:
        if self.snapshot() != snapshot:
            raise ValueError("Восстановление настроек не подтверждено")
        self.adapter.verify()

    def restore_offline(self, snapshot: bytes) -> None:
        """Восстановить настройки до сетевого reconcile, не запуская модуль."""
        if self.adapter.running():
            self.adapter.stop()
        write_private(self.path, snapshot)
        if self.snapshot() != snapshot or self.adapter.running():
            raise ValueError("Автономное восстановление не подтверждено")
