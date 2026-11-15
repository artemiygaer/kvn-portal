"""Согласование прав с модулем; ошибок backend не скрывать от администратора."""

from contextlib import AbstractContextManager
from typing import Protocol

from v5.core.contracts import UserGrant

from .model import ModuleState, User
from .store import UserStore


class UserModule(Protocol):
    """Эпоха стабильна при подтверждённом apply, но меняется при отключении,
    переустановке или неподтверждённом восстановлении модуля.
    """

    def guard(self) -> AbstractContextManager: ...
    def state(self) -> ModuleState: ...
    def apply_user(self, user: User, enabled: bool) -> None: ...


class UserApplyError(RuntimeError):
    """Не раскрывать текст исключения backend: он может содержать секреты."""


class UserController:
    def __init__(self, store: UserStore, modules: dict[str, UserModule]):
        self.store, self.modules = store, dict(modules)

    def change(self, grant: UserGrant, *, revision: int) -> int:
        if not isinstance(grant, UserGrant):
            raise ValueError("Некорректный доступ")
        user = self.store.get(grant.user_id)
        if user is None:
            raise ValueError("Пользователь не найден")
        # Выключенному пользователю можно сохранить будущее право, но нельзя его применить.
        if not user[0].enabled and grant.enabled:
            return self.store.set_grant(grant, revision=revision)
        module = self.modules.get(grant.module_id)
        if module is None:
            return self.store.set_grant(grant, revision=revision)
        with module.guard():
            revision = self.store.set_grant(grant, revision=revision)
            try:
                state = module.state()
                if not isinstance(state, ModuleState) or state.module != grant.module_id:
                    raise UserApplyError("user_module_state_invalid")
                if not state.enabled or state.generation is None:
                    return revision
                current = self.store.get(grant.user_id)
                if current is None:
                    raise UserApplyError("user_revision_changed")
                module.apply_user(current[0], grant.enabled and current[0].enabled)
                if module.state() != state:
                    raise UserApplyError("user_module_generation_changed")
                return self.store.confirm_grant(grant, revision=revision,
                                                generation=state.generation if grant.enabled else None)
            except Exception:
                # Старое подтверждение не должно перекрыть более новую операцию.
                try:
                    self.store.confirm_grant(grant, revision=revision, error=True)
                except ValueError:
                    pass
                raise UserApplyError("user_apply_failed") from None

    def reconcile(self, user_id: str, module_id: str, *, revision: int) -> int:
        current = self.store.get(user_id)
        if current is None or current[1] != revision:
            raise ValueError("Пользователь отсутствует или ревизия изменилась")
        grant = next((item.grant for item in current[2] if item.grant.module_id == module_id), None)
        if grant is None:
            raise ValueError("Доступ не найден")
        return self.change(grant, revision=revision)
