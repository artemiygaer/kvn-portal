"""Проверяемые права без доступа к конфигурациям конкретных модулей."""

from dataclasses import dataclass, field
import hashlib
import hmac
import re
import secrets

from v5.core.contracts import UserGrant, validate_module_id

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z", re.ASCII)
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z", re.ASCII)
_TOKEN = re.compile(r"(?:[A-Za-z0-9_-]{43}|[a-f0-9]{32})\Z", re.ASCII)
_GENERATION = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


@dataclass(frozen=True, slots=True)
class User:
    id: str
    name: str
    enabled: bool = True

    def __post_init__(self):
        if (not isinstance(self.id, str) or not _ID.fullmatch(self.id)
                or not isinstance(self.name, str) or not _NAME.fullmatch(self.name)
                or self.name in {".", ".."}
                or type(self.enabled) is not bool):
            raise ValueError("Некорректный VPN-пользователь")


@dataclass(frozen=True, slots=True)
class ModuleState:
    """Enabled означает подтверждённый runtime, не только желаемую запись БД."""

    module: str
    installed: bool
    enabled: bool
    generation: str | None = None

    def __post_init__(self):
        validate_module_id(self.module)
        if (type(self.installed) is not bool or type(self.enabled) is not bool
                or (self.enabled and not self.installed)):
            raise ValueError("Некорректное состояние модуля")
        if self.generation is not None and (not isinstance(self.generation, str)
                                            or not _GENERATION.fullmatch(self.generation)):
            raise ValueError("Некорректное поколение модуля")
        if not self.enabled and self.generation is not None:
            raise ValueError("Выключенный модуль не имеет активного поколения")


@dataclass(frozen=True, slots=True)
class GrantState:
    grant: UserGrant
    applied: bool
    error: bool = False
    generation: str | None = None

    def __post_init__(self):
        if not isinstance(self.grant, UserGrant) or type(self.applied) is not bool or type(self.error) is not bool:
            raise ValueError("Некорректное состояние доступа")
        if self.generation is not None and (not isinstance(self.generation, str)
                                            or not _GENERATION.fullmatch(self.generation) or not self.applied):
            raise ValueError("Некорректное поколение доступа")

    def status(self, user: User, module: ModuleState) -> str:
        if (not isinstance(user, User) or not isinstance(module, ModuleState)
                or self.grant.user_id != user.id or self.grant.module_id != module.module):
            raise ValueError("Доступ не соответствует пользователю или модулю")
        desired = self.grant.enabled and user.enabled
        # Прежняя ошибка не означает, что выключенный модуль требует повтора прямо сейчас.
        if desired and not module.installed:
            return "awaiting_install"
        if desired and not module.enabled:
            return "disabled"
        if self.error:
            return "error"
        if not desired:
            return "revoking" if self.applied else "revoked"
        return "active" if self.applied and module.generation is not None and self.generation == module.generation else "pending"

    def can_export(self, user: User, module: ModuleState) -> bool:
        return self.status(user, module) == "active"


@dataclass(frozen=True, slots=True)
class SubscriptionToken:
    """Новые токены — base64url; перенесённые из v4.2 — hex, в БД только digest."""

    value: str = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.value, str) or not _TOKEN.fullmatch(self.value):
            raise ValueError("Некорректный токен подписки")

    @classmethod
    def create(cls):
        return cls(secrets.token_urlsafe(32))

    def digest(self) -> bytes:
        return hashlib.sha256(self.value.encode("ascii")).digest()

    def matches(self, digest: bytes) -> bool:
        return isinstance(digest, bytes) and len(digest) == 32 and hmac.compare_digest(self.digest(), digest)
