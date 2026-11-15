"""Версии публичных границ и допустимые имена модулей."""

import re
from dataclasses import dataclass
from typing import Protocol

CORE_API_VERSION = 1
ADAPTER_API_VERSION = 1
PACKAGE_FORMAT_VERSION = 1
GRANTS_FORMAT_VERSION = 1
USER_PENDING_NAME = "users.pending.json"

MODULE_IDS = frozenset({"xray", "wireguard", "amneziawg", "hysteria", "telemt", "mtg"})
_MODULE_ID = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")


def validate_module_id(value: object) -> str:
    """Принимать только явно поддерживаемые идентификаторы модулей."""
    if not isinstance(value, str) or not _MODULE_ID.fullmatch(value) or value not in MODULE_IDS:
        raise ValueError("Неподдерживаемый идентификатор модуля")
    return value


@dataclass(frozen=True)
class ModuleDescriptor:
    """Идентификатор и версии интерфейса; достоверность подписи проверяется отдельно."""

    module_id: str
    version: str
    package_format: int = PACKAGE_FORMAT_VERSION
    adapter_api: int = ADAPTER_API_VERSION

    def __post_init__(self) -> None:
        validate_module_id(self.module_id)
        if not isinstance(self.version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}", self.version):
            raise ValueError("Некорректная версия модуля")
        if type(self.package_format) is not int or self.package_format != PACKAGE_FORMAT_VERSION:
            raise ValueError("Неподдерживаемая версия пакета")
        if type(self.adapter_api) is not int or self.adapter_api != ADAPTER_API_VERSION:
            raise ValueError("Несовместимый интерфейс адаптера")


@dataclass(frozen=True)
class UserGrant:
    """Назначение доступа не устанавливает и не включает модуль."""

    user_id: str
    module_id: str
    enabled: bool

    def __post_init__(self) -> None:
        validate_module_id(self.module_id)
        if not isinstance(self.user_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", self.user_id):
            raise ValueError("Некорректный идентификатор пользователя")
        if type(self.enabled) is not bool:
            raise ValueError("Некорректное состояние доступа")


class ModuleAdapter(Protocol):
    """Адаптер сообщает описание и наблюдаемое состояние без запуска команд."""

    def describe(self) -> ModuleDescriptor: ...

    def status(self) -> str: ...
