"""Минимальная структурная валидация состояния KVN VPN."""

from collections.abc import Mapping

from .errors import StateValidationError

SECRET_FIELD_NAMES = frozenset({
    "password", "private_key", "preshared_key", "secret", "secret16",
    "sub_token", "token", "uuid",
})

def validate_state_shape(state: object) -> dict:
    """Проверяет стабильные корневые инварианты, не раскрывая значения."""
    if not isinstance(state, dict):
        raise StateValidationError("Корень состояния должен быть JSON-объектом.")
    users = state.get("users", [])
    if not isinstance(users, list):
        raise StateValidationError("Поле users должно быть JSON-массивом.")
    for index, user in enumerate(users):
        if not isinstance(user, Mapping):
            raise StateValidationError(f"Элемент users[{index}] должен быть JSON-объектом.")
    version = state.get("schema_version", 3)
    if isinstance(version, bool) or not isinstance(version, int):
        raise StateValidationError("Поле schema_version должно быть целым числом.")
    return state

def redact_secrets(value: object) -> object:
    """Возвращает безопасную копию DTO для диагностики и журналов."""
    if isinstance(value, Mapping):
        return {str(key): "[скрыто]" if str(key).lower() in SECRET_FIELD_NAMES else redact_secrets(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    return value
