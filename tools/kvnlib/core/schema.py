"""Версия схемы и идемпотентная миграция состояния v3."""

import copy

from .errors import StateMigrationError
from .validation import validate_state_shape

STATE_SCHEMA_KEY = "schema_version"
CURRENT_STATE_SCHEMA_VERSION = 3

def state_schema_version(state: dict) -> int:
    """Старый state без маркера считается схемой v3."""
    validate_state_shape(state)
    return int(state.get(STATE_SCHEMA_KEY, CURRENT_STATE_SCHEMA_VERSION))

def migrate_v3_state(state: dict) -> dict:
    """Создаёт нормализованную копию v3 с явным номером схемы."""
    validate_state_shape(state)
    if state_schema_version(state) != CURRENT_STATE_SCHEMA_VERSION:
        raise StateMigrationError("Поддерживается только схема состояния v3.")
    migrated = copy.deepcopy(state)
    migrated[STATE_SCHEMA_KEY] = CURRENT_STATE_SCHEMA_VERSION
    validate_state_shape(migrated)
    return migrated

def migrate_state(state: dict) -> dict:
    """Публичная точка миграции; повторный вызов не меняет результат."""
    return migrate_v3_state(state)
