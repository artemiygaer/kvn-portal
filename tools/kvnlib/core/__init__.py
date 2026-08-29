"""Независимое доменное ядро состояния KVN VPN."""

from .errors import StateError, StateLockTimeout, StateMigrationError, StateRevisionConflict, StateValidationError
from .io import JsonStateStore, StateFileLock, TransactionResult, atomic_write_json, atomic_write_text
from .paths import ProjectPaths
from .schema import CURRENT_STATE_SCHEMA_VERSION, STATE_SCHEMA_KEY, migrate_state, migrate_v3_state, state_schema_version
from .state import state_revision
from .validation import SECRET_FIELD_NAMES, redact_secrets, validate_state_shape

__all__ = [
    "CURRENT_STATE_SCHEMA_VERSION", "JsonStateStore", "ProjectPaths", "SECRET_FIELD_NAMES",
    "STATE_SCHEMA_KEY", "StateError", "StateFileLock", "StateLockTimeout", "StateMigrationError",
    "StateRevisionConflict", "StateValidationError", "TransactionResult", "atomic_write_json",
    "atomic_write_text", "migrate_state", "migrate_v3_state", "redact_secrets", "state_revision",
    "state_schema_version", "validate_state_shape",
]
