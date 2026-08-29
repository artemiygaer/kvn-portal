"""Совместимый импорт транзакций; реализация находится в ``kvnlib.core``."""

from .core import (
    JsonStateStore,
    StateFileLock,
    StateLockTimeout,
    StateRevisionConflict,
    TransactionResult,
    atomic_write_json,
    atomic_write_text,
    state_revision,
)

__all__ = [
    "JsonStateStore",
    "StateFileLock",
    "StateLockTimeout",
    "StateRevisionConflict",
    "TransactionResult",
    "atomic_write_json",
    "atomic_write_text",
    "state_revision",
]
