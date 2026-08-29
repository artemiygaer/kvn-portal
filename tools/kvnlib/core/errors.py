"""Безопасные ошибки доменного ядра состояния."""

class StateError(RuntimeError):
    """Базовая ошибка состояния без включения содержимого state."""

class StateValidationError(StateError, ValueError):
    """Структура состояния не соответствует публичной схеме."""

class StateMigrationError(StateError):
    """Состояние нельзя безопасно привести к текущей схеме."""

class StateLockTimeout(StateError, TimeoutError):
    """Не удалось получить блокировку состояния за отведённое время."""

class StateRevisionConflict(StateError):
    """Файл изменился после отображения данных пользователю."""
