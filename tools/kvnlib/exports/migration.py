"""Сборка allowlisted VPN-архива в памяти без портальных и системных секретов."""

from __future__ import annotations

import copy
import json

from ..core.migration import FORMAT, FORMAT_VERSION, MAX_JSON_BYTES, MAX_USERS, SECTION_FIELDS, MigrationValidationError, validate_identity_complete


def build_migration(state: dict, selected: list[str] | None = None) -> bytes:
    """Формирует архив; неизвестные поля в переносимых разделах запрещены."""
    if not isinstance(state, dict):
        raise ValueError("Некорректное состояние VPN.")
    protocols = {name: copy.deepcopy(state[name]) for name in (*SECTION_FIELDS, "sni_routes") if name in state}
    users = state.get("users", [])
    if not isinstance(users, list):
        raise MigrationValidationError("Некорректный список пользователей.")
    if selected is not None:
        if (not isinstance(selected, list) or not selected or len(selected) > MAX_USERS
                or any(not isinstance(name, str) or not name or len(name) > 32 for name in selected)):
            raise MigrationValidationError("Выберите пользователей для переноса.")
        wanted = {name.casefold() for name in selected}
        if len(wanted) != len(selected):
            raise MigrationValidationError("Имена пользователей повторяются.")
        chosen = [user for user in users if isinstance(user, dict) and isinstance(user.get("name"), str)
                  and user["name"].casefold() in wanted]
        if len(chosen) != len(wanted):
            raise MigrationValidationError("Не все выбранные пользователи найдены.")
        users = chosen
        # Отдельные MTProto-учётные записи не входят в выбор VPN-пользователей.
        if isinstance(protocols.get("telemt"), dict):
            protocols["telemt"].pop("extra_users", None)
    envelope = {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "source_server": state.get("server", ""),
        "users": copy.deepcopy(users),
        "protocols": protocols,
    }
    validate_identity_complete(envelope)
    result = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(result) > MAX_JSON_BYTES:
        raise MigrationValidationError("Архив миграции превышает допустимый размер.")
    return result
