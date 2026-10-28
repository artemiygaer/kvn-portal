"""Сборка allowlisted VPN-архива в памяти без портальных и системных секретов."""

from __future__ import annotations

import copy
import json

from ..core.migration import FORMAT, FORMAT_VERSION, MAX_JSON_BYTES, SECTION_FIELDS, MigrationValidationError, validate_identity_complete


def build_migration(state: dict) -> bytes:
    """Формирует архив; неизвестные поля в переносимых разделах запрещены."""
    if not isinstance(state, dict):
        raise ValueError("Некорректное состояние VPN.")
    protocols = {name: copy.deepcopy(state[name]) for name in (*SECTION_FIELDS, "sni_routes") if name in state}
    envelope = {
        "format": FORMAT,
        "version": FORMAT_VERSION,
        "source_server": state.get("server", ""),
        "users": copy.deepcopy(state.get("users", [])),
        "protocols": protocols,
    }
    validate_identity_complete(envelope)
    result = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(result) > MAX_JSON_BYTES:
        raise MigrationValidationError("Архив миграции превышает допустимый размер.")
    return result
