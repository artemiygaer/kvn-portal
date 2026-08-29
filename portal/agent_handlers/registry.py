"""Сборка полного immutable RPC registry и проверка классификации."""

from __future__ import annotations

from types import MappingProxyType

from ..agent_protocol import ALLOWED_METHODS, MUTATION_METHODS, ProtocolError
from . import backup, dashboard, protocols, services, shell, updates, users
from .contract import HandlerSpec


def build_handler_registry(dispatcher) -> MappingProxyType[str, HandlerSpec]:
    merged: dict[str, HandlerSpec] = {}
    for source in (
        services.handlers(dispatcher),
        users.handlers(dispatcher),
        dashboard.handlers(dispatcher),
        protocols.handlers(dispatcher),
        updates.handlers(dispatcher),
        backup.handlers(dispatcher),
        shell.handlers(dispatcher),
    ):
        overlap = set(merged) & set(source)
        if overlap:
            raise RuntimeError(f"RPC зарегистрирован повторно: {sorted(overlap)}")
        merged.update(source)
    if set(merged) != set(ALLOWED_METHODS):
        missing = sorted(set(ALLOWED_METHODS) - set(merged))
        extra = sorted(set(merged) - set(ALLOWED_METHODS))
        raise RuntimeError(f"RPC registry не совпадает с протоколом: missing={missing}, extra={extra}")
    classified = {name for name, spec in merged.items() if spec.mutates}
    if classified != set(MUTATION_METHODS):
        raise RuntimeError("Классификация mutation RPC не совпадает с agent_protocol.")
    return MappingProxyType(merged)


def invoke(registry, method: str, params: dict):
    spec = registry.get(method)
    if spec is None:
        raise ProtocolError("method_not_found", "Метод не разрешён.")
    extra = set(params) - spec.allowed_params
    if extra:
        if method == "system.user.create":
            raise ProtocolError(
                "invalid_params",
                "Создание пользователя принимает только username и password.",
            )
        raise ProtocolError("invalid_params", "Запрос содержит неизвестные параметры.")
    return spec.callback(params)
