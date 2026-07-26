"""Единый эффективный план запуска сервисов из ``users.json``."""

from __future__ import annotations

from dataclasses import dataclass


DOCKER_SERVICE_ORDER = ("nginx", "xray", "hysteria", "telemt", "mtg", "ocserv", "portal")
HOST_SERVICE_ORDER = ("amneziawg", "wireguard")
OPERATOR_SERVICE_ORDER = (*DOCKER_SERVICE_ORDER, *HOST_SERVICE_ORDER, "agent")
COMPOSE_SERVICE_ORDER = (*DOCKER_SERVICE_ORDER[:-1], "portal", "portal-gateway")


def configured_service_preferences(state: dict) -> dict[str, bool]:
    """Возвращает только явно сохранённые настройки сервисов.

    Отсутствующая настройка намеренно не добавляется: legacy-состояние означает
    ``enabled=true`` и обрабатывается в :func:`effective_service_plan`.
    """
    configured = state.get("services", {})
    if not isinstance(configured, dict):
        return {}
    return {
        name: bool(settings.get("enabled", True))
        for name, settings in configured.items()
        if name in OPERATOR_SERVICE_ORDER and isinstance(settings, dict)
    }


def service_preference(state: dict, service: str) -> bool:
    """Возвращает persistent preference; отсутствующее значение равно ``true``."""
    return configured_service_preferences(state).get(service, True)


@dataclass(frozen=True)
class EffectiveServicePlan:
    """Детерминированный план Compose, host-служб и portal-agent."""

    enabled_docker: tuple[str, ...]
    disabled_docker: tuple[str, ...]
    enabled_host: tuple[str, ...]
    disabled_host: tuple[str, ...]
    compose_profiles: tuple[str, ...]
    effective_preferences: tuple[tuple[str, bool], ...]

    def enabled(self, service: str) -> bool:
        return dict(self.effective_preferences).get(service, False)

    def to_dict(self) -> dict:
        return {
            "docker": {
                "enabled": list(self.enabled_docker),
                "disabled": list(self.disabled_docker),
            },
            "host": {
                "enabled": list(self.enabled_host),
                "disabled": list(self.disabled_host),
            },
            "compose_profiles": list(self.compose_profiles),
            "preferences": dict(self.effective_preferences),
        }


def effective_service_plan(state: dict) -> EffectiveServicePlan:
    """Строит план без изменения ``state`` и без обращения к runtime/сети.

    Для совместимости все старые сервисы без ``services.*.enabled`` считаются
    включёнными. Portal и его agent дополнительно зависят от ``portal.enabled``.
    """
    portal = state.get("portal", {})
    portal_configured = isinstance(portal, dict) and bool(portal.get("enabled", False))
    portal_enabled = portal_configured and service_preference(state, "portal")
    agent_enabled = portal_enabled and service_preference(state, "agent")
    try:
        portal_port = int(portal.get("port", 8443)) if isinstance(portal, dict) else 8443
    except (TypeError, ValueError):
        portal_port = 8443

    preferences: dict[str, bool] = {}
    for service in DOCKER_SERVICE_ORDER:
        preferences[service] = (
            portal_enabled if service == "portal" else service_preference(state, service)
        )
    for service in HOST_SERVICE_ORDER:
        preferences[service] = service_preference(state, service)
    preferences["agent"] = agent_enabled

    enabled_docker = [service for service in DOCKER_SERVICE_ORDER if preferences[service]]
    if portal_enabled and portal_port != 443:
        enabled_docker.append("portal-gateway")
    disabled_docker = [service for service in COMPOSE_SERVICE_ORDER if service not in enabled_docker]
    enabled_host = [service for service in HOST_SERVICE_ORDER if preferences[service]]
    disabled_host = [service for service in HOST_SERVICE_ORDER if not preferences[service]]
    profiles: list[str] = []
    if portal_enabled:
        profiles.append("portal")
        if "portal-gateway" in enabled_docker:
            profiles.append("portal-custom")

    return EffectiveServicePlan(
        enabled_docker=tuple(enabled_docker),
        disabled_docker=tuple(disabled_docker),
        enabled_host=tuple(enabled_host),
        disabled_host=tuple(disabled_host),
        compose_profiles=tuple(profiles),
        effective_preferences=tuple((name, preferences[name]) for name in OPERATOR_SERVICE_ORDER),
    )
