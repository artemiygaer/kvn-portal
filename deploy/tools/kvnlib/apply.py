"""Классификация изменений и минимально достаточных действий сервисов."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ApplyAction(str, Enum):
    NOOP = "no-op"
    HOT_UPDATE = "hot-update"
    RELOAD = "reload"
    RESTART = "restart"


_PRIORITY = {
    ApplyAction.NOOP: 0,
    ApplyAction.HOT_UPDATE: 1,
    ApplyAction.RELOAD: 2,
    ApplyAction.RESTART: 3,
}


SERVICE_CAPABILITIES = {
    "nginx": {
        "version": "nginx:1.31.1-alpine",
        "preferred": "reload",
        "evidence": "nginx HUP: https://nginx.org/en/docs/control.html",
        "fallback": "restart",
    },
    "xray": {
        "version": "ghcr.io/xtls/xray-core:26.3.27",
        "preferred": "hot-update-users",
        "evidence": "HandlerService/StatsService: https://xtls.github.io/en/config/api.html",
        "fallback": "restart",
    },
    "hysteria": {
        "version": "tobyxdd/hysteria:v2.10.0",
        "preferred": "external-http-auth",
        "evidence": "server source принимает SIGTERM, но не SIGHUP; доступны HTTP auth и trafficStats",
        "fallback": "restart",
    },
    "telemt": {
        "version": "ghcr.io/telemt/telemt:3.4.24",
        "preferred": "hot-update",
        "evidence": "config watcher/SIGHUP и Control API в официальном репозитории telemt/telemt",
        "fallback": "restart",
    },
    "mtg": {
        "version": "nineseconds/mtg:2.2.8",
        "preferred": "restart",
        "evidence": "run загружает TOML при старте; штатный reload API не заявлен",
        "fallback": "restart",
    },
    "ocserv": {
        "version": "Debian trixie ocserv 1.3.0-2",
        "preferred": "hot-update-users",
        "evidence": "runtime passwd обновляется штатным ocpasswd; config reload проверяется image probe",
        "fallback": "restart",
    },
    "amneziawg": {
        "version": "host awg-tools",
        "preferred": "hot-update",
        "evidence": "awg/wg syncconf меняет peers без разрыва текущих сессий",
        "fallback": "restart",
    },
    "wireguard": {
        "version": "host wireguard-tools",
        "preferred": "hot-update",
        "evidence": "wg syncconf меняет peers без разрыва текущих сессий",
        "fallback": "restart",
    },
}


@dataclass(frozen=True)
class ServiceChange:
    service: str
    action: ApplyAction
    reason: str
    paths: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "action": self.action.value,
            "reason": self.reason,
            "paths": list(self.paths),
        }


@dataclass
class ChangeSet:
    changed_paths: tuple[str, ...] = ()
    services: dict[str, ServiceChange] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.changed_paths)

    @property
    def has_service_actions(self) -> bool:
        return any(change.action is not ApplyAction.NOOP for change in self.services.values())

    def to_dict(self) -> dict:
        return {
            "changed": bool(self),
            "changed_paths": list(self.changed_paths),
            "services": {
                name: change.to_dict()
                for name, change in sorted(self.services.items())
            },
        }


RenderResult = ChangeSet


_PATH_RULES = (
    (".env", "nginx", ApplyAction.RESTART, "compose-network-alias"),
    ("nginx/nginx.conf", "nginx", ApplyAction.RELOAD, "nginx-config"),
    ("xray/config.json", "xray", ApplyAction.RESTART, "xray-structure"),
    ("hy2/config.yaml", "hysteria", ApplyAction.RESTART, "hysteria-config"),
    ("telemt/config.toml", "telemt", ApplyAction.HOT_UPDATE, "telemt-watcher"),
    ("mtg/config.toml", "mtg", ApplyAction.RESTART, "mtg-config"),
    ("amneziawg/awg0.conf", "amneziawg", ApplyAction.HOT_UPDATE, "awg-syncconf"),
    ("wireguard/wg0.conf", "wireguard", ApplyAction.HOT_UPDATE, "wg-syncconf"),
    ("ocserv/users.txt", "ocserv", ApplyAction.HOT_UPDATE, "ocserv-users"),
    ("ocserv/ocserv.conf", "ocserv", ApplyAction.RELOAD, "ocserv-config"),
    ("ocserv/ocserv.env", "ocserv", ApplyAction.RESTART, "ocserv-environment"),
)


def merge_service_change(
    services: dict[str, ServiceChange],
    service: str,
    action: ApplyAction,
    reason: str,
    path: str,
) -> None:
    if service not in SERVICE_CAPABILITIES:
        action = ApplyAction.RESTART
        reason = "unknown-capability"
    previous = services.get(service)
    paths = set(previous.paths if previous else ())
    paths.add(path)
    if previous is None or _PRIORITY[action] > _PRIORITY[previous.action]:
        services[service] = ServiceChange(service, action, reason, tuple(sorted(paths)))
    else:
        services[service] = ServiceChange(
            service,
            previous.action,
            previous.reason,
            tuple(sorted(paths)),
        )


def build_change_set(before: dict[str, str], after: dict[str, str]) -> ChangeSet:
    """Строит план применения по изменившимся generated paths."""
    changed_paths = tuple(
        sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
    )
    services: dict[str, ServiceChange] = {}
    for path in changed_paths:
        for expected, service, action, reason in _PATH_RULES:
            if path == expected or path.startswith(f"{expected}/"):
                merge_service_change(services, service, action, reason, path)
                break
    return ChangeSet(changed_paths, services)
