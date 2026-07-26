"""Чистая модель выбора адреса в клиентских конфигурациях."""

from __future__ import annotations

import ipaddress
import copy
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal


AddressMode = Literal["server", "public-ip"]


class ClientExportValidationError(ValueError):
    """Ошибка политики экспорта, пригодная для показа оператору."""


def validate_public_ipv4(value: object) -> str:
    """Возвращает канонический публичный IPv4 или русскую ошибку."""
    candidate = str(value or "").strip()
    if not candidate:
        raise ClientExportValidationError(
            "Публичный IPv4 для экспорта не указан"
        )
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ClientExportValidationError(
            f"Адрес экспорта должен быть публичным IPv4: {candidate!r}"
        ) from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise ClientExportValidationError(
            "Адрес экспорта должен быть публичным IPv4, IPv6 не поддерживается"
        )
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        raise ClientExportValidationError(
            f"Адрес экспорта должен быть публичным глобальным IPv4: {address}"
        )
    return str(address)


@dataclass(frozen=True, slots=True)
class ClientExportPolicy:
    """Эффективная политика адреса, не изменяющая исходный state."""

    address_mode: AddressMode = "server"
    public_ip: str = ""
    include_alternate: bool = False

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> "ClientExportPolicy":
        raw = state.get("client_export")
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise ClientExportValidationError(
                "client_export должен быть объектом настроек"
            )

        mode = str(raw.get("address_mode", "server")).strip().lower()
        if mode not in {"server", "public-ip"}:
            raise ClientExportValidationError(
                "Режим адреса экспорта: допустимы только server и public-ip"
            )
        include_alternate = raw.get("include_alternate", False)
        if not isinstance(include_alternate, bool):
            raise ClientExportValidationError(
                "client_export.include_alternate должен быть true или false"
            )

        public_ip = str(raw.get("public_ip", "") or "").strip()
        if public_ip:
            public_ip = validate_public_ipv4(public_ip)
        elif mode == "public-ip":
            validate_public_ipv4(public_ip)

        return cls(
            address_mode=mode,
            public_ip=public_ip,
            include_alternate=include_alternate,
        )

    def as_state(self) -> dict[str, object]:
        """Возвращает стабильную схему для явного сохранения."""
        return {
            "address_mode": self.address_mode,
            "public_ip": self.public_ip,
            "include_alternate": self.include_alternate,
        }


def with_client_export_policy(
    state: Mapping[str, Any],
    *,
    address_mode: AddressMode,
    public_ip: str = "",
    include_alternate: bool = False,
) -> dict[str, Any]:
    """Возвращает глубокую копию state с временной политикой экспорта."""
    result = copy.deepcopy(dict(state))
    policy = ClientExportPolicy.from_state(
        {
            "client_export": {
                "address_mode": address_mode,
                "public_ip": public_ip,
                "include_alternate": include_alternate,
            }
        }
    )
    result["client_export"] = policy.as_state()
    return result


def client_connection_host(
    state: Mapping[str, Any],
    policy: ClientExportPolicy | None = None,
) -> str:
    """Выбирает endpoint клиента без мутации server/SNI/certificate state."""
    effective = policy or ClientExportPolicy.from_state(state)
    if effective.address_mode == "public-ip":
        return effective.public_ip
    return str(state.get("server", "") or "").strip()


def normalize_client_export_state(
    state: dict[str, Any],
) -> tuple[ClientExportPolicy, bool]:
    """Нормализует только явно существующий блок, сохраняя legacy state."""
    policy = ClientExportPolicy.from_state(state)
    if "client_export" not in state:
        return policy, False
    normalized = policy.as_state()
    changed = state.get("client_export") != normalized
    if changed:
        state["client_export"] = normalized
    return policy, changed


@dataclass(frozen=True, slots=True)
class SubscriptionIpReadiness:
    """Готовность HTTPS-подписки по IP: маршрут и IP SAN обязательны."""

    connection_host: str
    route_ready: bool
    certificate_ready: bool
    requested: bool

    @property
    def ready(self) -> bool:
        return self.requested and self.route_ready and self.certificate_ready


def subscription_ip_readiness(
    state: Mapping[str, Any],
    *,
    routed_hosts: Iterable[str],
    certificate_ip_sans: Iterable[str],
) -> SubscriptionIpReadiness:
    """Вычисляет готовность IP URL без сетевых вызовов и изменения state."""
    policy = ClientExportPolicy.from_state(state)
    connection_host = client_connection_host(state, policy)
    requested = policy.address_mode == "public-ip"
    routes = {str(value).strip() for value in routed_hosts}
    ip_sans = {str(value).strip() for value in certificate_ip_sans}
    return SubscriptionIpReadiness(
        connection_host=connection_host,
        route_ready=requested and connection_host in routes,
        certificate_ready=requested and connection_host in ip_sans,
        requested=requested,
    )


@dataclass(frozen=True, slots=True)
class ExportSection:
    """Один логический раздел пользовательского экспорта."""

    key: str
    title: str
    lines: tuple[str, ...]
    markdown_lines: tuple[str, ...] | None = None

    def selected_lines(self, *, markdown: bool) -> tuple[str, ...]:
        if markdown and self.markdown_lines is not None:
            return self.markdown_lines
        return self.lines

    def as_dict(self) -> dict[str, object]:
        return {
            "key": self.key,
            "title": self.title,
            "lines": list(self.lines),
        }


def render_export_document(
    title: str,
    sections: Iterable[ExportSection],
    *,
    markdown: bool,
    title_level: int = 1,
) -> str:
    """Рендерит одни sections в Markdown или текст для отправки."""
    lines = [
        f"{'#' * title_level} {title}" if markdown else title,
        "",
    ]
    for section in sections:
        section_title = (
            f"{'#' * (title_level + 1)} {section.title}"
            if markdown
            else section.title
        )
        lines.extend(
            [
                section_title,
                *section.selected_lines(markdown=markdown),
                "",
            ]
        )
    return "\n".join(lines)
