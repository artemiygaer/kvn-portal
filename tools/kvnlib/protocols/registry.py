"""Единственный registry поддерживаемых пользовательских systems."""

from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class SystemCapability:
    key: str
    label: str
    runtime: str
    sni_scope: str
    default_user_enabled: bool

SYSTEM_CAPABILITIES = (
    SystemCapability("tls", "VLESS TLS Vision", "xray", "per_user", True),
    SystemCapability("reality-xhttp", "Reality xHTTP", "xray", "per_user", True),
    SystemCapability("reality-tcp", "Reality TCP Vision", "xray", "per_user", True),
    SystemCapability("hysteria", "Hysteria 2", "hysteria", "per_user", True),
    SystemCapability("telemt", "Telemt MTProto TLS", "telemt", "service", True),
    SystemCapability("mtg", "MTProto (mtg, FakeTLS)", "mtg", "service", True),
    SystemCapability("amneziawg", "AmneziaWG", "host", "not_applicable", False),
    SystemCapability("wireguard", "WireGuard", "host", "not_applicable", False),
    SystemCapability("ocserv", "OpenConnect (ocserv)", "host", "service", False),
)

SYSTEMS = tuple(item.key for item in SYSTEM_CAPABILITIES)
if len(SYSTEMS) != len(set(SYSTEMS)):
    raise RuntimeError("Registry systems содержит дубликаты.")

BY_SYSTEM = {item.key: item for item in SYSTEM_CAPABILITIES}
DEFAULT_USER_SYSTEMS = tuple(item.key for item in SYSTEM_CAPABILITIES if item.default_user_enabled)
SYSTEM_LABELS = {item.key: item.label for item in SYSTEM_CAPABILITIES}

__all__ = ["BY_SYSTEM", "DEFAULT_USER_SYSTEMS", "SYSTEMS", "SYSTEM_CAPABILITIES", "SYSTEM_LABELS", "SystemCapability"]
