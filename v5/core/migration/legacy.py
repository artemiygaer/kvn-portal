"""Чтение схемы .kvn v4.2 без зависимостей от прежнего приложения."""

from dataclasses import dataclass, field
import hashlib
import re
from uuid import UUID

from v5.core.packages.manifest import PackageError, json_object
from v5.core.users.model import User
from v5.core.users.store import MAX_USERS

from .crypto import ArchiveError, MAX_PLAINTEXT

FORMAT = "kvn-vpn-migration"
_DEFAULT_SYSTEMS = ("tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg")
_SYSTEMS = frozenset((*_DEFAULT_SYSTEMS, "wireguard", "amneziawg", "ocserv"))
_ENVELOPE = frozenset({"format", "version", "source_server", "users", "protocols"})
_USER_FIELDS = frozenset({"name", "uuid", "hysteria_password", "telemt_secret", "ocserv_password", "sub_token",
                         "enabled", "description", "device", "systems", "sni_overrides", "amneziawg", "wireguard"})
_PEER = frozenset({"private_key", "public_key", "preshared_key", "address"})
_TUNNEL = frozenset({"enabled", "port", "interface", "network", "server_address", "dns", "mtu", "private_key", "public_key"})
_REALITY = frozenset({"privateKey", "public_key", "short_id", "shortIds"})
_SECTION_FIELDS = {
    "reality": _REALITY, "reality_tcp": _REALITY,
    "xray": frozenset({"xhttp_mode", "reality_xhttp_server_names"}),
    "telemt": frozenset({"camouflage_origin", "extra_users"}),
    "mtg": frozenset({"camouflage_origin", "secret16"}),
    "wireguard": _TUNNEL,
    "amneziawg": _TUNNEL | {"route_mode", "route_excludes", "compact_route_excludes", "protocol_version", "obfuscation", "v3"},
    "ocserv": frozenset({"enabled", "sni_enabled", "sni", "tcp_port", "dtls_enabled", "udp_port", "front_snis", "network",
                         "dns", "max_clients", "max_same_clients", "mtu"}),
}
_AWG_FIELDS = frozenset({"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
                         "I1", "I2", "I3", "I4", "I5"})
_AWG_V3 = frozenset({"header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout",
                     "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies"})
_ROUTE_FIELDS = frozenset({"default", "dest", "aliases", "reality_mode"})
_NAME = re.compile(r"[A-Za-z0-9_.-]{2,32}\Z", re.ASCII)
_TOKEN = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)


@dataclass(frozen=True, slots=True)
class LegacyUser:
    user: User
    systems: tuple[str, ...]
    skipped: tuple[str, ...]
    token_digest: bytes = field(repr=False)
    credentials: dict = field(repr=False)


@dataclass(frozen=True, slots=True)
class LegacyArchive:
    users: tuple[LegacyUser, ...]
    protocols: dict = field(repr=False)


def _bad():
    raise ArchiveError("migration_schema_invalid")


def _object(value, allowed, *, required=()):
    if not isinstance(value, dict) or value.keys() - allowed or not set(required) <= value.keys():
        _bad()
    return value


def _check_bounds(value):
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 12 or nodes > 100_000:
            _bad()
        if isinstance(item, dict):
            if len(item) > 2048 or any(len(name) > 128 or "\x00" in name for name in item):
                _bad()
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if len(item) > 2048:
                _bad()
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > 4096 or "\x00" in item:
                _bad()
        elif not (item is None or type(item) is bool or type(item) is int and -2**63 <= item < 2**63):
            _bad()


def _protocols(raw):
    raw = _object(raw, _SECTION_FIELDS.keys() | {"sni_routes"})
    result = {name: _object(value, _SECTION_FIELDS[name]) for name, value in raw.items() if name != "sni_routes"}
    if "sni_routes" in raw:
        for name, route in _object(raw["sni_routes"], _SYSTEMS | {"custom"}).items():
            if name == "custom":
                if not isinstance(route, list):
                    _bad()
                for item in route:
                    _object(item, {"sni", "dest"})
            else:
                _object(route, _ROUTE_FIELDS)
    awg = result.get("amneziawg", {})
    if "obfuscation" in awg:
        _object(awg["obfuscation"], _AWG_FIELDS)
    if "v3" in awg:
        _object(awg["v3"], _AWG_V3)
    if "extra_users" in result.get("telemt", {}):
        extra = result["telemt"]["extra_users"]
        if not isinstance(extra, dict) or any(not _NAME.fullmatch(name) or not isinstance(secret, str)
                                               for name, secret in extra.items()):
            _bad()
    # Старые сетевые правила и OpenConnect не переходят в состояние v5.
    result.pop("ocserv", None)
    return result


def _user(raw) -> LegacyUser:
    raw = _object(raw, _USER_FIELDS, required=("name", "uuid", "sub_token", "hysteria_password", "telemt_secret"))
    name, uid, token = raw["name"], raw["uuid"], raw["sub_token"]
    if (not isinstance(name, str) or not _NAME.fullmatch(name) or name == ".."
            or not isinstance(uid, str) or not isinstance(token, str) or not _TOKEN.fullmatch(token)
            or type(raw.get("enabled", True)) is not bool):
        _bad()
    try:
        identity = UUID(uid)
    except ValueError:
        _bad()
    if not identity.int:
        _bad()
    systems = raw.get("systems", list(_DEFAULT_SYSTEMS))
    if (not isinstance(systems, list) or any(not isinstance(item, str) or item not in _SYSTEMS for item in systems)
            or len(systems) != len(set(systems))):
        _bad()
    for name_field in ("description", "device", "ocserv_password"):
        if name_field in raw and not isinstance(raw[name_field], str):
            _bad()
    if "sni_overrides" in raw:
        overrides = _object(raw["sni_overrides"], frozenset(_DEFAULT_SYSTEMS[:4]))
        if any(not isinstance(value, str) for value in overrides.values()):
            _bad()
    credentials = {"uuid": str(identity)}
    for module, key in (("hysteria", "hysteria_password"), ("telemt", "telemt_secret")):
        if not isinstance(raw[key], str) or not raw[key]:
            _bad()
        if module in systems:
            credentials[key] = raw[key]
    for module in ("wireguard", "amneziawg"):
        if module in raw:
            peer = _object(raw[module], _PEER, required=_PEER if module in systems else ())
            if any(not isinstance(value, str) or (module in systems and not value) for value in peer.values()):
                _bad()
            if module in systems:
                credentials[module] = peer
        elif module in systems:
            _bad()
    return LegacyUser(User(identity.hex, name, raw.get("enabled", True)),
                      tuple(item for item in systems if item != "ocserv"),
                      ("ocserv",) if "ocserv" in systems else (),
                      hashlib.sha256(token.encode("ascii")).digest(), credentials)


def legacy_document(raw: dict) -> LegacyArchive:
    _check_bounds(raw)
    raw = _object(raw, _ENVELOPE, required=_ENVELOPE)
    if (raw["format"] != FORMAT or type(raw["version"]) is not int or raw["version"] != 1
            or not isinstance(raw["source_server"], str)):
        raise ArchiveError("migration_version_unsupported")
    if not isinstance(raw["users"], list) or len(raw["users"]) > MAX_USERS:
        raise ArchiveError("migration_users_limit")
    users = tuple(_user(row) for row in raw["users"])
    if (len({row.user.name.casefold() for row in users}) != len(users)
            or len({row.user.id for row in users}) != len(users)
            or len({row.token_digest for row in users}) != len(users)):
        raise ArchiveError("migration_identity_conflict")
    return LegacyArchive(users, _protocols(raw["protocols"]))


def parse_legacy(data: bytes) -> LegacyArchive:
    """Только декодирование; типизация ключей и проверка конфликтов выполняются до commit."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PLAINTEXT:
        raise ArchiveError("migration_archive_size")
    try:
        raw = json_object(data)
    except PackageError:
        raise ArchiveError("migration_schema_invalid") from None
    return legacy_document(raw)
