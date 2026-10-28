"""Строгая схема административного архива переноса VPN, без системных вызовов."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import uuid
import copy

FORMAT = "kvn-vpn-migration"
FORMAT_VERSION = 1
MAX_USERS = 2048
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 12
MAX_NODES = 100_000
MAX_STRING = 4096
SYSTEMS = frozenset({"tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg", "amneziawg", "wireguard", "ocserv"})
USER_FIELDS = frozenset({"name", "uuid", "hysteria_password", "telemt_secret", "ocserv_password", "sub_token", "enabled", "description", "device", "systems", "sni_overrides", "amneziawg", "wireguard"})
PEER_FIELDS = frozenset({"private_key", "public_key", "preshared_key", "address"})
SECTION_FIELDS = {
    "reality": frozenset({"privateKey", "public_key", "short_id", "shortIds"}),
    "reality_tcp": frozenset({"privateKey", "public_key", "short_id", "shortIds"}),
    "xray": frozenset({"xhttp_mode", "reality_xhttp_server_names"}),
    "telemt": frozenset({"camouflage_origin", "extra_users"}),
    "mtg": frozenset({"camouflage_origin", "secret16"}),
    "ocserv": frozenset({"enabled", "sni_enabled", "sni", "tcp_port", "dtls_enabled", "udp_port", "front_snis", "network", "dns", "max_clients", "max_same_clients", "mtu"}),
    "amneziawg": frozenset({"enabled", "port", "interface", "network", "server_address", "dns", "mtu", "route_mode", "route_excludes", "compact_route_excludes", "protocol_version", "obfuscation", "v3", "private_key", "public_key"}),
    "wireguard": frozenset({"enabled", "port", "interface", "network", "server_address", "dns", "mtu", "private_key", "public_key"}),
}
OBFUSCATION_FIELDS = frozenset({"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"})
AWG3_FIELDS = frozenset({"header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts", "random_trailers", "disable_cookies"})
ROUTE_FIELDS = frozenset({"default", "dest", "aliases", "reality_mode"})
NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")


class MigrationValidationError(ValueError):
    """Ошибка без вывода содержимого архива или секретных значений."""


def _object(value: object, allowed: frozenset, label: str) -> dict:
    if not isinstance(value, dict) or any(not isinstance(k, str) or k not in allowed for k in value):
        raise MigrationValidationError(f"Недопустимая структура или поле: {label}.")
    return value


def _bounds(value: object) -> None:
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise MigrationValidationError("Слишком сложный архив миграции.")
        if isinstance(item, dict):
            if len(item) > MAX_USERS:
                raise MigrationValidationError("Слишком много полей в архиве.")
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > 128:
                    raise MigrationValidationError("Недопустимое имя поля архива.")
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            if len(item) > MAX_USERS:
                raise MigrationValidationError("Слишком длинный список в архиве.")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > MAX_STRING or "\x00" in item:
                raise MigrationValidationError("Недопустимая строка в архиве.")
        elif item is not None and not isinstance(item, (bool, int)):
            raise MigrationValidationError("Недопустимый тип в архиве.")
        elif isinstance(item, int) and not isinstance(item, bool) and abs(item) > 2**63 - 1:
            raise MigrationValidationError("Слишком большое число в архиве.")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise MigrationValidationError("Повторяющееся поле JSON в архиве.")
        result[key] = value
    return result


def parse_migration(data: bytes) -> dict:
    """Читает JSON ограниченного размера, отклоняя неоднозначные и новые поля."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_JSON_BYTES:
        raise MigrationValidationError("Недопустимый размер архива миграции.")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(MigrationValidationError("Недопустимое число JSON.")))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise MigrationValidationError("Некорректный формат архива миграции.") from exc
    validate_migration(value)
    return value


def validate_migration(value: object) -> dict:
    _bounds(value)
    envelope = _object(value, frozenset({"format", "version", "source_server", "users", "protocols"}), "архив")
    if set(envelope) != {"format", "version", "source_server", "users", "protocols"}:
        raise MigrationValidationError("Архив не содержит обязательные поля.")
    if envelope["format"] != FORMAT or type(envelope["version"]) is not int or envelope["version"] != FORMAT_VERSION:
        raise MigrationValidationError("Неподдерживаемый формат или версия архива.")
    if not isinstance(envelope["source_server"], str):
        raise MigrationValidationError("Некорректный адрес исходного сервера.")
    protocols = _object(envelope["protocols"], frozenset(SECTION_FIELDS) | {"sni_routes"}, "protocols")
    for section, item in protocols.items():
        if section == "sni_routes":
            routes = _object(item, SYSTEMS | {"custom"}, "sni_routes")
            for route_name, route in routes.items():
                if route_name == "custom":
                    if not isinstance(route, list):
                        raise MigrationValidationError("Некорректные пользовательские маршруты.")
                    for custom in route:
                        _object(custom, frozenset({"sni", "dest"}), "custom route")
                else:
                    _object(route, ROUTE_FIELDS, "маршрут SNI")
            continue
        section_value = _object(item, SECTION_FIELDS[section], section)
        if section == "amneziawg":
            if "obfuscation" in section_value:
                _object(section_value["obfuscation"], OBFUSCATION_FIELDS, "AWG obfuscation")
            if "v3" in section_value:
                _object(section_value["v3"], AWG3_FIELDS, "AWG v3")
        if section == "telemt" and "extra_users" in section_value:
            extra = section_value["extra_users"]
            if not isinstance(extra, dict) or any(not NAME_PATTERN.fullmatch(k) or not isinstance(v, str) for k, v in extra.items()):
                raise MigrationValidationError("Некорректные дополнительные пользователи Telemt.")
    users = envelope["users"]
    if not isinstance(users, list) or len(users) > MAX_USERS:
        raise MigrationValidationError("Некорректный список пользователей.")
    names, uuids, tokens = set(), set(), set()
    addresses = {"amneziawg": set(), "wireguard": set()}
    public_keys = {"amneziawg": set(), "wireguard": set()}
    for user in users:
        _object(user, USER_FIELDS, "пользователь")
        name = user.get("name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or name.casefold() in names:
            raise MigrationValidationError("Недопустимое или повторяющееся имя пользователя.")
        names.add(name.casefold())
        if "enabled" in user and not isinstance(user["enabled"], bool):
            raise MigrationValidationError("Некорректный статус пользователя.")
        for field in ("uuid", "hysteria_password", "telemt_secret", "ocserv_password", "sub_token", "description", "device"):
            if field in user and not isinstance(user[field], str):
                raise MigrationValidationError("Некорректное поле пользователя.")
        if user.get("uuid"):
            try:
                key = uuid.UUID(user["uuid"])
            except (ValueError, AttributeError) as exc:
                raise MigrationValidationError("Некорректный UUID пользователя.") from exc
            if key in uuids:
                raise MigrationValidationError("Повторяющийся UUID пользователя.")
            uuids.add(key)
        token = user.get("sub_token", "")
        if token:
            if not re.fullmatch(r"[0-9a-f]{32}", token) or token in tokens:
                raise MigrationValidationError("Некорректный или повторяющийся токен подписки.")
            tokens.add(token)
        systems = user.get("systems", [])
        if not isinstance(systems, list) or any(not isinstance(s, str) or s not in SYSTEMS for s in systems) or len(set(systems)) != len(systems):
            raise MigrationValidationError("Некорректный список VPN-систем пользователя.")
        if "sni_overrides" in user:
            overrides = _object(user["sni_overrides"], frozenset({"tls", "reality-xhttp", "reality-tcp", "hysteria"}), "SNI пользователя")
            if any(not isinstance(domain, str) for domain in overrides.values()):
                raise MigrationValidationError("Некорректный SNI пользователя.")
        for system in addresses:
            if system not in user:
                continue
            peer = _object(user[system], PEER_FIELDS, "VPN peer")
            if any(not isinstance(v, str) for v in peer.values()):
                raise MigrationValidationError("Некорректные данные VPN peer.")
            public_key = peer.get("public_key", "")
            if public_key:
                if public_key in public_keys[system]:
                    raise MigrationValidationError("Повторяющийся публичный ключ VPN peer.")
                public_keys[system].add(public_key)
            if peer.get("address"):
                try:
                    addr = ipaddress.ip_interface(peer["address"]).ip
                except ValueError as exc:
                    raise MigrationValidationError("Некорректный адрес VPN peer.") from exc
                if addr in addresses[system]:
                    raise MigrationValidationError("Повторяющийся адрес VPN peer.")
                addresses[system].add(addr)
    extra_users = protocols.get("telemt", {}).get("extra_users", {})
    if any(name.casefold() in names for name in extra_users):
        raise MigrationValidationError("Имя пользователя совпадает с дополнительной учётной записью Telemt.")
    for system, keys in public_keys.items():
        if protocols.get(system, {}).get("public_key") in keys:
            raise MigrationValidationError("Ключ VPN peer совпадает с ключом сервера.")
    return envelope


def plan_migration(target: dict, envelope: dict, mode: str) -> dict:
    """Готовит новую копию state; никакие изменения на диск не записываются."""
    validate_migration(envelope)
    if not isinstance(target, dict) or not isinstance(target.get("users", []), list):
        raise MigrationValidationError("Некорректное состояние целевого сервера.")
    if mode not in {"restore", "merge"}:
        raise MigrationValidationError("Неизвестный режим переноса.")
    if mode == "restore" and target.get("users", []):
        raise MigrationValidationError("Полное восстановление доступно только на пустой VPN-цели.")
    result = copy.deepcopy(target)
    if mode == "restore":
        # Runtime-учётные данные, endpoint, сертификаты и настройки портала не переносятся.
        for name, section in envelope["protocols"].items():
            previous = result.get(name)
            incoming = copy.deepcopy(section)
            if name in {"amneziawg", "wireguard", "ocserv"} and isinstance(previous, dict) and "enabled" in previous:
                incoming["enabled"] = previous["enabled"]
            result[name] = incoming
        result["users"] = copy.deepcopy(envelope["users"])
    else:
        result["users"] = copy.deepcopy(target.get("users", [])) + copy.deepcopy(envelope["users"])

    # Повторная проверка уже объединённого набора выявляет конфликты с целевыми пользователями.
    candidate = {"format": FORMAT, "version": FORMAT_VERSION, "source_server": str(result.get("server", "")),
                 "users": result["users"], "protocols": {name: result[name] for name in (*SECTION_FIELDS, "sni_routes") if name in result}}
    validate_migration(candidate)
    for system, default in (("amneziawg", "10.66.66.0/24"), ("wireguard", "10.88.88.0/24")):
        config = result.get(system, {})
        try:
            network = ipaddress.ip_network(config.get("network", default), strict=False)
            server_ip = ipaddress.ip_interface(config.get("server_address", str(network.network_address + 1))).ip
        except (AttributeError, TypeError, ValueError) as exc:
            raise MigrationValidationError("Некорректная сеть VPN на целевом сервере.") from exc
        for user in result["users"]:
            peer = user.get(system, {})
            if peer.get("address"):
                address = ipaddress.ip_interface(peer["address"]).ip
                if address not in network or address == server_ip or address in {network.network_address, network.broadcast_address}:
                    raise MigrationValidationError("Адрес VPN peer несовместим с сетью целевого сервера.")
    return result


def validate_identity_complete(envelope: dict) -> None:
    """Не допускает импорт, после которого render молча создаст новые ключи."""
    validate_migration(envelope)
    protocols = envelope["protocols"]

    def valid_wg_key(value: object) -> bool:
        if not isinstance(value, str):
            return False
        try:
            return len(base64.b64decode(value, validate=True)) == 32
        except (ValueError, binascii.Error):
            return False

    for name in ("reality", "reality_tcp"):
        reality = protocols.get(name, {})
        private = reality.get("privateKey")
        short_ids = reality.get("shortIds") or [reality.get("short_id")]
        try:
            private_valid = isinstance(private, str) and len(base64.b64decode(private + "=" * (-len(private) % 4), altchars=b"-_", validate=True)) == 32
        except (ValueError, binascii.Error):
            private_valid = False
        if (not private_valid or not isinstance(short_ids, list) or not short_ids
                or any(not isinstance(short_id, str) or not re.fullmatch(r"[0-9a-fA-F]{0,16}", short_id) for short_id in short_ids)):
            raise MigrationValidationError("В архиве отсутствует полная Reality identity.")
    for name in ("amneziawg", "wireguard"):
        config = protocols.get(name, {})
        if any(not valid_wg_key(config.get(key)) for key in ("private_key", "public_key")):
            raise MigrationValidationError("В архиве отсутствует ключ сервера VPN.")
    awg = protocols["amneziawg"]
    if awg.get("protocol_version") == "3.1" and not valid_wg_key(awg.get("v3", {}).get("header_protection_key")):
        raise MigrationValidationError("В архиве отсутствует ключ заголовка AWG 3.1.")
    if not re.fullmatch(r"[0-9a-f]{32}", str(protocols.get("mtg", {}).get("secret16", ""))):
        raise MigrationValidationError("В архиве отсутствует секрет MTProto.")
    for user in envelope["users"]:
        if any(not user.get(key) for key in ("uuid", "hysteria_password", "telemt_secret", "sub_token")):
            raise MigrationValidationError("В архиве отсутствуют учётные данные пользователя.")
        systems = user.get("systems", ["tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg"])
        if "ocserv" in systems and not user.get("ocserv_password"):
            raise MigrationValidationError("В архиве отсутствует пароль OpenConnect.")
        for name in ("amneziawg", "wireguard"):
            if name in systems:
                peer = user.get(name, {})
                if not peer.get("address") or any(not valid_wg_key(peer.get(key)) for key in ("private_key", "public_key", "preshared_key")):
                    raise MigrationValidationError("В архиве отсутствует ключ или адрес VPN peer.")
