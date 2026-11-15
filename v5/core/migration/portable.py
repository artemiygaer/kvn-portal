"""Переносимые учётные данные: без маршрутов, установочных команд и runtime."""

import base64
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface
import re
from uuid import UUID

from v5.core.contracts import MODULE_IDS
from v5.core.packages.manifest import canonical_json, json_object
from v5.core.users.model import User
from v5.core.users.store import MAX_USERS
from v5.modules.mtproto_common.profiles import valid_user as valid_telemt_user

from .crypto import ArchiveError, MAX_PLAINTEXT
from .legacy import FORMAT, LegacyArchive, _AWG_FIELDS, _AWG_V3, _check_bounds, _object

XRAY_PROFILES = frozenset({"tls", "reality-xhttp", "reality-tcp"})
TUNNELS = frozenset({"amneziawg", "wireguard"})
_DIGEST = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_SECRET = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)
_SHORT_ID = re.compile(r"(?:[a-fA-F0-9]{2}){0,8}\Z", re.ASCII)
_PEER = frozenset({"private_key", "public_key", "preshared_key", "address"})
_USER = frozenset({"id", "name", "enabled", "token_digest", "grants", "credentials", "skipped"})


def _require(condition):
    if not condition:
        raise ArchiveError("migration_credentials_invalid")


def _key(value, *, urlsafe=False):
    _require(isinstance(value, str))
    pattern = r"[A-Za-z0-9_-]{43}=?" if urlsafe else r"[A-Za-z0-9+/]{43}="
    _require(re.fullmatch(pattern, value, flags=re.ASCII))
    encoded = value.rstrip("=") + "="
    result = base64.b64decode(encoded, altchars=b"-_" if urlsafe else None, validate=True)
    normalized = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(result).decode("ascii")
    _require(normalized == encoded and result != bytes(32))
    return normalized.rstrip("=") if urlsafe else normalized


def _secret(value):
    _require(isinstance(value, str) and _SECRET.fullmatch(value))
    return value


def normalize_credential(module, value):
    if module == "xray":
        row = _object(value, {"uuid", "profiles"}, required={"uuid", "profiles"})
        _require(isinstance(row["uuid"], str) and UUID(row["uuid"]).int != 0)
        profiles = row["profiles"]
        _require(isinstance(profiles, list) and profiles and all(isinstance(p, str) and p in XRAY_PROFILES for p in profiles)
                 and len(profiles) == len(set(profiles)))
        return {"uuid": str(UUID(row["uuid"])), "profiles": sorted(profiles)}
    if module == "hysteria":
        row = _object(value, {"login", "password"}, required={"login", "password"})
        _require(isinstance(row["login"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", row["login"])
                 and row["login"] not in {".", "..", "_kvn_no_user"})
        _require(isinstance(row["password"], str) and re.fullmatch(r"[!-~]{1,128}", row["password"]))
        return {"login": row["login"], "password": row["password"]}
    if module == "telemt":
        row = _object(value, {"secret"}, required={"secret"})
        return {"secret": _secret(row["secret"])}
    if module in TUNNELS:
        row = _object(value, _PEER, required=_PEER)
        _require(isinstance(row["address"], str))
        interface = IPv4Interface(row["address"])
        _require(interface.network.prefixlen == 32)
        return {"address": str(interface.ip), **{name: _key(row[name]) for name in _PEER - {"address"}}}
    raise ArchiveError("migration_credentials_invalid")


def _reality(value):
    names = {"private", "short_ids"}
    row = _object(value, names, required=names)
    short = row["short_ids"]
    _require(isinstance(short, list) and 1 <= len(short) <= 16
             and all(isinstance(item, str) and _SHORT_ID.fullmatch(item) for item in short)
             and len({item.lower() for item in short}) == len(short))
    return {"private": _key(row["private"], urlsafe=True), "short_ids": [item.lower() for item in short]}


def normalize_seed(module, value):
    if module == "xray":
        return {kind: _reality(identity) for kind, identity in
                _object(value, XRAY_PROFILES - {"tls"}).items()}
    if module == "mtg":
        return {"secret": _secret(_object(value, {"secret"}, required={"secret"})["secret"])}
    if module == "telemt":
        _require(isinstance(value, dict) and len(value) <= 256 and all(valid_telemt_user(name) for name in value))
        _require(len({name.casefold() for name in value}) == len(value))
        result = {}
        for name, item in value.items():
            if isinstance(item, dict):
                row = _object(item, {"secret", "enabled"}, required={"secret", "enabled"})
                _require(type(row["enabled"]) is bool)
                result[name] = {"secret": _secret(row["secret"]), "enabled": row["enabled"]}
            else:
                result[name] = _secret(item)
        return result
    if module in TUNNELS:
        allowed = {"private_key", "public_key", "address", "mtu"}
        if module == "amneziawg":
            allowed.update({"mode", "obfuscation", "v3"})
        row = _object(value, allowed, required={"private_key", "public_key"})
        normalized = {name: _key(row[name]) for name in ("private_key", "public_key")}
        if "address" in row:
            _require(isinstance(row["address"], str))
            normalized["address"] = str(IPv4Interface(row["address"]))
        if "mtu" in row:
            _require(type(row["mtu"]) is int and 576 <= row["mtu"] <= 1420)
            normalized["mtu"] = row["mtu"]
        if module == "amneziawg":
            mode = row.get("mode", "legacy")
            _require(mode in ("legacy", "3.1"))
            normalized["mode"] = mode
            fields = _object(row.get("obfuscation", {}), _AWG_FIELDS)
            _require(all(type(val) in (int, str) for val in fields.values()))
            if fields:
                normalized["obfuscation"] = fields
            if mode == "3.1":
                v3 = _object(row.get("v3"), _AWG_V3, required={"header_protection_key"})
                _require(all(type(val) in (str, int, bool) for val in v3.values()))
                normalized["v3"] = {**v3, "header_protection_key": _key(v3["header_protection_key"])}
        return normalized
    raise ArchiveError("migration_credentials_invalid")


@dataclass(frozen=True, slots=True)
class PortableUser:
    user: User
    grants: tuple[tuple[str, bool], ...]
    token_digest: bytes | None = field(repr=False)
    credentials: tuple[tuple[str, bytes], ...] = field(repr=False)
    skipped: tuple[str, ...]

    @classmethod
    def parse(cls, value):
        row = _object(value, _USER, required=_USER)
        user = User(row["id"], row["name"], row["enabled"])
        digest = row["token_digest"]
        _require(digest is None or isinstance(digest, str) and _DIGEST.fullmatch(digest))
        grants = _object(row["grants"], MODULE_IDS)
        _require(all(type(enabled) is bool for enabled in grants.values()))
        skipped = row["skipped"]
        _require(skipped in ([], ["ocserv"]))
        credentials = _object(row["credentials"], grants.keys() - {"mtg"})
        return cls(user, tuple(sorted(grants.items())), bytes.fromhex(digest) if digest else None,
                   tuple(sorted((name, canonical_json(normalize_credential(name, data))) for name, data in credentials.items())),
                   tuple(skipped))

    def document(self):
        return {"id": self.user.id, "name": self.user.name, "enabled": self.user.enabled,
                "token_digest": self.token_digest.hex() if self.token_digest is not None else None,
                "grants": dict(self.grants), "credentials": {name: json_object(data) for name, data in self.credentials},
                "skipped": list(self.skipped)}


@dataclass(frozen=True, slots=True)
class PortableArchive:
    users: tuple[PortableUser, ...]
    seeds: tuple[tuple[str, bytes], ...] = field(repr=False)

    @classmethod
    def parse(cls, value):
        keys = {"format", "version", "users", "seeds"}
        try:
            _check_bounds(value)
            value = _object(value, keys, required=keys)
            _require(value["format"] == FORMAT and type(value["version"]) is int and value["version"] == 2)
            _require(isinstance(value["users"], list) and len(value["users"]) <= MAX_USERS)
            users = tuple(PortableUser.parse(item) for item in value["users"])
            seeds = tuple(sorted((module, canonical_json(normalize_seed(module, item))) for module, item in
                                 _object(value["seeds"], MODULE_IDS - {"hysteria"}).items()))
            cls._unique(users, seeds)
            return cls(users, seeds)
        except ArchiveError:
            raise
        except (ValueError, TypeError, OverflowError):
            raise ArchiveError("migration_credentials_invalid") from None

    @staticmethod
    def _unique(users, seeds):
        identities, names, tokens, per_module = set(), set(), set(), {}

        def add(seen, value):
            if value in seen:
                raise ArchiveError("migration_identity_conflict")
            seen.add(value)

        for row in users:
            add(identities, row.user.id)
            add(names, row.user.name.casefold())
            if row.token_digest is not None:
                add(tokens, row.token_digest)
            if any(module == "telemt" for module, _ in row.grants):
                add(per_module.setdefault(("telemt", "name"), set()), row.user.id.casefold())
            for module, raw in row.credentials:
                credential = json_object(raw)
                fields = ({"uuid"} if module == "xray" else {"login"} if module == "hysteria" else {"secret"} if module == "telemt" else
                          {"address", "public_key"} if module in TUNNELS else set())
                for key in fields:
                    add(per_module.setdefault((module, key), set()), credential[key])
        for module, raw in seeds:
            if module in TUNNELS:
                server = json_object(raw)
                add(per_module.setdefault((module, "public_key"), set()), server["public_key"])
                if "address" in server:
                    add(per_module.setdefault((module, "address"), set()), str(IPv4Address(server["address"].split("/")[0])))
            if module == "telemt":
                for name, item in json_object(raw).items():
                    add(per_module.setdefault((module, "name"), set()), name.casefold())
                    add(per_module.setdefault((module, "secret"), set()), item["secret"] if isinstance(item, dict) else item)

    def document(self):
        return {"format": FORMAT, "version": 2, "users": [row.document() for row in self.users],
                "seeds": {module: json_object(data) for module, data in self.seeds}}

    def encode(self):
        raw = canonical_json(self.document())
        if len(raw) > MAX_PLAINTEXT:
            raise ArchiveError("migration_archive_size")
        return raw


def from_legacy(archive: LegacyArchive) -> PortableArchive:
    users, seeds = [], {}
    for item in archive.users:
        grants = {"xray" if protocol in XRAY_PROFILES else protocol: True for protocol in item.systems}
        values = item.credentials
        credentials = {name: values[name] for name in TUNNELS if name in values}
        if "xray" in grants:
            credentials["xray"] = {"uuid": values["uuid"], "profiles": sorted(XRAY_PROFILES.intersection(item.systems))}
        if "hysteria" in grants:
            credentials["hysteria"] = {"login": item.user.name, "password": values["hysteria_password"]}
        if "telemt" in grants:
            credentials["telemt"] = {"secret": values["telemt_secret"]}
        users.append({"id": item.user.id, "name": item.user.name, "enabled": item.user.enabled,
                      "token_digest": item.token_digest.hex(), "grants": grants, "credentials": credentials,
                      "skipped": list(item.skipped)})
    protocols = archive.protocols
    reality = {kind: {"private": protocols[section].get("privateKey"),
                      "short_ids": protocols[section].get("shortIds") or [protocols[section].get("short_id")]}
               for kind, section in (("reality-xhttp", "reality"), ("reality-tcp", "reality_tcp")) if section in protocols}
    if reality:
        seeds["xray"] = reality
    for module in TUNNELS.intersection(protocols):
        value = protocols[module]
        seed = {name: value[name] for name in ("private_key", "public_key", "mtu") if name in value}
        if value.get("server_address"):
            seed["address"] = value["server_address"]
        if module == "amneziawg":
            seed["mode"] = value.get("protocol_version", "legacy")
            seed.update({name: value[name] for name in ("obfuscation", "v3") if name in value})
        seeds[module] = seed
    if "mtg" in protocols:
        seeds["mtg"] = {"secret": protocols["mtg"].get("secret16")}
    if protocols.get("telemt", {}).get("extra_users"):
        seeds["telemt"] = protocols["telemt"]["extra_users"]
    return PortableArchive.parse({"format": FORMAT, "version": 2, "users": users, "seeds": seeds})
