"""Стабильные X25519/shortId и права VLESS. Приватные данные не печатаются."""

import base64
from dataclasses import dataclass, field
from pathlib import Path
import re
import secrets
import subprocess
from uuid import UUID

from v5.core.packages.manifest import canonical_json, json_object
from v5.core.private_files import read_private, write_private

from .profiles import Kind


_PKCS8 = bytes.fromhex("302e020100300506032b656e04220420")
_SPKI = bytes.fromhex("302a300506032b656e032100")
_B64 = re.compile(r"[A-Za-z0-9_-]{43}", re.ASCII)
_SHORT = re.compile(r"(?:[0-9a-f]{2}){0,8}", re.ASCII)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _key(value: str) -> bytes:
    if not isinstance(value, str) or not _B64.fullmatch(value):
        raise ValueError("Некорректный ключ X25519")
    raw = base64.urlsafe_b64decode(value + "=")
    if _b64(raw) != value or raw == bytes(32):
        raise ValueError("Некорректный ключ X25519")
    return raw


def _openssl(*args: str, data: bytes | None = None) -> bytes:
    try:
        return subprocess.run(("/usr/bin/openssl", *args), input=data if data is not None else b"",
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              check=True, timeout=15, env={"LC_ALL": "C", "OPENSSL_CONF": "/dev/null"}).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Не удалось обработать X25519") from exc


def _der_value(der: bytes, prefix: bytes) -> bytes:
    if len(der) != len(prefix) + 32 or not der.startswith(prefix):
        raise ValueError("Неожиданный формат X25519")
    return der[len(prefix):]


@dataclass(frozen=True, slots=True)
class PublicReality:
    key: str
    short_id: str

    def __post_init__(self) -> None:
        _key(self.key)
        if not isinstance(self.short_id, str) or not _SHORT.fullmatch(self.short_id):
            raise ValueError("Некорректный shortId Reality")


@dataclass(frozen=True, slots=True)
class RealityKey:
    private: str = field(repr=False)
    public: PublicReality
    alternates: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _key(self.private)
        if (not isinstance(self.public, PublicReality) or not isinstance(self.alternates, tuple)
                or len(self.alternates) > 15 or any(not isinstance(item, str) or not _SHORT.fullmatch(item)
                                                   for item in self.alternates)
                or len(set(self.short_ids)) != len(self.short_ids)):
            raise ValueError("Не задан открытый ключ Reality")

    @property
    def short_ids(self) -> tuple[str, ...]:
        return (self.public.short_id, *self.alternates)

    @classmethod
    def from_private(cls, private: str, short_id: str, alternates: tuple[str, ...] = ()) -> "RealityKey":
        der = _openssl("pkey", "-inform", "DER", "-pubout", "-outform", "DER", data=_PKCS8 + _key(private))
        return cls(private, PublicReality(_b64(_der_value(der, _SPKI)), short_id), alternates)


@dataclass(frozen=True, slots=True)
class Account:
    name: str
    id: str = field(repr=False)
    grants: tuple[Kind, ...]

    def __post_init__(self) -> None:
        if (not isinstance(self.name, str) or not 1 <= len(self.name) <= 64
                or not all(ch.isalnum() or ch in " ._-" for ch in self.name)
                or self.name != self.name.strip()):
            raise ValueError("Некорректное имя пользователя Xray")
        try:
            if not isinstance(self.id, str) or str(UUID(self.id)) != self.id or not UUID(self.id).int:
                raise ValueError
        except ValueError as exc:
            raise ValueError("Некорректный идентификатор VLESS") from exc
        if (not isinstance(self.grants, tuple) or any(not isinstance(item, Kind) for item in self.grants)
                or len(set(self.grants)) != len(self.grants)):
            raise ValueError("Некорректные права VLESS")


def load_reality(path: Path, *, create: bool = False) -> RealityKey:
    try:
        raw = read_private(path, 1024)
    except FileNotFoundError:
        if not create:
            raise
        private = _b64(_der_value(_openssl("genpkey", "-algorithm", "X25519", "-outform", "DER"), _PKCS8))
        short = secrets.token_hex(8)
        try:
            write_private(path, canonical_json({"schema": 1, "private": private, "short_id": short}), replace=False)
        except FileExistsError:
            # Другой процесс уже создал ключ: используем сохранённый, ничего не меняем.
            pass
        raw = read_private(path, 1024)
    doc = json_object(raw)
    if doc.keys() != {"schema", "private", "short_id"} or type(doc["schema"]) is not int or doc["schema"] != 1:
        raise ValueError("Некорректная схема ключа Reality")
    return RealityKey.from_private(doc["private"], doc["short_id"])


def profile_reality_keys(path, profiles, *, imported=None, create=False) -> dict[Kind, RealityKey]:
    """Восстановленный ключ относится к конкретному профилю, не к соседнему режиму."""
    result, fallback = {}, None
    for profile in profiles:
        if profile.kind is Kind.TLS:
            continue
        item = imported.get(profile.kind.value) if imported is not None else None
        if item is not None:
            primary, *alternates = item["short_ids"]
            result[profile.kind] = RealityKey.from_private(item["private"], primary, tuple(alternates))
        else:
            if fallback is None:
                fallback = load_reality(path, create=create)
            result[profile.kind] = fallback
    return result
