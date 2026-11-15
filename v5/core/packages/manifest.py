"""Строгий формат подписанных метаданных. Имена ресурсов назначает ядро."""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import NoReturn

from v5.core.contracts import (
    ADAPTER_API_VERSION, CORE_API_VERSION, PACKAGE_FORMAT_VERSION, validate_module_id,
)

MAX_MANIFEST = 16 * 1024
MAX_PACKAGE = 256 * 1024**2
MAX_IMAGE = 512 * 1024**2
MAX_NOTES = 32 * 1024
MAX_TAR = MAX_IMAGE + 128 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}")
UTC_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
IMAGES = {
    "xray": "ghcr.io/xtls/xray-core",
    "hysteria": "docker.io/tobyxdd/hysteria",
    "telemt": "ghcr.io/telemt/telemt",
    "mtg": "docker.io/nineseconds/mtg",
}


class PackageError(ValueError):
    """Причина безопасна для вывода: содержит только код ядра."""


def reject(code: str) -> NoReturn:
    raise PackageError(code)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            reject("duplicate_json_key")
        result[key] = value
    return result


def json_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=lambda _: reject("invalid_json"))
    except PackageError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        reject("invalid_json")
    if not isinstance(value, dict):
        reject("invalid_json")
    return value


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")


def _keys(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or value.keys() != keys:
        reject("unsupported_manifest_fields")
    return value


def _match(pattern: re.Pattern, value: object, code: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        reject(code)
    return value


def version_key(value: object) -> tuple[int, ...]:
    return tuple(map(int, _match(VERSION, value, "invalid_module_version").split(".")))


def _timestamp(value: object) -> datetime:
    value = _match(UTC_STAMP, value, "invalid_package_time")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        reject("invalid_package_time")


@dataclass(frozen=True)
class Resource:
    kind: str
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class Manifest:
    module_id: str
    version: str
    issued_at: datetime
    expires_at: datetime
    image_digest: str | None
    resources: tuple[Resource, ...]

    @property
    def image_ref(self) -> str | None:
        if self.image_digest is None:
            return None
        return f"{IMAGES[self.module_id]}@sha256:{self.image_digest}"

    @property
    def offline_image(self) -> bool:
        return any(resource.kind == "image" for resource in self.resources)

    def check_fresh(self, now: datetime) -> None:
        if self.issued_at > now + timedelta(minutes=5):
            reject("package_not_yet_valid")
        if self.expires_at <= now:
            reject("package_expired")


def parse_manifest(raw: bytes, now: datetime | None = None, *, installed: bool = False) -> Manifest:
    if not 0 < len(raw) <= MAX_MANIFEST:
        reject("manifest_size")
    doc = _keys(json_object(raw), {
        "format", "core_api", "adapter_api", "module_id", "version",
        "issued_at", "expires_at", "image_digest", "resources",
    })
    for field, expected in (("format", PACKAGE_FORMAT_VERSION), ("core_api", CORE_API_VERSION),
                            ("adapter_api", ADAPTER_API_VERSION)):
        if type(doc[field]) is not int or doc[field] != expected:
            reject("incompatible_package")
    try:
        module_id = validate_module_id(doc["module_id"])
    except ValueError:
        reject("unsupported_module")
    version_key(doc["version"])
    issued, expires = _timestamp(doc["issued_at"]), _timestamp(doc["expires_at"])
    if not timedelta(0) < expires - issued <= timedelta(days=366):
        reject("invalid_package_lifetime")
    image_digest = doc["image_digest"]
    if module_id in IMAGES:
        _match(SHA256, image_digest, "invalid_image_digest")
    elif image_digest is not None:
        reject("unsupported_image")
    allowed = {"notes": ("payload/notes.txt", MAX_NOTES)}
    if module_id in IMAGES:
        allowed["image"] = ("payload/image.tar", MAX_IMAGE)
    resources = doc["resources"]
    if not isinstance(resources, list) or len(resources) > len(allowed):
        reject("resource_limit")
    result = []
    seen = set()
    for item in resources:
        item = _keys(item, {"kind", "path", "size", "sha256"})
        kind = item["kind"]
        if not isinstance(kind, str) or kind not in allowed or kind in seen:
            reject("unsupported_resource")
        path, limit = allowed[kind]
        if item["path"] != path:
            reject("unsupported_resource_path")
        if type(item["size"]) is not int or not 0 < item["size"] <= limit:
            reject("resource_size")
        sha = _match(SHA256, item["sha256"], "invalid_resource_digest")
        seen.add(kind)
        result.append(Resource(kind, path, item["size"], sha))
    try:
        if raw != canonical_json(doc):
            reject("noncanonical_manifest")
    except RecursionError:
        reject("invalid_json")
    manifest = Manifest(module_id, doc["version"], issued, expires, image_digest, tuple(result))
    if not installed:
        manifest.check_fresh(now or datetime.now(timezone.utc))
    return manifest
