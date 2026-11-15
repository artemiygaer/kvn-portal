"""Контракт подписанного выпуска ядра, отдельно от пакетов модулей."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat

from .console import AGENT_UNIT, SOCKET_UNIT, WEB_SOCKET_UNIT, WEB_UNIT
from .contracts import CORE_API_VERSION
from .packages.manifest import SHA256, json_object, version_key

ARCHIVE = "kvn-portal-v5-installer.tar.gz"
MANIFEST = "kvn-portal-v5-core.json"
SIGNATURE = "kvn-portal-v5-core.sig"
MAX_ARCHIVE = 12 * 1024 * 1024
MAX_UNPACKED = 32 * 1024 * 1024
VERSION_MEMBER = "v5/install/core-version"
VENDOR_METADATA = frozenset(f"v5/portal/static/vendor/xterm/{name}" for name in
                            ("LICENSE.xterm", "LICENSE.addon-fit", "SHA256SUMS"))
SERVICES = ("kvn-v5-agent.service", "kvn-v5-web.service", "kvn-v5-gateway.service")
TRIGGERS = ("kvn-v5-tls.path", "kvn-v5-tls-renew.timer", "kvn-v5-package.socket", "kvn-v5-reconcile.service",
            "kvn-v5-lifecycle.socket", "kvn-v5-migration.socket", "kvn-v5-socket-observer.socket",
            "kvn-v5-core-update.socket")
UNIT_FILES = (*SERVICES, *TRIGGERS, "kvn-v5-tls.service", "kvn-v5-tls-renew.service", "kvn-v5-package@.service",
              "kvn-v5-lifecycle@.service", "kvn-v5-module-xray.service", "kvn-v5-module-wireguard.service",
              "kvn-v5-module-amneziawg.service", "kvn-v5-module-hysteria.service", "kvn-v5-module-tls-sync.service",
              "kvn-v5-module-telemt.service", "kvn-v5-module-mtg.service", "kvn-v5-migration@.service",
              AGENT_UNIT, SOCKET_UNIT, WEB_UNIT, WEB_SOCKET_UNIT, "kvn-v5-observer.service",
              "kvn-v5-socket-observer@.service", "kvn-v5-core-update@.service", "kvn-v5-core-apply@.service",
              "kvn-v5-provision@.service", "kvn-v5-forwarding.service")
LIVE = Path("/usr/local/lib/kvn-v5")
CORE_PIN = Path("/etc/kvn-v5/core/publisher.json")
_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z", re.ASCII)


def stable_version(value: str) -> tuple[int, int, int]:
    version = version_key(value)
    if version[0] != 5:
        raise ValueError("Требуется стабильная версия линейки v5")
    return version


def read_asset(path: Path, maximum: int) -> bytes:
    if not path.is_absolute() or not _ASSET.fullmatch(path.name):
        raise ValueError("Некорректный путь артефакта")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError("Некорректный файл артефакта")
        raw = stream.read(maximum + 1)
    if len(raw) != info.st_size:
        raise ValueError("Файл изменился при чтении")
    return raw


def installed_version(root=LIVE) -> str | None:
    path = root / "core-version"
    try:
        raw = read_asset(path, 48)
    except FileNotFoundError:
        return None
    value = raw.decode("ascii").removesuffix("\n")
    stable_version(value)
    return value


@dataclass(frozen=True)
class Release:
    version: str
    sha256: str
    size: int

    @classmethod
    def parse(cls, raw: bytes):
        doc = json_object(raw)
        if (doc.keys() != {"kind", "format", "core_api", "version", "sha256", "size"}
                or doc["kind"] != "kvn-v5-core" or type(doc["format"]) is not int or doc["format"] != 1
                or type(doc["core_api"]) is not int or doc["core_api"] != CORE_API_VERSION
                or type(doc["size"]) is not int or not 0 < doc["size"] <= MAX_ARCHIVE
                or not isinstance(doc["sha256"], str) or SHA256.fullmatch(doc["sha256"]) is None):
            raise ValueError("Несовместимый манифест выпуска ядра")
        stable_version(doc["version"])
        return cls(doc["version"], doc["sha256"], doc["size"])


def verified_release(directory: Path, publisher, work: Path) -> tuple[Release, bytes]:
    manifest = read_asset(directory / MANIFEST, 4096)
    publisher.verify(manifest, read_asset(directory / SIGNATURE, 64), work)
    release = Release.parse(manifest)
    raw = read_asset(directory / ARCHIVE, release.size)
    if len(raw) != release.size or hashlib.sha256(raw).hexdigest() != release.sha256:
        raise ValueError("Архив не совпадает с подписанным SHA-256")
    return release, raw
