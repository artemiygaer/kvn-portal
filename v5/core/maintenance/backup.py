"""Приватный снимок конфигурации ядра, без runtime и пакетов."""

from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

from v5.core.private_files import private_directory, read_private, write_private
from v5.core.tls.controller import GatewayController
from v5.core.tls.access import load_access
from v5.core.tls import imported
from v5.core.tls.queue import registry
from v5.core.tls.transaction import CertificateStore, read_gateway_config

MAX_FILE = 256 * 1024
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_ENTRIES = 48
NAME = re.compile(r"core-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{12}\.tar\.gz\Z", re.ASCII)
CERT = re.compile(r"gateway/certs/(?:dns|ip)-[a-z0-9_.-]{1,220}/[0-9a-f]{64}/(?:fullchain|privkey)\.pem\Z", re.ASCII)
REQUIRED = frozenset({
    "install/install.json", "install/identity.json", "web/config.json",
    "gateway/identities.json", "gateway/nginx.conf", "gateway/bootstrap.crt",
    "gateway/bootstrap.key", "site/index.html",
})
OPTIONAL = ("packages/publisher.json", "core/publisher.json", "core/install-location.json")
OPTIONAL_PUBLIC = ("access.json",)
OPTIONAL_STATE = ("tls/imported.json",)


def read_owned(path: Path, mode: int | tuple[int, ...], *, gid=None, maximum=MAX_FILE) -> bytes:
    if path.resolve(strict=True) != path:
        raise ValueError("Символьная ссылка в конфигурации не поддерживается")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        modes = (mode,) if isinstance(mode, int) else mode
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in modes
                or info.st_nlink != 1 or (gid is not None and info.st_gid != gid)):
            raise ValueError("Небезопасный файл конфигурации")
        raw = handle.read(maximum + 1)
    if not 0 < len(raw) <= maximum:
        raise ValueError("Недопустимый размер файла конфигурации")
    return raw


def _manifest(files):
    return {"format": 1, "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}


def collect(install: Path, config: Path, state: Path, web_gid: int) -> dict[str, bytes]:
    private_directory(install)
    gateway = config / "gateway"
    installed = read_owned(install / "install.json", 0o600)
    if json.loads(installed) != {"format": 1, "status": "complete"}:
        raise ValueError("Нужна завершённая установка v5")
    identities = read_owned(gateway / "identities.json", 0o600)
    nginx = read_gateway_config(gateway / "nginx.conf")
    names, ipv6 = registry(gateway / "identities.json")
    controller = GatewayController(gateway / "nginx.conf", CertificateStore(gateway / "certs"), names, ipv6=ipv6)
    files = {
        "install/install.json": installed,
        "install/identity.json": read_owned(install / "identity.json", 0o600),
        "web/config.json": read_owned(config / "web/config.json", 0o640, gid=web_gid),
        "gateway/identities.json": identities,
        "gateway/nginx.conf": nginx,
        "gateway/bootstrap.crt": read_owned(gateway / "bootstrap.crt", (0o600, 0o644)),
        "gateway/bootstrap.key": read_owned(gateway / "bootstrap.key", 0o600),
        "site/index.html": read_owned(state / "site/index.html", 0o644),
    }
    for pair in controller.active():
        for path in (pair.chain, pair.key):
            files["gateway/" + path.relative_to(gateway).as_posix()] = read_owned(path, 0o600)
    for name in OPTIONAL:
        pin = config / name
        if pin.exists() or pin.is_symlink():
            files[name] = read_owned(pin, 0o600)
    for name in OPTIONAL_PUBLIC:
        path = config / name
        if path.exists() or path.is_symlink():
            load_access(path)
            files[name] = read_owned(path, 0o644)
    for name in OPTIONAL_STATE:
        marker = state / name
        if marker.exists() or marker.is_symlink():
            imported.load(marker)
            files[name] = read_owned(marker, 0o600)
    if nginx != read_gateway_config(gateway / "nginx.conf") or identities != read_owned(gateway / "identities.json", 0o600):
        raise ValueError("Конфигурация TLS менялась во время снимка. Повторите команду.")
    for name in OPTIONAL_STATE:
        marker = state / name
        current = read_owned(marker, 0o600) if marker.exists() or marker.is_symlink() else None
        if current != files.get(name):
            raise ValueError("Источник сертификата менялся во время снимка. Повторите команду.")
    return files


def _allowed(name: str) -> bool:
    return name in REQUIRED or name in OPTIONAL or name in OPTIONAL_PUBLIC or name in OPTIONAL_STATE or CERT.fullmatch(name) is not None


def encode(files: dict[str, bytes]) -> bytes:
    if (not REQUIRED <= files.keys() or len(files) >= MAX_ENTRIES
            or any(not _allowed(name) or not 0 < len(data) <= MAX_FILE for name, data in files.items())
            or sum(map(len, files.values())) > MAX_ARCHIVE):
        raise ValueError("Недопустимый состав бэкапа")
    output = io.BytesIO()
    entries = {**files, "manifest.json": json.dumps(_manifest(files), sort_keys=True).encode("ascii")}
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for name, data in sorted(entries.items()):
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o600, len(data)
                archive.addfile(info, io.BytesIO(data))
    raw = output.getvalue()
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("Архив слишком большой")
    return raw


def decode(raw: bytes) -> dict[str, bytes]:
    if not 0 < len(raw) <= MAX_ARCHIVE:
        raise ValueError("Недопустимый размер архива")
    # Явный лимит применяется до tarfile, в том числе к служебным заголовкам.
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        payload = compressed.read(MAX_ARCHIVE + 64 * 1024 + 1)
    if len(payload) > MAX_ARCHIVE + 64 * 1024:
        raise ValueError("Архив превышает лимит распаковки")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive:
            name = member.name
            if (name in files or len(files) >= MAX_ENTRIES or member.type != tarfile.REGTYPE
                    or set(member.pax_headers) - {"path"}
                    or not 0 < member.size <= MAX_FILE or (name != "manifest.json" and not _allowed(name))):
                raise ValueError("Недопустимая запись в бэкапе")
            with archive.extractfile(member) as handle:
                files[name] = handle.read()
    if "manifest.json" not in files or not REQUIRED <= files.keys():
        raise ValueError("Бэкап не содержит обязательные файлы")
    if json.loads(files.pop("manifest.json")) != _manifest(files):
        raise ValueError("Контрольные суммы бэкапа не совпадают")
    return files


def save(directory: Path, files: dict[str, bytes]) -> tuple[str, str]:
    directory.mkdir(mode=0o700, exist_ok=True)
    raw = encode(files)
    digest = hashlib.sha256(raw).hexdigest()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"core-{stamp}-{digest[:12]}.tar.gz"
    write_private(directory / name, raw, replace=False)
    return name, digest


def load(directory: Path, name: str, digest: str) -> dict[str, bytes]:
    if not NAME.fullmatch(name) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
        raise ValueError("Укажите штатное имя архива и полный SHA-256")
    raw = read_private(directory / name, MAX_ARCHIVE)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("SHA-256 архива не совпадает")
    return decode(raw)
