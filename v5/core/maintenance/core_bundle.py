"""Ограниченный перенос трёх подписанных файлов выпуска ядра."""

import io
import os
from pathlib import Path
import stat
import tarfile

from v5.core.private_files import private_directory
from v5.core.release import ARCHIVE, MANIFEST, MAX_ARCHIVE, SIGNATURE, read_asset

NAME = "kvn-portal-v5-update.tar"
MAX_BUNDLE = MAX_ARCHIVE + 128 * 1024
LIMITS = {ARCHIVE: MAX_ARCHIVE, MANIFEST: 4096, SIGNATURE: 64}
ORDER = (MANIFEST, SIGNATURE, ARCHIVE)


def build(directory: Path, target: Path) -> None:
    """Создать воспроизводимый bundle из уже подготовленных файлов издателя."""
    values = {name: read_asset(directory / name, LIMITS[name]) for name in ORDER}
    if len(values[SIGNATURE]) != 64:
        raise ValueError("Некорректная подпись выпуска")
    with target.open("xb") as output:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in ORDER:
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime, info.uid, info.gid = len(values[name]), 0o600, 0, 0, 0
                archive.addfile(info, io.BytesIO(values[name]))
    if target.stat().st_size > MAX_BUNDLE:
        target.unlink()
        raise ValueError("Пакет ядра превышает допустимый размер")


def unpack(source: Path, destination: Path) -> None:
    """Не доверять имени, типу или размеру ни одного члена архива."""
    private_directory(destination)
    if not source.is_absolute():
        raise ValueError("Недопустимый пакет ядра")
    found = set()
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or not 0 < info.st_size <= MAX_BUNDLE):
            raise ValueError("Недопустимый размер или владелец пакета ядра")
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            _unpack(archive, destination, found)
    if found != set(ORDER):
        raise ValueError("Пакет ядра неполон")


def _unpack(archive, destination, found):
    for member in archive:
        if (member.name not in LIMITS or member.name in found or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                or member.pax_headers
                or not 0 < member.size <= LIMITS[member.name]
                or member.name == SIGNATURE and member.size != 64):
            raise ValueError("Недопустимый состав пакета ядра")
        found.add(member.name)
        body = archive.extractfile(member)
        if body is None:
            raise ValueError("Недоступное содержимое пакета")
        path = destination / member.name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            remaining = member.size
            while remaining:
                chunk = body.read(min(128 * 1024, remaining))
                if not chunk:
                    raise ValueError("Пакет ядра обрезан")
                output.write(chunk)
                remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
