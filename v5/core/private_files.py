"""Закрытые локальные файлы и атомарная запись без символьных ссылок."""

import os
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile


def private_directory(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Требуется закрытый каталог")


def read_private(path: Path, limit: int) -> bytes:
    private_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Недопустимые права закрытого файла")
        raw = handle.read(limit + 1)
    if not 1 <= len(raw) <= limit:
        raise ValueError("Недопустимый размер закрытого файла")
    return raw


def write_private(path: Path, raw: bytes, *, replace: bool = True) -> None:
    private_directory(path.parent)
    stage = None
    try:
        with NamedTemporaryFile(mode="wb", prefix=".kvn-", dir=path.parent, delete=False) as handle:
            stage = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(stage, path)
        else:
            os.link(stage, path)
        fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)
