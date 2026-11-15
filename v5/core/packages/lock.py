"""Общая блокировка runtime, доступная без открытия реестра пакетов."""

from contextlib import contextmanager
import fcntl
import os
import stat

from v5.core.private_files import private_directory

from .manifest import reject


@contextmanager
def runtime_lock(root):
    try:
        private_directory(root)
        fd = os.open(root / "runtime.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except (OSError, ValueError):
        reject("insecure_package_store")
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            reject("insecure_package_store")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            reject("module_operation_busy")
        yield
