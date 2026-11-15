"""Разрешить только включение и отключение собственного сборщика истории."""

import os
from pathlib import Path
import stat
import subprocess

from v5.core.private_files import private_directory
from v5.core.lifecycle.controller import LifecycleError
from .collector import DIRECTORY

UNIT = "kvn-v5-observer.service"
SYSTEMCTL = "/usr/bin/systemctl"


def _run(*arguments):
    try:
        return subprocess.run([SYSTEMCTL, *arguments, UNIT], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=30, check=False,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.SubprocessError) as exc:
        raise LifecycleError("observer_control_unavailable") from exc


def status():
    result = _run("show", "--property=ActiveState", "--property=UnitFileState", "--value")
    if result.returncode != 0:
        raise LifecycleError("observer_control_unavailable")
    fields = result.stdout.decode("ascii", "strict").splitlines()
    # Порядок свойств systemd не гарантирован: допустимы только известные состояния.
    active = {"active", "inactive", "failed", "activating", "deactivating"}
    configured = {"enabled", "disabled", "static", "masked", "indirect", "generated", "transient"}
    if len(fields) != 2 or len(set(fields) & active) != 1 or len(set(fields) & configured) != 1:
        raise LifecycleError("observer_control_unavailable")
    return {"enabled": "enabled" in fields, "active": "active" in fields}


def _erase(directory: Path):
    try:
        private_directory(directory)
    except FileNotFoundError:
        return
    for name in ("history.sqlite3", "history.sqlite3-journal", "history.sqlite3-wal", "history.sqlite3-shm"):
        path = directory / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LifecycleError("observer_storage_invalid")
        path.unlink()


def configure(enabled: bool, *, directory=DIRECTORY):
    if type(enabled) is not bool:
        raise LifecycleError("invalid_request")
    result = _run("enable" if enabled else "disable", "--now")
    if result.returncode:
        raise LifecycleError("observer_control_unavailable")
    current = status()
    if current["enabled"] != enabled or current["active"] != enabled:
        raise LifecycleError("observer_control_unavailable")
    if not enabled:
        _erase(Path(directory))
    return current
