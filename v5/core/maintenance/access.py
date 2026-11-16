"""Сброс администратора с отзывом сессий и откатом при сбое web."""

import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import subprocess
from tempfile import NamedTemporaryFile
import time

from v5.core.console import AGENT_UNIT, WEB_SOCKET, WEB_UNIT
from v5.core.credentials import LOGIN, hash_admin_password
from v5.core.tls.gateway import admin_hosts
from v5.core.tls.queue import registry

from .backup import read_owned

AGENT_SOCKET = "/run/kvn-v5-agent/control.sock"
SYSTEMCTL = "/usr/bin/systemctl"


def _sync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace(path: Path, body: bytes, gid: int) -> None:
    temporary = None
    try:
        with NamedTemporaryFile(dir=path.parent, prefix=".recovery-", delete=False) as handle:
            temporary = Path(handle.name)
            os.fchown(handle.fileno(), os.geteuid(), gid)
            os.fchmod(handle.fileno(), 0o640)
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def change(config: Path, gid: int, login: str, password: str, *, activate) -> None:
    if LOGIN.fullmatch(login) is None:
        raise ValueError("Некорректный логин")
    path = config / "web/config.json"
    parent = path.parent.lstat()
    if (path.parent.resolve(strict=True) != path.parent or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid() or parent.st_gid != gid or stat.S_IMODE(parent.st_mode) != 0o750):
        raise ValueError("Недопустимые права каталога настроек панели")
    identities, _ = registry(config / "gateway/identities.json")
    try:
        previous = read_owned(path, 0o640, gid=gid, maximum=16 * 1024)
    except FileNotFoundError:
        previous = None
    body = json.dumps({"login": login, "password_hash": hash_admin_password(password),
                       "session_key": secrets.token_hex(32), "allowed_hosts": admin_hosts(identities),
                       "agent_socket": AGENT_SOCKET}).encode("ascii")
    _replace(path, body, gid)
    try:
        _sync_dir(path.parent)
        activate()
    except BaseException:
        try:
            if previous is None:
                path.unlink()
            else:
                _replace(path, previous, gid)
            _sync_dir(path.parent)
            activate()
        except Exception as failure:
            raise RuntimeError("Прежний файл восстановлен не полностью или web не ответил. Проверьте службу по SSH.") from failure
        raise


def wait_login(config: Path, *, timeout=90) -> None:
    context = ssl.create_default_context(cadata=read_owned(
        config / "gateway/bootstrap.crt", (0o600, 0o644)).decode("ascii"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        connection = http.client.HTTPSConnection("127.0.0.1", 8443, timeout=2, context=context)
        try:
            connection.request("GET", "/login")
            if connection.getresponse().status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(.25)
    raise RuntimeError("Web не ответил через доверенный аварийный HTTPS-вход")


def restart_and_check(config: Path) -> None:
    if WEB_SOCKET.is_socket():
        subprocess.run([SYSTEMCTL, "stop", WEB_UNIT, AGENT_UNIT], check=True, timeout=15,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run([SYSTEMCTL, "restart", "kvn-v5-web.service"], check=True, timeout=45,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_login(config)
