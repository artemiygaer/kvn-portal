"""Приватные копии и аварийный доступ KVN v5 (только root через SSH)."""

import argparse
from contextlib import contextmanager
import fcntl
import getpass
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tarfile
import warnings

from v5.core import audit
from v5.core.packages.lock import runtime_lock
from v5.core.packages.manifest import PackageError
from v5.core.packages.signature import load_publisher
from v5.core.private_files import private_directory, read_private
from v5.core.release import CORE_PIN

from . import access, backup
from .core_update import CoreUpdate, UpdateError

CONFIG = Path("/etc/kvn-v5")
STATE = Path("/var/lib/kvn-v5")
DEFAULT_INSTALL = "/root/portal"


@contextmanager
def locked(directory):
    private_directory(directory)
    if directory.resolve(strict=True) != directory:
        raise ValueError("Каталог установки не должен быть ссылкой")
    fd = os.open(directory / ".maintenance.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("Недопустимый файл блокировки")
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if json.loads(read_private(directory / "install.json", 4096)) != {"format": 1, "status": "complete"}:
            raise ValueError("Нужна завершённая установка v5")
        yield


def _password():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Пароль задаётся только в интерактивном терминале")
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass("Новый пароль администратора: ")
        if password != getpass.getpass("Повторите пароль: "):
            raise ValueError("Пароли не совпали")
    return password


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-dir", default=DEFAULT_INSTALL, help="Каталог, выбранный при установке")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("backup", help="Создать root-only копию конфигурации ядра")
    check = sub.add_parser("verify", help="Проверить состав и контрольные суммы копии")
    check.add_argument("archive")
    check.add_argument("sha256")
    reset = sub.add_parser("reset-admin", help="Сменить пароль администратора и отозвать прежние сессии")
    identity = reset.add_mutually_exclusive_group()
    identity.add_argument("--login", help="Логин (по умолчанию admin)")
    identity.add_argument("--from-backup", nargs=2, metavar=("ИМЯ", "SHA256"),
                          help="Взять прежний логин из проверенной копии")
    update = sub.add_parser("core-update", help="Применить отдельно подписанный выпуск ядра")
    update.add_argument("directory", type=Path, help="Абсолютный каталог трёх файлов выпуска")
    recover = sub.add_parser("core-recover", help="Откатить прерванное обновление ядра")
    recover.add_argument("--previous", action="store_true", help="Вручную вернуть предыдущий успешный выпуск")
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("Команду нужно запустить от root")
    if not re.fullmatch(r"/root/[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", args.install_dir):
        parser.error("Требуется каталог установки первого уровня внутри /root")
    install = Path(args.install_dir)
    copies = install / "backups"
    method = {"backup": "maintenance.backup", "reset-admin": "maintenance.reset_admin",
              "core-update": "maintenance.core_update", "core-recover": "maintenance.core_recover"}.get(args.action)
    ok = False
    try:
        with locked(install):
            if args.action == "verify":
                entries = backup.load(copies, args.archive, args.sha256)
                print(f"Копия проверена. Файлов: {len(entries)}. Сервер не изменён.")
            elif args.action == "backup":
                gid = grp.getgrnam("kvn-v5-web").gr_gid
                name, digest = backup.save(copies, backup.collect(install, CONFIG, STATE, gid))
                print(f"Приватная копия: {copies / name}\nSHA-256: {digest}")
            elif args.action == "reset-admin":
                login = args.login or "admin"
                if args.from_backup:
                    entries = backup.load(copies, *args.from_backup)
                    saved = json.loads(entries["web/config.json"])
                    login = saved.get("login") if isinstance(saved, dict) else None
                if not isinstance(login, str) or access.LOGIN.fullmatch(login) is None:
                    raise ValueError("Некорректный логин")
                gid = grp.getgrnam("kvn-v5-web").gr_gid
                access.change(CONFIG, gid, login, _password(), activate=lambda: access.restart_and_check(CONFIG))
                print("Доступ восстановлен. Прежние сеансы недействительны.")
            else:
                with runtime_lock(STATE / "packages"):
                    updater = CoreUpdate()
                    if args.action == "core-update":
                        private_directory(CORE_PIN.parent)
                        version = updater.apply(args.directory, load_publisher(CORE_PIN), pwd.getpwnam("kvn-v5-web").pw_uid)
                        print(f"Ядро v{version} применено; HTTPS и RPC проверены. Конфигурация не переписана.")
                    else:
                        updater.recover(previous=args.previous)
                        print("Прежнее ядро восстановлено; HTTPS и RPC проверены.")
        ok = True
        return 0
    except (OSError, ValueError, RuntimeError, LookupError, tarfile.TarError, subprocess.SubprocessError,
            RecursionError, EOFError, SyntaxError, KeyboardInterrupt, getpass.GetPassWarning) as exc:
        reason = str(exc) if isinstance(exc, UpdateError) else {
            "invalid_package_signature": "Подпись выпуска не совпадает с закреплённым ключом.",
            "publisher_not_configured": "Ключ обновления ядра ещё не закреплён.",
            "module_operation_busy": "Операция с модулями уже выполняется. Повторите позже.",
        }.get(str(exc)) if isinstance(exc, PackageError) else None
        print(reason or f"Операция не завершена ({type(exc).__name__}). Проверьте права, SHA-256 и журнал.",
              file=sys.stderr)
        return 1
    finally:
        if method is not None:
            audit.record(method, ok)


if __name__ == "__main__":
    raise SystemExit(main())
