"""Терминальный установщик чистого ядра для Debian 12/13."""

import argparse
import fcntl
import getpass
import grp
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import time

from .preflight import DEFAULT_INSTALL_DIR, InstallIdentity, InstallPreflightError, check_ports, ipv6_available, reject_legacy
from v5.core.credentials import LOGIN, MAX_PASSWORD, MIN_PASSWORD, hash_admin_password
from v5.core.release import LIVE as LIB, SERVICES, TRIGGERS, UNIT_FILES, stable_version
from v5.core.site.document import SiteStore
from v5.core.tls.acme import ACME_ROOT, AcmeMode
from v5.core.tls.access import PortalAccess
from v5.core.packages.signature import parse_publisher
from v5.core.tls.gateway import admin_hosts, render_gateway
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.provision import ProvisionError, install_runtime
from v5.core.tls.queue import TLS_QUEUE, QueueBusy, TLSJob, TLSQueue

SOURCE = Path(__file__).resolve().parents[1]
CONFIG = Path("/etc/kvn-v5")
STATE_DIR = ACME_ROOT.parent
SYSTEMD = Path("/etc/systemd/system")
ACCOUNTS = ("kvn-v5-web", "kvn-v5-gateway")


def safe_target(value: str) -> Path:
    if not re.fullmatch(r"/root/[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", value):
        raise InstallPreflightError("Укажите абсолютный каталог первого уровня внутри /root")
    return Path(value)


def run(*args):
    subprocess.run(args, check=True)


def write_new(path: Path, data: str, mode: int, *, gid: int = 0) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, mode), "w", encoding="utf-8") as stream:
        os.fchown(stream.fileno(), 0, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(data)


def mkdir_mode(path: Path, mode: int) -> None:
    path.mkdir(mode=mode)
    path.chmod(mode)


def copy_runtime_code(source: Path, target: Path) -> None:
    # Архив из README распаковывается с umask 077; web должен читать только этот код.
    shutil.copytree(source, target, symlinks=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for path in target.rglob("*"):
        if path.is_symlink():
            raise InstallPreflightError("Симлинки в коде служб не поддерживаются")
        path.chmod(0o755 if path.is_dir() else 0o644)
    target.chmod(0o755)


def detect_public_ipv4():
    """Предложить адрес, не считая ответ внешнего сервиса гарантией настройки DNS."""
    connection = None
    try:
        connection = http.client.HTTPSConnection('api.ipify.org', timeout=3)
        connection.request('GET', '/', headers={'Accept': 'text/plain'})
        response = connection.getresponse()
        if response.status != 200:
            return None
        raw = response.read(65)
        if not raw or len(raw) > 64:
            return None
        address = ipaddress.ip_address(raw.decode('ascii').strip())
        return str(address) if address.version == 4 and address.is_global else None
    except (OSError, ValueError, UnicodeError, http.client.HTTPException):
        return None
    finally:
        if connection is not None:
            connection.close()


def identity_prompt(ask=input, password_prompt=getpass.getpass, *, suggested_ip=None):
    if suggested_ip is None and ask is input:
        suggested_ip = detect_public_ipv4()
    prompt = f"IP сервера [{suggested_ip}]: " if suggested_ip else "IP сервера: "
    selected_ip = ask(prompt).strip() or suggested_ip or ""
    identity = InstallIdentity.parse(selected_ip, ask("Имена DNS через пробел (необязательно): "))
    login = ask("Логин администратора [admin]: ").strip() or "admin"
    if LOGIN.fullmatch(login) is None:
        raise InstallPreflightError("Некорректный логин")
    password = password_prompt("Пароль администратора: ")
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD or password != password_prompt("Повторите пароль: "):
        raise InstallPreflightError("Пароли не совпали или длина вне диапазона 12–256")
    return identity, login, password


def read_existing(target):
    if not target.exists() and not target.is_symlink():
        return None
    if target.is_symlink() or not target.is_dir() or target.stat().st_uid != 0 or target.stat().st_mode & 0o077:
        raise InstallPreflightError("Каталог установки уже существует и не защищён как каталог v5")
    marker = target / "install.json"
    if marker.is_symlink() or not marker.is_file():
        raise InstallPreflightError("Каталог уже существует; установщик не перезаписывает его")
    state = json.loads(marker.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or state.get("format") != 1 or state.get("status") != "complete":
        raise InstallPreflightError("Обнаружена незавершённая или неизвестная установка; данные сохранены")
    return state


def check_platform():
    if os.geteuid() != 0:
        raise InstallPreflightError("Установщик нужно запустить от root")
    os_info = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        name, equal, value = line.partition("=")
        if equal:
            os_info[name] = value.strip('"')
    if os_info.get("ID") != "debian" or os_info.get("VERSION_ID") not in {"12", "13"}:
        raise InstallPreflightError("Установщик поддерживает только Debian 12/13")
    if not Path("/run/systemd/system").is_dir():
        raise InstallPreflightError("Требуется запущенный systemd")


def preflight_new(access=PortalAccess()):
    for path in (LIB, CONFIG, STATE_DIR, *(SYSTEMD / name for name in UNIT_FILES)):
        if path.exists() or path.is_symlink():
            raise InstallPreflightError(f"Системный путь уже занят: {path}")
    for account in ACCOUNTS:
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(account)
            except KeyError:
                continue
            raise InstallPreflightError("Имя системной учётной записи v5 уже занято")
    check_ports(tuple(dict.fromkeys((80, 443, 8443, access.port))))


def install_dependencies(*, with_acme=False):
    # Не даём Debian-пакету впервые запустить отдельный стандартный nginx.
    packages = []
    required = ("nginx", "gunicorn", "python3-flask", "openssl", "ca-certificates", "qrencode",
                "gpg", "gpg-agent") + (
        ("python3-venv",) if with_acme else ())
    for package in required:
        result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package],
                                capture_output=True, text=True, check=False)
        if result.returncode or result.stdout.strip() != "installed":
            packages.append(package)
    if not packages:
        return
    new_nginx = "nginx" in packages and not Path("/usr/sbin/nginx").is_file()
    if new_nginx:
        for unit in ("/run/systemd/system/nginx.service", "/etc/systemd/system/nginx.service"):
            if Path(unit).exists() or Path(unit).is_symlink():
                raise InstallPreflightError("Имеется собственный unit nginx; установка не меняет его")
        run("systemctl", "mask", "--runtime", "nginx.service")
    try:
        run("apt-get", "update")
        run("apt-get", "install", "-y", "--no-install-recommends", *packages)
        if new_nginx:
            run("systemctl", "disable", "nginx.service")
    finally:
        if new_nginx:
            run("systemctl", "unmask", "--runtime", "nginx.service")


def bootstrap_config(identity: InstallIdentity, *, ipv6: bool) -> str:
    names = (TLSIdentity(identity.ip, True), *(TLSIdentity(name, False) for name in identity.names))
    try:
        return render_gateway(names, ipv6=ipv6)
    except ValueError as exc:
        raise InstallPreflightError(str(exc)) from exc


def provision(target, identity, login, password_digest, *, with_acme=False, access=PortalAccess()):
    ipv6 = ipv6_available()
    bootstrap = bootstrap_config(identity, ipv6=ipv6)
    version_file = SOURCE / "install/core-version"
    version = None
    if version_file.exists() or version_file.is_symlink():
        if version_file.is_symlink() or not version_file.is_file() or version_file.stat().st_size > 48:
            raise InstallPreflightError("Некорректный файл версии")
        version = version_file.read_text(encoding="ascii").removesuffix("\n")
        stable_version(version)
    pin_path = SOURCE / "install/publisher.json"
    publisher = None
    if pin_path.exists() or pin_path.is_symlink():
        if pin_path.is_symlink() or not pin_path.is_file():
            raise InstallPreflightError("Некорректный файл ключа издателя")
        with pin_path.open("rb") as handle:
            publisher = handle.read(4097)
        parse_publisher(publisher)
    install_dependencies(with_acme=with_acme)
    if with_acme:
        install_runtime()
    for account in ACCOUNTS:
        run("useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", account)
    web = pwd.getpwnam("kvn-v5-web")
    target.mkdir(mode=0o700)
    write_new(target / "install.json", json.dumps({"format": 1, "status": "preparing"}), 0o600)
    mkdir_mode(LIB, 0o755)
    mkdir_mode(LIB / "v5", 0o755)
    if version is not None:
        write_new(LIB / "core-version", version + "\n", 0o644)
    for component in ("core", "portal", "modules"):
        copy_runtime_code(SOURCE / component, LIB / "v5" / component)
    mkdir_mode(CONFIG, 0o755)
    write_new(CONFIG / "access.json", json.dumps({"port": access.port, "prefix": access.prefix}), 0o644)
    mkdir_mode(CONFIG / "packages", 0o700)
    mkdir_mode(CONFIG / "core", 0o700)
    write_new(CONFIG / "core/install-location.json", json.dumps({"format": 1, "path": str(target)}), 0o600)
    if publisher is not None:
        write_new(CONFIG / "packages/publisher.json", publisher.decode("utf-8"), 0o600)
        write_new(CONFIG / "core/publisher.json", publisher.decode("utf-8"), 0o600)
    web_dir, gateway_dir = CONFIG / "web", CONFIG / "gateway"
    mkdir_mode(web_dir, 0o750)
    os.chown(web_dir, 0, web.pw_gid)
    gateway_dir.mkdir(mode=0o700)
    (gateway_dir / "certs").mkdir(mode=0o700)
    names = (TLSIdentity(identity.ip, True), *(TLSIdentity(name, False) for name in identity.names))
    write_new(gateway_dir / "identities.json", json.dumps({"ip": identity.ip, "names": identity.names, "ipv6": ipv6}), 0o600)
    config = {"login": login, "password_hash": password_digest, "session_key": secrets.token_hex(32),
              "allowed_hosts": admin_hosts(names, access), "agent_socket": "/run/kvn-v5-agent/control.sock"}
    write_new(web_dir / "config.json", json.dumps(config), 0o640, gid=web.pw_gid)
    write_new(target / "identity.json", json.dumps({"ip": identity.ip, "names": identity.names}), 0o600)
    write_new(target / "modules.json", '{"schema":1,"installed":[]}', 0o600)
    for public in (STATE_DIR, ACME_ROOT, ACME_ROOT / "webroot", ACME_ROOT / "webroot/.well-known",
                   ACME_ROOT / "webroot/.well-known/acme-challenge", STATE_DIR / "site"):
        mkdir_mode(public, 0o755)
    TLS_QUEUE.mkdir(mode=0o700)
    mkdir_mode(STATE_DIR / "packages", 0o700)
    mkdir_mode(STATE_DIR / "modules", 0o700)
    mkdir_mode(STATE_DIR / "users", 0o700)
    SiteStore(STATE_DIR / "site").reset()
    write_new(gateway_dir / "nginx.conf", bootstrap, 0o600)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "365",
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
                    "-keyout", str(gateway_dir / "bootstrap.key"), "-out", str(gateway_dir / "bootstrap.crt")],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (gateway_dir / "bootstrap.key").chmod(0o600)
    for service in UNIT_FILES:
        unit = (SOURCE / "install/systemd" / service).read_text(encoding="utf-8")
        write_new(SYSTEMD / service, unit.replace("@WEB_UID@", str(web.pw_uid)), 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", *SERVICES, *TRIGGERS)
    wait_ready(TLSIdentity(identity.ip, True).authority)
    write_new(target / ".install-complete", json.dumps({"format": 1, "status": "complete"}), 0o600)
    (target / ".install-complete").replace(target / "install.json")


def wait_ready(authority: str, timeout=180):
    context = ssl.create_default_context(cafile=str(CONFIG / "gateway/bootstrap.crt"))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        connection = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=3)
        try:
            connection.request("GET", "/login")
            if connection.getresponse().status == 200 and Path("/run/kvn-v5-agent/control.sock").is_socket():
                with_http = http.client.HTTPConnection("127.0.0.1", 80, timeout=3)
                try:
                    with_http.request("GET", "/", headers={"Host": authority})
                    response = with_http.getresponse()
                    if response.status == 308 and response.getheader("Location") == f"https://{authority}/":
                        return
                finally:
                    with_http.close()
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(1)
    raise InstallPreflightError("HTTP/HTTPS-шлюз или сокет агента не готовы; проверьте журнал служб kvn-v5")


def describe_access():
    print("Первый вход: https://127.0.0.1:8443; публичный TCP/80 служит для HTTP-01.")
    print("Подключитесь SSH-туннелем: ssh -L 8443:127.0.0.1:8443 USER@SERVER")
    print("Для доверия в туннеле отдельно проверьте сертификат /etc/kvn-v5/gateway/bootstrap.crt.")


def issue_initial_certificates(identity: InstallIdentity, *, runtime_ready=False):
    """Попробовать публичный выпуск, сохранив рабочий аварийный вход при ошибке."""
    names = [TLSIdentity(name, False) for name in identity.names]
    if ipaddress.ip_address(identity.ip).is_global:
        names.append(TLSIdentity(identity.ip, True))
    if not names:
        print("[ПРЕДУПРЕЖДЕНИЕ] Нет публичного IP или DNS-имени для Let's Encrypt.")
        return ()
    try:
        if not runtime_ready:
            install_dependencies(with_acme=True)
            install_runtime()
    except (OSError, ValueError, ProvisionError, subprocess.SubprocessError):
        print("[ПРЕДУПРЕЖДЕНИЕ] Certbot недоступен. Панель доступна через SSH-туннель; сертификат можно выпустить позже в панели.")
        return ()
    queue = TLSQueue()
    ready = []
    for item in names:
        try:
            queue.submit(TLSJob(item, AcmeMode.PUBLIC, ""))
            run("systemctl", "start", "kvn-v5-tls.service")
            status = queue.snapshot().get("results", {}).get(item.slot, {}).get("public", {}).get("status")
            if status in ("active", "unchanged"):
                print(f"[OK] Сертификат Let's Encrypt: {item.authority}")
                ready.append(item.authority)
            else:
                print(f"[ПРЕДУПРЕЖДЕНИЕ] Сертификат {item.authority} не получен; проверьте DNS и TCP/80 в панели.")
        except (QueueBusy, OSError, ValueError, subprocess.SubprocessError):
            print(f"[ПРЕДУПРЕЖДЕНИЕ] Не удалось выпустить сертификат {item.authority}; повторите в панели.")
    return tuple(ready)


def main(argv=None, *, ask=input, password_prompt=getpass.getpass):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Защищённый каталог установки внутри /root")
    parser.add_argument("--with-acme", action="store_true", help="Также установить Certbot из закреплённых wheels")
    args = parser.parse_args(argv)
    try:
        check_platform()
        if ask is input and (not sys.stdin.isatty() or not sys.stderr.isatty()):
            raise InstallPreflightError("Первичная настройка требует интерактивного терминала")
        selected = args.target or ask(f"Каталог установки [{DEFAULT_INSTALL_DIR}]: ").strip() or str(DEFAULT_INSTALL_DIR)
        target = safe_target(selected)
        reject_legacy(install_dir=target)
        if read_existing(target):
            if args.with_acme:
                raise InstallPreflightError("Для добавления Certbot к установленной панели используйте отдельную команду из инструкции")
            run("systemctl", "start", *SERVICES, *TRIGGERS)
            print("Уже установлено. Администратор, ключи и конфигурация сохранены.")
            describe_access()
            return 0
        preflight_new()
        identity, login, password = identity_prompt(ask, password_prompt)
        access = PortalAccess.parse(ask("HTTPS-порт панели [8443]: ").strip() or "8443",
                                    ask("Путь панели [/]: ").strip() or "/")
        preflight_new(access)
        print("Будут установлены портал, агент и локальный HTTPS-шлюз; дополнительных модулей не будет.")
        print("После установки будет выполнена попытка выпуска Let's Encrypt без email; подтверждая установку, вы принимаете условия Let's Encrypt.")
        if args.with_acme:
            print("Certbot и его зависимости будут загружены из PyPI и проверены по SHA-256.")
        if ask("Начать установку? [да/нет]: ").strip().casefold() not in ("да", "yes", "y"):
            print("Отменено. Изменений нет.")
            return 1
        password_digest = hash_admin_password(password)
        del password
        fd = os.open("/run/lock/kvn-v5-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            reject_legacy(install_dir=target)
            if read_existing(target):
                raise InstallPreflightError("Пока мастер был открыт, установка уже выполнена")
            preflight_new(access)
            provision(target, identity, login, password_digest, with_acme=args.with_acme, access=access)
        ready = issue_initial_certificates(identity, runtime_ready=args.with_acme)
        for authority in ready:
            print(f"Портал: https://{authority}:{access.port}{access.prefix}/")
        describe_access()
        return 0
    except (InstallPreflightError, OSError, ValueError, subprocess.CalledProcessError, EOFError, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, (InstallPreflightError, ProvisionError)) else type(exc).__name__
        print(f"Установка остановлена: {reason}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
