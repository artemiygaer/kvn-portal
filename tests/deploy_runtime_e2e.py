#!/usr/bin/env python3
"""Полная проверка портала из чистого deploy-архива в Docker."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import base64
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "kvn-vpn-deploy.tar.gz"
WORK = ROOT / ".deploy-runtime-e2e"
PROJECT = WORK / "deploy"
PROJECT_NAME = "kvn-deploy-e2e"
AGENT_IMAGE = "kvn-deploy-agent:e2e"
QR_IMAGE = "kvn-qr-verifier:e2e"
AGENT_CONTAINER = "kvn-deploy-e2e-agent"
PORTAL_CONTAINER = "kvn-deploy-e2e-portal"
GATEWAY_CONTAINER = "kvn-deploy-e2e-gateway"
SOCKET_VOLUME = "kvn-deploy-e2e-socket"
DATA_VOLUME = "kvn-deploy-e2e-data"
METRICS_VOLUME = "kvn-deploy-e2e-metrics"
NETWORK = "kvn-deploy-e2e-network"


def available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


PORT = int(os.environ.get("KVN_DEPLOY_E2E_PORT", "0")) or available_port()
IP_MODE = os.environ.get("KVN_DEPLOY_E2E_IP") == "1"
DOMAIN = "1.1.1.1" if IP_MODE else "portal.test"
PORTAL_PATH = "/gaer"
LOGIN = "admin"
PASSWORD = "VisualPassword-2026"
SECRET = "e2e-agent-secret-" + "a" * 48
os.environ.setdefault("BUILDX_NO_DEFAULT_ATTESTATIONS", "1")


def docker_daemon_path(path: Path) -> str:
    """Путь host bind, одинаково видимый agent-контейнеру и Docker daemon."""
    resolved = path.resolve()
    if os.name != "nt":
        return resolved.as_posix()
    drive = resolved.drive.rstrip(":").lower()
    relative = resolved.relative_to(resolved.anchor).as_posix()
    return f"/run/desktop/mnt/host/{drive}/{relative}"


def run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    timeout: int = 300,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    print("+", subprocess.list2cmdline(argv), flush=True)
    result = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
    )
    if result.stdout.strip():
        print(result.stdout.rstrip())
    if result.stderr.strip():
        print(result.stderr.rstrip(), file=sys.stderr)
    if check and result.returncode != 0:
        raise RuntimeError(f"Команда завершилась с кодом {result.returncode}: {argv[0]}")
    return result


def docker_compose(*args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return run(
        [
            "docker", "compose", "-p", PROJECT_NAME,
            "-f", str(PROJECT / "docker-compose.yml"),
            "-f", str(PROJECT / "docker-compose.e2e.yml"),
            *args,
        ],
        cwd=PROJECT,
        check=check,
        timeout=timeout,
    )


def build_deploy_archive() -> None:
    if os.name == "nt":
        run([
            "docker", "run", "--rm", "-v", f"{ROOT}:/work", "-w", "/work",
            "python:3.13-slim", "bash", "tools/build-deploy.sh",
        ], timeout=300)
    else:
        run(["bash", "tools/build-deploy.sh"], timeout=300)


def cleanup() -> None:
    if PROJECT.exists():
        try:
            docker_compose("down", "--volumes", "--remove-orphans", check=False, timeout=120)
        except Exception:
            pass
    run(
        ["docker", "rm", "-f", AGENT_CONTAINER, PORTAL_CONTAINER, GATEWAY_CONTAINER],
        check=False,
        timeout=30,
    )
    run(["docker", "volume", "rm", "-f", SOCKET_VOLUME, DATA_VOLUME, METRICS_VOLUME], check=False, timeout=30)
    run(["docker", "network", "rm", NETWORK], check=False, timeout=30)
    if WORK.exists():
        shutil.rmtree(WORK)


def extract_archive() -> None:
    WORK.mkdir(parents=True)
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        for member in members:
            target = (WORK / member.name).resolve()
            if WORK.resolve() not in target.parents and target != WORK.resolve():
                raise RuntimeError(f"Небезопасный путь в архиве: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"Ссылки в deploy-архиве запрещены: {member.name}")
        archive.extractall(WORK, members=members, filter="data")
    if not PROJECT.is_dir():
        raise RuntimeError("В архиве отсутствует корневой каталог deploy/")


def assert_archive_clean() -> None:
    required = {
        "docker-compose.yml",
        "setup.sh",
        "update.sh",
        "tools/kvnctl.py",
        "tools/kvnlib/__init__.py",
        "tools/kvnlib/apply.py",
        "tools/kvnlib/state.py",
        "wireguard/install-host-service.sh",
        "wireguard/sync-host-service.sh",
        "portal/Dockerfile",
        "portal/agent.py",
        "portal/metrics.py",
        "portal/app/__init__.py",
        "portal/app/templates/file_preview.html",
    }
    present = {
        path.relative_to(PROJECT).as_posix()
        for path in PROJECT.rglob("*")
        if path.is_file()
    }
    missing = sorted(required - present)
    if missing:
        raise RuntimeError(f"В deploy отсутствуют обязательные файлы: {', '.join(missing)}")
    forbidden_parts = {
        "portal.db", "portal.db-wal", "portal.db-shm",
        "metrics.db", "metrics.db-wal", "metrics.db-shm",
        "control.sock", "agent.secret",
    }
    leaked = sorted(path for path in present if Path(path).name in forbidden_parts)
    if leaked:
        raise RuntimeError(f"В deploy попали runtime-данные: {', '.join(leaked)}")
    if "nginx/portal-gateway.conf" in present:
        raise RuntimeError("В deploy попал сгенерированный portal-gateway.conf")
    state = json.loads((PROJECT / "users.json").read_text(encoding="utf-8"))
    if state.get("server") != "YOUR_SERVER_IP" or state.get("users") != []:
        raise RuntimeError("deploy/users.json содержит рабочие данные")
    if state.get("portal", {}).get("enabled") is not False:
        raise RuntimeError("Портал в deploy/users.json должен быть выключен")


def password_hash(password: str) -> str:
    salt = bytes.fromhex("22" * 16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1, dklen=32,
        maxmem=256 * 1024 * 1024,
    )
    salt_text = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_text = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"scrypt$131072$8$1${salt_text}${digest_text}"


def write_fixture() -> None:
    state = {
        "server": "127.0.0.1",
        "site": {"title": "KVN E2E"},
        "subscription": {"enabled": False, "port": 2096},
        "letsencrypt": {
            "enabled": not IP_MODE,
            "domain": "" if IP_MODE else DOMAIN,
            "domains": [] if IP_MODE else [DOMAIN],
        },
        "ocserv": {"enabled": False, "sni_enabled": False},
        "services": {
            "nginx": {"enabled": False},
            "xray": {"enabled": False},
            "hysteria": {"enabled": False},
            "telemt": {"enabled": False},
            "mtg": {"enabled": False},
            "ocserv": {"enabled": False},
            "portal": {"enabled": True},
            "agent": {"enabled": True},
            "amneziawg": {"enabled": True},
            "wireguard": {"enabled": True},
        },
        "sni_routes": {},
        "portal": {
            "enabled": True,
            "name": "KVN Deploy E2E",
            "domain": DOMAIN,
            "port": PORT,
            "path": PORTAL_PATH,
            "login": LOGIN,
            "password_hash": password_hash(PASSWORD),
            "proxy_secret": "b" * 64,
            "hysteria_secret": "c" * 64,
            "allow_self_signed_ip": IP_MODE,
        },
        "users": [],
    }
    (PROJECT / "users.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (PROJECT / "portal-runtime").mkdir(parents=True, exist_ok=True)
    (PROJECT / "portal-runtime" / "users.json").write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (PROJECT / "e2e-agent.secret").write_text(SECRET + "\n", encoding="ascii")
    (PROJECT / "ocserv" / "ocserv.env").write_text("", encoding="ascii")
    (PROJECT / ".env").write_text(
        f"KVN_PORTAL_PORT={PORT}\nKVN_PORTAL_GID=12345\nCOMPOSE_PROFILES=portal,portal-custom\n",
        encoding="ascii",
    )
    override = f"""services:
  portal:
    container_name: {PORTAL_CONTAINER}
    volumes:
      - portal-data:/data
      - portal-socket:/run/kvn-portal:ro
      - ./e2e-agent.secret:/run/secrets/agent-token:ro
  portal-gateway:
    container_name: {GATEWAY_CONTAINER}
volumes:
  portal-data:
    external: true
    name: {DATA_VOLUME}
  portal-socket:
    external: true
    name: {SOCKET_VOLUME}
networks:
  default:
    external: true
    name: {NETWORK}
"""
    (PROJECT / "docker-compose.e2e.yml").write_text(override, encoding="utf-8")


def build_agent_image() -> None:
    run(
        ["docker", "build", "-f", str(ROOT / "tests" / "e2e-agent.Dockerfile"), "-t", AGENT_IMAGE, str(ROOT)],
        timeout=600,
    )
    run(
        ["docker", "build", "-f", str(ROOT / "tests" / "qr-verifier.Dockerfile"), "-t", QR_IMAGE, str(ROOT)],
        timeout=600,
    )


def generate_certificate_and_gateway() -> None:
    if IP_MODE:
        certificate_commands = f"""
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN={DOMAIN}" \\
  -addext "subjectAltName=IP:{DOMAIN}" -addext "extendedKeyUsage=serverAuth" \\
  -keyout /project/site-certs/server.key -out /project/site-certs/server.crt >/dev/null 2>&1
"""
    else:
        certificate_commands = """
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj "/CN=Let's Encrypt E2E CA" -keyout /tmp/ca.key -out /tmp/ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=portal.test" \
  -keyout /project/site-certs/server.key -out /tmp/site.csr >/dev/null 2>&1
printf 'subjectAltName=DNS:portal.test\nextendedKeyUsage=serverAuth\n' >/tmp/site.ext
openssl x509 -req -days 2 -sha256 -in /tmp/site.csr -CA /tmp/ca.crt -CAkey /tmp/ca.key \
  -CAcreateserial -extfile /tmp/site.ext -out /project/site-certs/server.crt >/dev/null 2>&1
"""
    script = f"""
set -eu
mkdir -p /project/site-certs
{certificate_commands}
chmod 0644 /project/site-certs/server.crt /project/site-certs/server.key
python -c 'import json; from tools.kvnctl import render_portal_gateway; render_portal_gateway(json.load(open("users.json", encoding="utf-8")))'
"""
    run(
        ["docker", "run", "--rm", "-v", f"{PROJECT}:/project", AGENT_IMAGE, "sh", "-c", script],
        timeout=120,
    )
    gateway = PROJECT / "nginx" / "portal-gateway.conf"
    content = gateway.read_text(encoding="utf-8")
    # E2E делает десятки запросов за секунды; production rate-limit проверяется
    # unit-тестами, а здесь он не должен маскировать portal/auth assertions.
    content = content.replace("rate=120r/m", "rate=6000r/m").replace(
        "limit_req zone=portal burst=20", "limit_req zone=portal burst=200",
    )
    gateway.write_text(content, encoding="utf-8")
    for expected in [DOMAIN, f"location = {PORTAL_PATH}", f"location ^~ {PORTAL_PATH}/"]:
        if expected not in content:
            raise RuntimeError(f"Некорректный gateway-конфиг: отсутствует {expected}")


def start_stack() -> None:
    run(["docker", "volume", "create", SOCKET_VOLUME])
    run(["docker", "volume", "create", DATA_VOLUME])
    run(["docker", "volume", "create", METRICS_VOLUME])
    run(
        [
            "docker", "run", "--rm", "-v", f"{DATA_VOLUME}:/data",
            "alpine:3.22", "chown", "10001:10001", "/data",
        ],
        timeout=60,
    )
    run(["docker", "network", "create", NETWORK])
    docker_compose("--profile", "portal", "--profile", "portal-custom", "config", "--quiet")
    # Host-agent запускает Compose через Docker socket. Его project root должен
    # совпадать с путём, который видит daemon, иначе bind mounts станут `/project/*`.
    agent_project = docker_daemon_path(PROJECT)
    agent_script = f"""
set -eu
addgroup -g 12345 kvn-portal
chown root:kvn-portal /run/kvn-portal
chmod 0750 /run/kvn-portal
exec python {shlex.quote(f"{agent_project}/portal/agent.py")} --project-root {shlex.quote(agent_project)} \
  --socket /run/kvn-portal/control.sock --secret-file /run/secrets/agent-token \
  --socket-group kvn-portal
"""
    run(
        [
            "docker", "run", "-d", "--name", AGENT_CONTAINER,
            "--network", NETWORK,
            "-e", f"COMPOSE_PROJECT_NAME={PROJECT_NAME}",
            "-v", f"{PROJECT}:{agent_project}",
            "-v", f"{SOCKET_VOLUME}:/run/kvn-portal",
            "-v", f"{METRICS_VOLUME}:/var/lib/kvn-portal",
            "-v", f"{PROJECT / 'e2e-agent.secret'}:/run/secrets/agent-token:ro",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            AGENT_IMAGE, "sh", "-c", agent_script,
        ],
        timeout=60,
    )
    for _ in range(50):
        ready = run(
            ["docker", "exec", AGENT_CONTAINER, "test", "-S", "/run/kvn-portal/control.sock"],
            check=False,
            timeout=10,
        )
        if ready.returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("Host-agent не создал Unix socket")
    docker_compose(
        "--profile", "portal", "--profile", "portal-custom",
        "up", "-d", "--build", "--remove-orphans", "portal", "portal-gateway",
        timeout=900,
    )


def wait_https() -> None:
    last_error = ""
    for _ in range(90):
        try:
            status, _headers, body = request("GET", f"{PORTAL_PATH}/login")
            if status == 200 and "Управление KVN VPN" in body:
                return
            last_error = f"HTTP {status}"
        except Exception as exc:  # контейнеры ещё запускаются
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(f"HTTPS-портал не стал доступен: {last_error}")


def request(
    method: str,
    path: str,
    *,
    fields: dict[str, str | list[str]] | None = None,
    cookie: str = "",
) -> tuple[int, dict[str, str], str]:
    status, headers, payload = request_raw(method, path, fields=fields, cookie=cookie)
    return status, headers, payload.decode("utf-8", errors="replace")


def request_raw(
    method: str,
    path: str,
    *,
    fields: dict[str, str | list[str]] | None = None,
    cookie: str = "",
) -> tuple[int, dict[str, str], bytes]:
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection("127.0.0.1", PORT, context=context, timeout=20)
    body = urlencode(fields, doseq=True).encode("utf-8") if fields is not None else None
    headers = {"Host": DOMAIN, "User-Agent": "KVN-Deploy-E2E/1.0"}
    if fields is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read()
    response_headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, payload


def verify_portal() -> None:
    status, headers, login_page = request("GET", f"{PORTAL_PATH}/login")
    if status != 200:
        raise RuntimeError(f"Страница входа вернула HTTP {status}")
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', login_page)
    if not csrf_match:
        raise RuntimeError("На странице входа отсутствует CSRF token")
    status, headers, _body = request(
        "POST",
        f"{PORTAL_PATH}/login",
        fields={"login": LOGIN, "password": PASSWORD, "csrf_token": csrf_match.group(1)},
    )
    if status != 302 or headers.get("location") != f"{PORTAL_PATH}/":
        raise RuntimeError(f"Вход не выполнен: HTTP {status}, Location={headers.get('location')}")
    cookie = headers.get("set-cookie", "").split(";", 1)[0]
    if not cookie:
        raise RuntimeError("После входа не выдана session cookie")

    routes = {
        f"{PORTAL_PATH}/": "KVN Deploy E2E",
        f"{PORTAL_PATH}/users": "Пользователи",
        f"{PORTAL_PATH}/users/new": "Новый пользователь",
        f"{PORTAL_PATH}/services": "Сервисы",
        f"{PORTAL_PATH}/logs": "Логи",
        f"{PORTAL_PATH}/certificates": "Сертификаты",
        f"{PORTAL_PATH}/health": "Диагностика",
        f"{PORTAL_PATH}/audit": "Аудит",
        f"{PORTAL_PATH}/settings": "Нагрузка портала",
    }
    for path, marker in routes.items():
        status, headers, body = request("GET", path, cookie=cookie)
        if status != 200:
            raise RuntimeError(f"Раздел {path} вернул HTTP {status}")
        if marker not in body or "ОШИБКА 500" in body.upper() or "Внутренняя ошибка" in body:
            raise RuntimeError(f"Раздел {path} отрисован некорректно")
        if "strict-transport-security" not in headers:
            raise RuntimeError(f"Раздел {path} не вернул HSTS")

    status, _headers, body = request("GET", f"{PORTAL_PATH}/", cookie=cookie)
    expected_links = ["users", "services", "logs", "certificates", "health", "audit"]
    for link in expected_links:
        if f'href="{PORTAL_PATH}/{link}' not in body:
            raise RuntimeError(f"В меню отсутствует пункт {link}")

    status, headers, body = request("GET", f"{PORTAL_PATH}/dashboard.json", cookie=cookie)
    if status != 200 or headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise RuntimeError("dashboard.json недоступен")
    cards = json.loads(body).get("cards", [])
    card_ids = {card.get("id") for card in cards if isinstance(card, dict)}
    if card_ids != {"server", "cpu", "memory", "disk", "network", "containers", "protocols", "certificates"}:
        raise RuntimeError("dashboard.json вернул неполный набор человекочитаемых KPI")

    status, headers, body = request(
        "GET", f"{PORTAL_PATH}/metrics/history.json?range_hours=1&step=1", cookie=cookie,
    )
    history = json.loads(body) if status == 200 else {}
    if status != 200 or history.get("range_hours") != 1 or not history.get("points"):
        raise RuntimeError("История host metrics недоступна или пуста")

    settings_result = ""
    for attempt in range(2):
        status, _headers, settings_page = request("GET", f"{PORTAL_PATH}/settings", cookie=cookie)
        settings_csrf = re.search(r'name="csrf_token" value="([^"]+)"', settings_page)
        settings_revision = re.search(r'name="revision" value="([^"]+)"', settings_page)
        if status != 200 or not settings_csrf or not settings_revision:
            raise RuntimeError("Настройки нагрузки портала недоступны")
        status, _headers, settings_result = request(
            "POST", f"{PORTAL_PATH}/settings", cookie=cookie,
            fields={
                "csrf_token": settings_csrf.group(1),
                "action": "performance",
                "revision": settings_revision.group(1),
                "profile": "light",
            },
        )
        if status != 409:
            break
        if attempt == 0:
            time.sleep(0.2)
    if status != 200 or "Режим портала обновлён" not in settings_result:
        safe_excerpt = re.sub(r"\s+", " ", settings_result)[:500]
        raise RuntimeError(
            f"Облегчённый профиль не сохранился через портал: HTTP {status}; {safe_excerpt}"
        )
    light_state = json.loads((PROJECT / "users.json").read_text(encoding="utf-8"))["portal"]
    if light_state.get("performance_profile") != "light" or light_state.get("features") != {
        "monitoring": False, "background_refresh": False,
    }:
        raise RuntimeError("Облегчённый профиль не попал в source of truth")
    status, _headers, light_dashboard = request("GET", f"{PORTAL_PATH}/", cookie=cookie)
    if status != 200 or "Мониторинг отключён" not in light_dashboard:
        raise RuntimeError("Dashboard не объясняет облегчённый режим")

    status, _headers, create_page = request("GET", f"{PORTAL_PATH}/users/new", cookie=cookie)
    create_csrf = re.search(r'name="csrf_token" value="([^"]+)"', create_page)
    revision = re.search(r'name="revision" value="([^"]+)"', create_page)
    if status != 200 or not create_csrf or not revision:
        raise RuntimeError("Не удалось подготовить создание AWG-пользователя")
    status, _headers, result_page = request(
        "POST", f"{PORTAL_PATH}/users/new", cookie=cookie,
        fields={
            "csrf_token": create_csrf.group(1), "revision": revision.group(1),
            "name": "release-awg", "description": "Deploy E2E",
            "device": "ios", "systems": ["hysteria", "amneziawg", "wireguard"], "enabled": "on",
        },
    )
    if status != 200 or "Пользователь создан" not in result_page:
        raise RuntimeError(f"Создание AWG-пользователя завершилось некорректно: HTTP {status}")
    result_csrf = re.search(r'name="csrf_token" value="([^"]+)"', result_page)
    if not result_csrf:
        raise RuntimeError("Результат создания не содержит CSRF для reconcile")

    status, _headers, user_page = request("GET", f"{PORTAL_PATH}/users/release-awg", cookie=cookie)
    expected_files = [
        "amneziawg.conf", "amneziawg.png", "wireguard.conf", "wireguard.png",
        "happ-subscription.txt", "happ-subscription.png",
        "karing-subscription.txt", "karing-subscription.png",
        "karing-wireguard.txt", "karing-wireguard.png", "karing-wireguard.yaml",
    ]
    if status != 200 or any(filename not in user_page for filename in expected_files):
        raise RuntimeError("Карточка пользователя не содержит AWG/HAPP/Karing конфиги и QR")
    for filename in expected_files:
        status, headers, payload = request_raw(
            "GET", f"{PORTAL_PATH}/users/release-awg/files/{filename}", cookie=cookie,
        )
        if status != 200 or not payload or "attachment" not in headers.get("content-disposition", ""):
            raise RuntimeError(f"Скачивание {filename} не работает")
        status, _headers, preview = request(
            "GET", f"{PORTAL_PATH}/users/release-awg/files/{filename}/view", cookie=cookie,
        )
        if status != 200 or filename not in preview:
            raise RuntimeError(f"Preview {filename} не работает")
    for filename, marker in [
        ("amneziawg.png", "[Interface]"),
        ("wireguard.png", "[Interface]"),
        ("happ-subscription.png", "https://"),
        ("karing-subscription.png", "https://"),
        ("karing-wireguard.png", "/karing-wg/"),
    ]:
        decoded = run(
            [
                "docker", "run", "--rm", "-v", f"{PROJECT}:/project:ro", QR_IMAGE,
                f"/project/clients/release-awg/{filename}",
            ],
            timeout=30,
        ).stdout
        if marker not in decoded:
            raise RuntimeError(f"QR {filename} не декодируется в ожидаемый payload")
        status, headers, payload = request_raw(
            "GET", f"{PORTAL_PATH}/users/release-awg/files/{filename}/inline", cookie=cookie,
        )
        if status != 200 or headers.get("content-type") != "image/png" or not payload.startswith(b"\x89PNG"):
            raise RuntimeError(f"Inline QR {filename} недоступен")

    status, headers, _body = request(
        "GET", f"{PORTAL_PATH}/users/release-awg/files/amneziawg.conf",
    )
    if status != 302 or headers.get("location") != f"{PORTAL_PATH}/login":
        raise RuntimeError("Клиентский конфиг доступен без аутентификации")

    status, _headers, reconcile_page = request(
        "POST", f"{PORTAL_PATH}/reconcile", cookie=cookie,
        fields={"csrf_token": result_csrf.group(1)},
    )
    if status != 200 or "Состояние повторно применено" not in reconcile_page:
        raise RuntimeError("Reconcile через портал не завершён")

    runtime_state = json.loads((PROJECT / "users.json").read_text(encoding="utf-8"))
    created = next((user for user in runtime_state.get("users", []) if user.get("name") == "release-awg"), None)
    if not created or not {"amneziawg", "wireguard"}.issubset(set(created.get("systems", []))):
        raise RuntimeError("Созданный AWG/WireGuard-пользователь не сохранён в source of truth")

    for asset, content_type in [
        ("style.css", "text/css"),
        ("base.js", "text/javascript"),
        ("dashboard.js", "text/javascript"),
        ("app.js", "text/javascript"),
    ]:
        status, headers, body = request("GET", f"{PORTAL_PATH}/static/{asset}", cookie=cookie)
        if status != 200 or content_type not in headers.get("content-type", "") or not body.strip():
            raise RuntimeError(f"Статический ресурс {asset} недоступен через custom path")

    status, _headers, dashboard = request("GET", f"{PORTAL_PATH}/", cookie=cookie)
    csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', dashboard)
    if status != 200 or not csrf_match:
        raise RuntimeError("Не удалось получить CSRF token для выхода")
    status, headers, _body = request(
        "POST", f"{PORTAL_PATH}/logout",
        fields={"csrf_token": csrf_match.group(1)}, cookie=cookie,
    )
    if status != 302 or headers.get("location") != f"{PORTAL_PATH}/login":
        raise RuntimeError("Выход из портала не завершён")

    for attempt in range(1, 6):
        status, _headers, login_page = request("GET", f"{PORTAL_PATH}/login")
        csrf_match = re.search(r'name="csrf_token" value="([^"]+)"', login_page)
        if status != 200 or not csrf_match:
            raise RuntimeError("Страница входа недоступна перед проверкой lockout")
        status, headers, _body = request(
            "POST", f"{PORTAL_PATH}/login",
            fields={"login": LOGIN, "password": "WrongPassword-2026", "csrf_token": csrf_match.group(1)},
        )
        expected = 429 if attempt == 5 else 401
        if status != expected:
            raise RuntimeError(f"Попытка входа {attempt}: ожидался HTTP {expected}, получен {status}")
        if attempt == 5 and int(headers.get("retry-after", "0")) < 12 * 60 * 60 - 5:
            raise RuntimeError("IP заблокирован менее чем на 12 часов")


def verify_security_and_logs() -> None:
    project_services = set(run([
        "docker", "ps",
        "--filter", f"label=com.docker.compose.project={PROJECT_NAME}",
        "--format", '{{.Label "com.docker.compose.service"}}',
    ]).stdout.splitlines())
    unexpected = project_services - {"portal", "portal-gateway"}
    if unexpected:
        raise RuntimeError(
            f"E2E запустил явно отключённые Compose-сервисы: {', '.join(sorted(unexpected))}"
        )

    inspect = json.loads(run(["docker", "inspect", PORTAL_CONTAINER]).stdout)[0]
    mounts = inspect.get("Mounts", [])
    if any(mount.get("Destination") == "/var/run/docker.sock" for mount in mounts):
        raise RuntimeError("Docker socket смонтирован в web-контейнер")
    destinations = {mount.get("Destination") for mount in mounts}
    if "/project/runtime" not in destinations or "/project/users.json" in destinations:
        raise RuntimeError("Портал использует небезопасный одиночный bind users.json")
    host = inspect["HostConfig"]
    if not host.get("ReadonlyRootfs") or host.get("CapDrop") != ["ALL"]:
        raise RuntimeError("Нарушено усиление web-контейнера")
    if not any(option.startswith("no-new-privileges") for option in host.get("SecurityOpt", [])):
        raise RuntimeError("Для web-контейнера не включён no-new-privileges")
    if host.get("Memory") != 192 * 1024 * 1024 or host.get("NanoCpus") != 350_000_000 or host.get("PidsLimit") != 64:
        raise RuntimeError("Ресурсные лимиты portal не соответствуют профилю 1 vCPU/1 ГБ")

    gateway_inspect = json.loads(run(["docker", "inspect", GATEWAY_CONTAINER]).stdout)[0]
    gateway_host = gateway_inspect["HostConfig"]
    if gateway_host.get("Memory") != 64 * 1024 * 1024 or gateway_host.get("NanoCpus") != 150_000_000 or gateway_host.get("PidsLimit") != 32:
        raise RuntimeError("Ресурсные лимиты portal-gateway не соответствуют профилю 1 vCPU/1 ГБ")
    portal_pids = max(0, len([line for line in run(["docker", "top", PORTAL_CONTAINER]).stdout.splitlines() if line.strip()]) - 1)
    gateway_pids = max(0, len([line for line in run(["docker", "top", GATEWAY_CONTAINER]).stdout.splitlines() if line.strip()]) - 1)
    stats = run([
        "docker", "stats", "--no-stream", "--format", "{{json .}}",
        PORTAL_CONTAINER, GATEWAY_CONTAINER,
    ]).stdout.splitlines()
    if portal_pids > 64 or gateway_pids > 32 or inspect.get("RestartCount") != 0 or gateway_inspect.get("RestartCount") != 0:
        raise RuntimeError("Constrained smoke превысил PID limit или обнаружил restart")
    print(
        f"[INFO] Constrained smoke: portal_pids={portal_pids}/64, gateway_pids={gateway_pids}/32, "
        f"restarts=0, stats={' | '.join(stats)}"
    )

    runtime_path = PROJECT / "portal-runtime" / "users.json"
    runtime_state = json.loads(runtime_path.read_text(encoding="utf-8"))
    runtime_state["e2e_runtime_revision"] = "atomic-replace-visible"
    temporary = runtime_path.with_suffix(".tmp")
    temporary.write_text(json.dumps(runtime_state, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, runtime_path)
    host_hash = hashlib.sha256(runtime_path.read_bytes()).hexdigest()
    container_hash = run(
        ["docker", "exec", PORTAL_CONTAINER, "sha256sum", "/project/runtime/users.json"],
        timeout=30,
    ).stdout.split()[0]
    current_id = json.loads(run(["docker", "inspect", PORTAL_CONTAINER]).stdout)[0]["Id"]
    if host_hash != container_hash or current_id != inspect["Id"]:
        raise RuntimeError("Atomic replace runtime-state потребовал recreate портала")

    gateway_id = json.loads(run(["docker", "inspect", GATEWAY_CONTAINER]).stdout)[0]["Id"]
    users_hash = hashlib.sha256((PROJECT / "users.json").read_bytes()).hexdigest()
    metrics_before = int(run([
        "docker", "exec", AGENT_CONTAINER, "python", "-c",
        "import sqlite3; print(sqlite3.connect('/var/lib/kvn-portal/metrics.db').execute('select count(*) from samples').fetchone()[0])",
    ]).stdout.strip())
    portal_rows_before = run([
        "docker", "exec", PORTAL_CONTAINER, "python", "-c",
        "import sqlite3; db=sqlite3.connect('/data/portal.db'); print(*[db.execute('select count(*) from '+name).fetchone()[0] for name in ('login_failures','audit_events')])",
    ]).stdout.strip()
    docker_compose(
        "--profile", "portal", "--profile", "portal-custom",
        "up", "-d", "--build", "--remove-orphans", "portal", "portal-gateway",
        timeout=900,
    )
    rerun_portal = json.loads(run(["docker", "inspect", PORTAL_CONTAINER]).stdout)[0]
    rerun_gateway = json.loads(run(["docker", "inspect", GATEWAY_CONTAINER]).stdout)[0]
    metrics_after = int(run([
        "docker", "exec", AGENT_CONTAINER, "python", "-c",
        "import sqlite3; print(sqlite3.connect('/var/lib/kvn-portal/metrics.db').execute('select count(*) from samples').fetchone()[0])",
    ]).stdout.strip())
    portal_rows_after = run([
        "docker", "exec", PORTAL_CONTAINER, "python", "-c",
        "import sqlite3; db=sqlite3.connect('/data/portal.db'); print(*[db.execute('select count(*) from '+name).fetchone()[0] for name in ('login_failures','audit_events')])",
    ]).stdout.strip()
    if rerun_portal["Id"] != current_id or rerun_gateway["Id"] != gateway_id:
        raise RuntimeError("Идемпотентный Compose rerun пересоздал неизменённый portal consumer")
    if metrics_after < metrics_before or portal_rows_after != portal_rows_before:
        raise RuntimeError("Повторный запуск потерял metrics history или portal runtime schema/data")
    if hashlib.sha256((PROJECT / "users.json").read_bytes()).hexdigest() != users_hash:
        raise RuntimeError("Повторный запуск изменил users/credentials state")
    print(
        f"[OK] Rerun: portal/gateway IDs сохранены; metrics {metrics_before}->{metrics_after}; "
        f"portal rows {portal_rows_before}"
    )

    rpc = run(
        [
            "docker", "exec", PORTAL_CONTAINER, "python", "-c",
            "from pathlib import Path; from agent_client import AgentClient; "
            "secret=Path('/run/secrets/agent-token').read_text().strip(); "
            "print(AgentClient(Path('/run/kvn-portal/control.sock'), secret).call('ping', {}))",
        ],
        timeout=30,
    )
    if "'status': 'ok'" not in rpc.stdout:
        raise RuntimeError("Web-контейнер не может вызвать host-agent")

    ps = docker_compose("ps", "--format", "json")
    if PORTAL_CONTAINER not in ps.stdout or GATEWAY_CONTAINER not in ps.stdout:
        raise RuntimeError("Контейнеры портала отсутствуют в compose ps")
    portal_state = rerun_portal.get("State", {})
    gateway_state = rerun_gateway.get("State", {})
    if portal_state.get("Status") != "running" or portal_state.get("Health", {}).get("Status") != "healthy":
        raise RuntimeError("Portal container не running/healthy после rerun")
    if gateway_state.get("Status") != "running":
        raise RuntimeError("Portal gateway не running после rerun")
    logs = docker_compose("logs", "--no-color", "portal", "portal-gateway").stdout
    lowered = logs.lower()
    for forbidden in ["traceback", "internal server error", "emerg", "permission denied"]:
        if forbidden in lowered:
            raise RuntimeError(f"В логах портала обнаружено: {forbidden}")
    agent_logs = run(["docker", "logs", AGENT_CONTAINER]).stdout.lower()
    if "traceback" in agent_logs:
        raise RuntimeError("Host-agent завершился с traceback")


def main() -> int:
    if shutil.which("docker") is None:
        # В минимальном контейнере без Docker CLI проверяем офлайн-контракты;
        # полный lifecycle запускается отдельно через Docker Desktop на хосте.
        subprocess.run(
            [sys.executable, "-m", "unittest", "tests.test_offline_release", "-v"],
            cwd=ROOT,
            check=True,
        )
        print("[SKIP] Docker CLI недоступен; офлайн-контракты release проверены")
        return 0
    keep = os.environ.get("KVN_KEEP_DEPLOY_E2E") == "1"
    cleanup()
    try:
        build_deploy_archive()
        extract_archive()
        assert_archive_clean()
        write_fixture()
        build_agent_image()
        generate_certificate_and_gateway()
        start_stack()
        wait_https()
        verify_portal()
        verify_security_and_logs()
        mode = "IP без DNS" if IP_MODE else "домен"
        print(f"[OK] Deploy runtime E2E ({mode}): HTTPS, вход, Settings/light, все меню, metrics history, AWG apply, QR, reconcile, rerun и hardening проверены")
        return 0
    finally:
        if keep:
            print(f"[INFO] E2E-стенд оставлен запущенным: https://{DOMAIN}:{PORT}{PORTAL_PATH}/")
        else:
            cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
