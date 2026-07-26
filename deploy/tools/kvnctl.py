#!/usr/bin/env python3
"""Управление пользователями и клиентскими конфигами KVN VPN v3."""

from __future__ import annotations

import argparse
import base64
import copy
import datetime
import getpass
import hashlib
import html
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import string
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import uuid
from contextlib import closing
from pathlib import Path
from urllib.parse import quote, urlencode

try:
    import grp
except ImportError:  # pragma: no cover - нет на Windows
    grp = None  # type: ignore[assignment]

try:
    from tools.kvnlib import (
        ApplyAction,
        ChangeSet,
        ClientExportPolicy,
        ClientExportValidationError,
        ExportSection,
        JsonStateStore,
        RenderResult,
        add_client_export_parsers,
        atomic_write_private,
        atomic_write_json,
        build_change_set,
        client_connection_host,
        configured_service_preferences,
        effective_service_plan,
        normalize_client_export_state,
        render_export_document,
        serialize_user_export,
        subscription_ip_readiness,
        with_client_export_policy,
    )
except ModuleNotFoundError:  # запуск как python3 tools/kvnctl.py
    from kvnlib import (
        ApplyAction,
        ChangeSet,
        ClientExportPolicy,
        ClientExportValidationError,
        ExportSection,
        JsonStateStore,
        RenderResult,
        add_client_export_parsers,
        atomic_write_private,
        atomic_write_json,
        build_change_set,
        client_connection_host,
        configured_service_preferences,
        effective_service_plan,
        normalize_client_export_state,
        render_export_document,
        serialize_user_export,
        subscription_ip_readiness,
        with_client_export_policy,
    )


# ── Цвета ──────────────────────────────────────────────────────────────────

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR") == "1"


class C:
    """ANSI-цвета для терминала. Отключаются если NO_COLOR=1 или piped вывод."""

    if _NO_COLOR:
        reset = bold = dim = red = green = yellow = cyan = magenta = blue = ""
    else:
        reset = "\033[0m"
        bold = "\033[1m"
        dim = "\033[2m"
        red = "\033[31m"
        green = "\033[32m"
        yellow = "\033[33m"
        blue = "\033[34m"
        magenta = "\033[35m"
        cyan = "\033[36m"


def ok(msg: str) -> None:
    print(f"{C.green}[OK]{C.reset} {msg}")


def warn(msg: str) -> None:
    print(f"{C.yellow}[WARN]{C.reset} {msg}")


def err(msg: str) -> None:
    print(f"{C.red}[ОШИБКА]{C.reset} {msg}")


def info(msg: str) -> None:
    print(f"{C.cyan}[INFO]{C.reset} {msg}")


def header(msg: str) -> None:
    width = max(len(msg) + 4, 52)
    print(f"\n{C.bold}{C.cyan}{'═' * width}{C.reset}")
    print(f"{C.bold}{C.cyan}  {msg}{C.reset}")
    print(f"{C.bold}{C.cyan}{'═' * width}{C.reset}")


def separator() -> None:
    print(f"{C.dim}{'─' * 52}{C.reset}")


ROOT = Path(__file__).resolve().parents[1]
USERS_FILE = ROOT / "users.json"
STATE_STORE = JsonStateStore(USERS_FILE, ROOT / ".kvnctl.lock")
PORTAL_RUNTIME_DIR = ROOT / "portal-runtime"
PORTAL_RUNTIME_STATE = PORTAL_RUNTIME_DIR / "users.json"
XRAY_CONFIG = ROOT / "xray" / "config.json"
HY2_CONFIG = ROOT / "hy2" / "config.yaml"
NGINX_CONFIG = ROOT / "nginx" / "nginx.conf"
PORTAL_GATEWAY_CONFIG = ROOT / "nginx" / "portal-gateway.conf"
TELEMT_CONFIG = ROOT / "telemt" / "config.toml"
AMNEZIAWG_CONFIG = ROOT / "amneziawg" / "awg0.conf"
WIREGUARD_CONFIG = ROOT / "wireguard" / "wg0.conf"
OCSERV_CONFIG = ROOT / "ocserv" / "ocserv.conf"
OCSERV_USERS = ROOT / "ocserv" / "users.txt"
OCSERV_ENV = ROOT / "ocserv" / "ocserv.env"
OCSERV_CERTS_DIR = ROOT / "ocserv" / "certs"
SITE_CERTS_DIR = ROOT / "site-certs"
LE_LIVE_DIR = Path("/etc/letsencrypt/live")
LE_RENEWAL_DIR = Path("/etc/letsencrypt/renewal")
HOST_AMNEZIAWG_CONFIG = Path("/etc/amnezia/amneziawg/awg0.conf")
HOST_WIREGUARD_CONFIG = Path("/etc/wireguard/wg0.conf")
SUB_WEB_DIR = ROOT / "nginx" / "web"
DECOY_SITE_DIR = ROOT / "nginx" / "site"
CLIENTS_DIR = ROOT / "clients"
CLIENT_LINKS_FILE = ROOT / "CLIENT_LINKS.md"
DEFAULT_SUB_PORT = 2096
XRAY_IMAGE = "ghcr.io/xtls/xray-core:26.3.27"
DIRECT_PORTS = {
    "tls": 2443,
    "reality-xhttp": 2444,
    "reality-tcp": 2445,
    "telemt": 2446,
    "mtg": 2447,
    "ocserv": 2448,
}
NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
SUB_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
HYSTERIA_PASSWORD_RE = re.compile(r"^[A-Za-z0-9_.@%+=-]{8,128}$")
OCSERV_PASSWORD_RE = re.compile(r"^[A-Za-z0-9_.@%+=-]{8,128}$")
MAX_DESCRIPTION_LEN = 200
MAX_SITE_TITLE_LEN = 80
X25519_P = 2**255 - 19
TLS_INBOUND_TAG = "tls-vision-443"
REALITY_XHTTP_INBOUND_TAG = "reality-xhttp-2053"
REALITY_TCP_INBOUND_TAG = "reality-tcp-2054"
# ВНИМАНИЕ: Xray считает maxTimeDiff в МИЛЛИСЕКУНДАХ.
# По умолчанию не задаём, чтобы профиль Reality совпадал с рабочим сервером пользователя.
# При необходимости можно добавить в users.json: xray.reality_max_time_diff_ms = 60000.
REALITY_MAX_TIME_DIFF_MS = 0
XHTTP_DEFAULT_MODE = "stream-one"
REALITY_XHTTP_PATH = "/api/v1/data"
REALITY_XHTTP_COMPAT_SNIS = [
    "github.com",
    "miu.com",
    "android.com",
    "cloudflare.com",
    "apple.com",
    "www.github.com",
    "www.bing.com",
]
AWG_DEFAULT_ROUTE_EXCLUDES = [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
]
# Все доступные системы/протоколы
DEFAULT_USER_SYSTEMS = ["tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg"]
ALL_SYSTEMS = [*DEFAULT_USER_SYSTEMS, "amneziawg", "wireguard", "ocserv"]
SYSTEM_LABELS = {
    "tls": "VLESS TLS Vision",
    "reality-xhttp": "Reality xHTTP",
    "reality-tcp": "Reality TCP Vision",
    "hysteria": "Hysteria 2",
    "telemt": "Telemt MTProto TLS",
    "mtg": "MTProto (mtg, FakeTLS)",
    "amneziawg": "AmneziaWG",
    "wireguard": "WireGuard",
    "ocserv": "OpenConnect (ocserv)",
}
DEFAULT_SITE_TITLE = "Сервисная страница"
PORTAL_FEATURE_DEFAULTS = {
    "monitoring": True,
    "background_refresh": True,
}
PORTAL_PERFORMANCE_PROFILES = {
    "standard": dict(PORTAL_FEATURE_DEFAULTS),
    "light": {"monitoring": False, "background_refresh": False},
}
PORTAL_PERFORMANCE_PROFILE_NAMES = {*PORTAL_PERFORMANCE_PROFILES, "custom"}

# SNI по умолчанию.
# ВАЖНО: каждый домен в nginx-мапе (tls/reality-xhttp/reality-tcp/telemt/mtg) обязан быть
# УНИКАЛЬНЫМ — иначе SNI-коллизия и трафик уйдёт не в тот бэкенд (Reality-TCP падал из-за этого).
# Для Reality default — это ещё и dest: должен реально достигаться сервером.
DEFAULT_SNIS = {
    "tls": "www.microsoft.com",
    "reality-xhttp": "github.com",
    "reality-tcp": "apple.com",
    "hysteria": "www.apple.com",
    "telemt": "yandex.com",
    "mtg": "ya.ru",
}
DEFAULT_ROUTE_DESTS = {
    "tls": "xray:443",
    "reality-xhttp": "xray:2053",
    "reality-tcp": "xray:2054",
    "hysteria": "hysteria:443",
    "telemt": "telemt:3129",
    "mtg": "mtg:3128",
}
SNI_ROUTE_SYSTEMS = ["tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg"]
USER_SNI_OVERRIDE_SYSTEMS = ["tls", "reality-xhttp", "reality-tcp", "hysteria"]
MTPROTO_SYSTEMS = ("telemt", "mtg")
CAMOUFLAGE_ORIGINS = ("external", "local-site")

# Профили устройств: SNI под экосистему (анти-DPI камуфляж под естественный трафик).
# Каждый домен уникален на свой бэкенд (см. выше). hysteria - UDP, не в nginx-мапе, домены может разделять.
DEVICE_PROFILES = {
    # ВАЖНО: Reality (reality-xhttp/reality-tcp) НЕ device-специфичен - serverName должен
    # быть заранее разрешён в sni_routes и реально доступен как dest/маскировочный сайт.
    # Device-профиль его не меняет: базовые значения xhttp→github.com, tcp→apple.com.
    # Device-камуфляж работает на TLS и Hysteria. Reality допускает только явно
    # настроенные serverNames из sni_routes. Telemt, mtg и ocserv используют
    # service-level SNI и не имеют надёжного per-user SNI в текущей схеме.
    "ios": {
        "tls": "www.apple.com",
        "reality-xhttp": "github.com",
        "reality-tcp": "apple.com",
        "hysteria": "gateway.icloud.com",
    },
    "android": {
        "tls": "www.android.com",
        "reality-xhttp": "github.com",
        "reality-tcp": "apple.com",
        "hysteria": "www.gstatic.com",
    },
    "windows": {
        "tls": "www.microsoft.com",
        "reality-xhttp": "github.com",
        "reality-tcp": "apple.com",
        "hysteria": "www.apple.com",
    },
}
# Reality-системы: serverName выбирается из sni_routes, но не из device-профилей.
REALITY_SYSTEMS = ["reality-xhttp", "reality-tcp"]
DEVICE_PROFILE_SYSTEMS = ["tls", "hysteria"]
ALL_DEVICES = list(DEVICE_PROFILES.keys())
# Системы, чьи SNI реально маршрутизируются nginx (должны быть взаимно уникальны).
NGINX_ROUTED_SYSTEMS = ["tls", "reality-xhttp", "reality-tcp", "telemt", "mtg"]

# Домены для SAN в самоподписанных сертификатах (RU-устойчивые экосистемы).
# Каждый протокол → свой уникальный SNI (см. DEVICE_PROFILES). hysteria — свои домены.
CERT_SAN_DOMAINS = [
    "www.microsoft.com", "microsoft.com", "www.bing.com",
    "www.apple.com", "apple.com", "www.icloud.com", "icloud.com", "gateway.icloud.com",
    "www.android.com", "android.com", "developers.google.com", "www.gstatic.com",
    "yandex.com", "www.yandex.com", "ya.ru",
]


# ── Утилиты ──────────────────────────────────────────────────────────────


def load_state() -> dict:
    return STATE_STORE.load()


def save_state(state: dict) -> None:
    STATE_STORE.save(state)
    sync_portal_runtime_state(state)


def github_updates_config(state: dict, *, mutate: bool = False) -> dict:
    """Нормализует публичные настройки GitHub без чтения credential."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from portal.github_updates import GitHubUpdateError, normalize_github_settings

    try:
        return normalize_github_settings(state, mutate=mutate)
    except GitHubUpdateError as exc:
        raise SystemExit(str(exc)) from exc


def sync_portal_runtime_state(state: dict) -> None:
    """Обновляет видимую порталу runtime-копию, не раскрывая каталог проекта."""
    runtime_state = PORTAL_RUNTIME_STATE
    if STATE_STORE.path.resolve() != USERS_FILE.resolve():
        runtime_state = STATE_STORE.path.parent / "portal-runtime" / "users.json"
    portal = state.get("portal", {})
    if not isinstance(portal, dict) or not portal.get("enabled"):
        runtime_state.unlink(missing_ok=True)
        return
    runtime_state.parent.mkdir(parents=True, exist_ok=True)
    # Файл читает только непривилегированный portal через группу kvn-portal.
    atomic_write_json(runtime_state, state, mode=0o640)


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def generated_fingerprint() -> dict[str, str]:
    """Хэш сгенерированных файлов, по которому решаем, нужен ли restart."""
    targets = [
        ROOT / ".env",
        NGINX_CONFIG,
        PORTAL_GATEWAY_CONFIG,
        XRAY_CONFIG,
        HY2_CONFIG,
        TELEMT_CONFIG,
        ROOT / "mtg" / "config.toml",
        AMNEZIAWG_CONFIG,
        WIREGUARD_CONFIG,
        OCSERV_CONFIG,
        OCSERV_USERS,
        OCSERV_ENV,
        DECOY_SITE_DIR,
        SUB_WEB_DIR,
        CLIENTS_DIR,
        CLIENT_LINKS_FILE,
    ]
    result: dict[str, str] = {}

    def add_file(path: Path) -> None:
        if path.name.endswith(".tmp") or "__pycache__" in path.parts:
            return
        try:
            rel = path.relative_to(ROOT).as_posix()
        except ValueError:
            rel = str(path)
        result[rel] = file_sha256(path)

    for target in targets:
        if target.is_file():
            add_file(target)
        elif target.is_dir():
            for path in sorted(p for p in target.rglob("*") if p.is_file()):
                add_file(path)
    return result


def enabled_users(state: dict) -> list[dict]:
    return [user for user in state["users"] if user.get("enabled", True)]


def find_user(state: dict, name: str) -> dict | None:
    for user in state["users"]:
        if user["name"].lower() == name.lower():
            return user
    return None


def find_user_or_exit(state: dict, name: str) -> dict:
    user = find_user(state, name)
    if not user:
        raise SystemExit(f"Пользователь не найден: {name}")
    return user


def validate_name(name: str) -> None:
    if not NAME_RE.match(name):
        raise SystemExit(
            "Имя пользователя должно быть 2-32 символа: латиница, цифры, _, ., -"
        )


def validate_host(value: str, field: str = "host") -> str:
    """Strictly validate user-controlled hostnames before writing configs."""
    value = (value or "").strip()
    if not value:
        raise SystemExit(f"{field}: пустое значение")
    if value == "YOUR_SERVER_IP":
        return value
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not HOST_RE.fullmatch(value):
        raise SystemExit(f"{field}: недопустимый host: {value!r}")
    labels = value.split(".")
    for label in labels:
        if not label or len(label) > 63:
            raise SystemExit(f"{field}: недопустимая DNS-метка в {value!r}")
        if label.startswith("-") or label.endswith("-"):
            raise SystemExit(f"{field}: DNS-метка не может начинаться/заканчиваться '-': {value!r}")
    return value.lower()


def validate_sni_domain(value: str) -> str:
    return validate_host(value, "SNI")


def validate_portal_host(value: str) -> str:
    """Проверяет публичный адрес портала: DNS-имя или глобальный IPv4."""
    value = (value or "").strip().rstrip(".")
    if not value:
        raise SystemExit("Адрес портала: пустое значение")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return validate_sni_domain(value)
    if address.version != 4:
        raise SystemExit("IP-режим портала пока поддерживает только публичный IPv4")
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    ):
        raise SystemExit("IP-режим портала требует публичный глобальный IPv4")
    return str(address)


def portal_host_kind(value: str) -> str:
    """Возвращает `ipv4` или `domain` только для уже проверенного endpoint."""
    normalized = validate_portal_host(value)
    try:
        ipaddress.IPv4Address(normalized)
    except ipaddress.AddressValueError:
        return "domain"
    return "ipv4"


def probe_sni_target(value: str, timeout: float = 3.0) -> dict[str, object]:
    """Безопасно проверяет DNS и TLS для SNI, не раскрывая адреса и сертификаты.

    Проверка диагностическая: она не меняет маршрут и не обещает доступность у
    другого оператора/в другом регионе. DNS вынесен в daemon-thread, чтобы CLI
    не зависал на проблемном resolver дольше заданного timeout.
    """
    domain = validate_sni_domain(value)
    timeout = max(0.5, min(float(timeout), 10.0))
    resolved: list[tuple] = []
    error: list[BaseException] = []
    started = time.monotonic()

    def resolve() -> None:
        try:
            resolved.extend(socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM))
        except OSError as exc:
            error.append(exc)

    worker = threading.Thread(target=resolve, name="kvn-sni-resolve", daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        return {"sni": domain, "dns": "timeout", "tls": "not_checked", "reason": "dns_timeout"}
    if error or not resolved:
        return {"sni": domain, "dns": "unavailable", "tls": "not_checked", "reason": "dns_unavailable"}

    addresses = {(family, sockaddr) for family, _socktype, _proto, _canonname, sockaddr in resolved}
    deadline = started + timeout
    tls_error = "connect_unavailable"
    context = ssl.create_default_context()
    for family, sockaddr in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock: socket.socket | None = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(remaining)
            sock.connect(sockaddr)
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                tls_sock.do_handshake()
            return {"sni": domain, "dns": "ok", "addresses": len(addresses), "tls": "ok", "reason": "ok"}
        except socket.timeout:
            tls_error = "tls_timeout"
        except ssl.SSLError:
            tls_error = "tls_invalid"
        except OSError:
            tls_error = "connect_unavailable"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return {"sni": domain, "dns": "ok", "addresses": len(addresses), "tls": "unavailable", "reason": tls_error}


def validate_backend_dest(value: str) -> str:
    if not value or ":" not in value:
        raise SystemExit(f"Невалидный dest (ожидается host:port): {value}")
    host, port_s = value.rsplit(":", 1)
    host = validate_host(host, "dest host")
    try:
        port = int(port_s)
    except ValueError:
        raise SystemExit(f"Невалидный port в dest: {value}")
    if not (1 <= port <= 65535):
        raise SystemExit(f"Port вне диапазона 1-65535 в dest: {value}")
    return f"{host}:{port}"


def validate_subscription_token(value: str) -> str:
    value = (value or "").strip().lower()
    if not SUB_TOKEN_RE.fullmatch(value):
        raise ValueError("subscription token must be 32 lowercase hex chars")
    return value


def validate_iface(value: str) -> str:
    value = (value or "").strip()
    if not IFACE_RE.fullmatch(value):
        raise SystemExit(f"Невалидное имя интерфейса: {value!r}")
    return value


def validate_uuid(value: str) -> str:
    try:
        return str(uuid.UUID(value))
    except ValueError:
        raise SystemExit(f"Невалидный UUID: {value}")


def validate_telemt_secret(value: str) -> str:
    if not re.fullmatch(r"[0-9a-fA-F]{32}", value):
        raise SystemExit(f"Telemt secret должен быть 32-символьным hex: {value}")
    return value.lower()


def validate_hysteria_password(value: str) -> str:
    value = value or ""
    if not HYSTERIA_PASSWORD_RE.fullmatch(value):
        raise SystemExit(
            "Hysteria password должен быть 8-128 символов без пробелов/двоеточий; "
            "разрешены латиница, цифры и . _ @ % + = -"
        )
    return value


def validate_ocserv_password(value: str) -> str:
    value = value or ""
    if not OCSERV_PASSWORD_RE.fullmatch(value):
        raise SystemExit(
            "ocserv password должен быть 8-128 символов без пробелов/двоеточий; "
            "разрешены латиница, цифры и . _ @ % + = -"
        )
    return value


def validate_description(value: str) -> str:
    value = value or ""
    if len(value) > MAX_DESCRIPTION_LEN:
        raise SystemExit(f"Описание не должно быть длиннее {MAX_DESCRIPTION_LEN} символов")
    if any(ord(ch) < 32 for ch in value):
        raise SystemExit("Описание не должно содержать управляющие символы")
    return value


def validate_site_title(value: str) -> str:
    value = (value or DEFAULT_SITE_TITLE).strip() or DEFAULT_SITE_TITLE
    if len(value) > MAX_SITE_TITLE_LEN:
        raise SystemExit(f"Надпись сайта не должна быть длиннее {MAX_SITE_TITLE_LEN} символов")
    if any(ord(ch) < 32 for ch in value):
        raise SystemExit("Надпись сайта не должна содержать управляющие символы")
    return value


def validate_portal_path(value: str) -> str:
    raw_value = value or ""
    if any(ord(char) < 32 for char in raw_value):
        raise SystemExit("Путь портала не должен содержать управляющие символы")
    value = raw_value.strip()
    if (
        not value
        or value == "/"
        or len(value) > 120
        or ".." in value
        or "//" in value
        or "?" in value
        or "#" in value
        or not re.fullmatch(r"/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", value)
    ):
        raise SystemExit("Путь портала должен иметь вид /segment[/segment], без '..', query и fragment")
    return value.rstrip("/")


def validate_portal_port(value: int | str, state: dict | None = None) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise SystemExit("Порт портала должен быть целым числом")
    if not (1 <= port <= 65535):
        raise SystemExit("Порт портала вне диапазона 1-65535")
    reserved = {80, 2096, *range(2443, 2449)}
    if state:
        reserved.add(int(state.get("subscription", {}).get("port", DEFAULT_SUB_PORT)))
    if port != 443 and port in reserved:
        raise SystemExit(f"Порт {port} уже используется VPN-стеком")
    return port


def validate_portal_login(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,64}", value):
        raise SystemExit("Логин портала: 3-64 символа, латиница, цифры и ._@-")
    return value


def validate_portal_password(value: str) -> str:
    if len(value) < 12 or len(value) > 256 or any(ord(char) < 32 for char in value):
        raise SystemExit("Пароль портала должен содержать 12-256 печатных символов")
    return value


def hash_portal_password(password: str) -> str:
    password = validate_portal_password(password)
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**17, r=8, p=1, dklen=32,
        maxmem=256 * 1024 * 1024,
    )
    return "scrypt$131072$8$1$" + base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=") + "$" + base64.urlsafe_b64encode(derived).decode("ascii").rstrip("=")


def portal_performance_config(portal: dict) -> dict:
    """Нормализует профиль нагрузки и независимые feature flags портала."""
    if not isinstance(portal, dict):
        raise SystemExit("portal должен быть объектом")
    raw_profile = portal.get("performance_profile", "standard")
    if not isinstance(raw_profile, str) or raw_profile not in PORTAL_PERFORMANCE_PROFILE_NAMES:
        raise SystemExit("portal.performance_profile должен быть standard, light или custom")
    raw_features = portal.get("features", {})
    if not isinstance(raw_features, dict):
        raise SystemExit("portal.features должен быть объектом")
    unknown = sorted(set(raw_features) - set(PORTAL_FEATURE_DEFAULTS))
    if unknown:
        raise SystemExit("Неизвестные portal.features: " + ", ".join(unknown))
    if raw_profile == "custom" and set(raw_features) != set(PORTAL_FEATURE_DEFAULTS):
        raise SystemExit("Профиль custom требует явных monitoring и background_refresh")

    base_profile = raw_profile if raw_profile in PORTAL_PERFORMANCE_PROFILES else "standard"
    features = dict(PORTAL_PERFORMANCE_PROFILES[base_profile])
    for name, value in raw_features.items():
        if not isinstance(value, bool):
            raise SystemExit(f"portal.features.{name} должен быть true или false")
        features[name] = value

    if features == PORTAL_PERFORMANCE_PROFILES["standard"]:
        effective_profile = "standard"
    elif features == PORTAL_PERFORMANCE_PROFILES["light"]:
        effective_profile = "light"
    else:
        effective_profile = "custom"
    portal["performance_profile"] = effective_profile
    portal["features"] = features
    return {
        "profile": effective_profile,
        "monitoring": features["monitoring"],
        "background_refresh": features["background_refresh"],
    }


def portal_config(state: dict) -> dict:
    cfg = state.setdefault("portal", {})
    if not isinstance(cfg, dict):
        raise SystemExit("portal должен быть объектом")
    cfg["enabled"] = bool(cfg.get("enabled", False))
    if not cfg["enabled"]:
        return cfg
    cfg["name"] = validate_site_title(cfg.get("name", "KVN VPN"))
    cfg["domain"] = validate_portal_host(cfg.get("domain", ""))
    cfg["port"] = validate_portal_port(cfg.get("port", 8443), state)
    if portal_host_kind(cfg["domain"]) == "ipv4" and cfg["port"] == 443:
        raise SystemExit("Портал по IP должен использовать отдельный HTTPS-порт, например 8443")
    allow_self_signed_ip = cfg.get("allow_self_signed_ip", False)
    if not isinstance(allow_self_signed_ip, bool):
        raise SystemExit("portal.allow_self_signed_ip должен быть true или false")
    cfg["allow_self_signed_ip"] = allow_self_signed_ip
    cfg["path"] = validate_portal_path(cfg.get("path", "/admin"))
    cfg["login"] = validate_portal_login(cfg.get("login", ""))
    portal_performance_config(cfg)
    password_hash = cfg.get("password_hash", "")
    if not isinstance(password_hash, str) or not password_hash.startswith("scrypt$"):
        raise SystemExit("portal.password_hash отсутствует или имеет неизвестный формат")
    for field in ["proxy_secret", "hysteria_secret"]:
        value = cfg.get(field, "")
        if not isinstance(value, str) or len(value) < 32:
            raise SystemExit(f"portal.{field} отсутствует")
    return cfg


def normalize_systems(systems: list[str], user_name: str = "<unknown>") -> tuple[list[str], bool]:
    if not isinstance(systems, list):
        raise SystemExit(f"Пользователь {user_name}: systems должен быть списком")
    normalized: list[str] = []
    changed = False
    for system in systems:
        if system not in ALL_SYSTEMS:
            raise SystemExit(f"Пользователь {user_name}: неизвестная система: {system}")
        if system in normalized:
            changed = True
            continue
        normalized.append(system)
    if not normalized:
        raise SystemExit(f"Пользователь {user_name}: нужна хотя бы одна система")
    return normalized, changed or normalized != systems


def unique_name(state: dict, name: str, exclude: str | None = None) -> None:
    names = {user["name"].lower() for user in state["users"]}
    if exclude:
        names.discard(exclude.lower())
    if name.lower() in names:
        raise SystemExit(f"Пользователь уже есть: {name}")


_PW_ALPHABET = string.ascii_letters + string.digits


def random_password(length: int = 18) -> str:
    # Равномерная выборка из алфавита без смещения (в отличие от token_urlsafe с replace).
    return "".join(secrets.choice(_PW_ALPHABET) for _ in range(length))


def random_hex32() -> str:
    return secrets.token_hex(16)


def mask_secret(value: str, visible: int = 4) -> str:
    if not value:
        return "-"
    if len(value) <= visible * 2:
        return "*" * len(value)
    return f"{value[:visible]}...{value[-visible:]}"


def random_x25519_private() -> str:
    """Генерирует приватный ключ X25519 (32 байта с clamping, base64url)."""
    scalar = bytearray(secrets.token_bytes(32))
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return b64url_encode_key(bytes(scalar))


def random_short_id() -> str:
    """Reality shortId — 8 байт в hex (16 символов)."""
    return secrets.token_hex(8)


def random_wg_private_key() -> str:
    """Генерирует приватный ключ WireGuard/AmneziaWG в стандартном base64."""
    scalar = bytearray(secrets.token_bytes(32))
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return base64.b64encode(bytes(scalar)).decode("ascii")


def wg_public_key(private_key: str) -> str:
    """Вычисляет публичный ключ WireGuard/AmneziaWG из приватного ключа."""
    try:
        scalar_bytes = bytearray(base64.b64decode(private_key, validate=True))
    except (ValueError, TypeError):
        return ""
    if len(scalar_bytes) != 32:
        return ""
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public = x25519_scalar_mult(scalar, 9)
    return base64.b64encode(public.to_bytes(32, "little")).decode("ascii")


def parse_systems(value: str) -> list[str]:
    """Парсит список систем из строки 'tls,reality-xhttp,...'"""
    systems = [s.strip() for s in value.split(",") if s.strip()]
    unknown = [s for s in systems if s not in ALL_SYSTEMS]
    if unknown:
        raise SystemExit(f"Неизвестные системы: {', '.join(unknown)}. Доступные: {', '.join(ALL_SYSTEMS)}")
    normalized, _ = normalize_systems(systems)
    return normalized


def user_systems(user: dict) -> list[str]:
    """Возвращает список доступных систем пользователя."""
    systems = user.get("systems")
    if systems is not None:
        return systems
    return list(DEFAULT_USER_SYSTEMS)


def apply_device_profile(user: dict, device: str, *, overwrite: bool = False) -> list[str]:
    """Проставляет sni_overrides под экосистему устройства (ios/android/windows).
    Возвращает список применённых систем. Без overwrite уже заданные оверрайды не трогает."""
    device = (device or "").lower()
    profile = DEVICE_PROFILES.get(device)
    user["device"] = device if profile else ""
    if not profile:
        return []
    overrides = user.setdefault("sni_overrides", {})
    applied = []
    for system in DEVICE_PROFILE_SYSTEMS:
        if overwrite or not overrides.get(system):
            if overrides.get(system) != profile[system]:
                overrides[system] = profile[system]
                applied.append(system)
    return applied


def reapply_device_profiles(state: dict) -> bool:
    """Дозаполняет SNI-профиль устройства, не перетирая ручные значения."""
    changed = False
    for user in state.get("users", []):
        device = user.get("device", "")
        if device in DEVICE_PROFILES:
            before = dict(user.get("sni_overrides", {}))
            apply_device_profile(user, device)
            if user.get("sni_overrides", {}) != before:
                changed = True
    return changed


def validate_sni_uniqueness(state: dict) -> None:
    """Проверяет, что один SNI не маршрутизируется в два разных бэкенда (иначе nginx
    отправит трафик не туда — так падал Reality-TCP). Громко предупреждает о коллизиях."""
    routes = get_sni_routes(state)
    fatal_errors: list[str] = []
    domain_to_routes: dict[str, list[tuple[str, str]]] = {}
    for sys_name in NGINX_ROUTED_SYSTEMS:
        route = routes.get(sys_name, {})
        if not isinstance(route, dict):
            continue
        dest = route.get("dest", "")
        domains = set(route.get("aliases", []))
        if route.get("default"):
            domains.add(route["default"])
        for d in domains:
            domain_to_routes.setdefault(d, []).append((sys_name, dest))
    custom_routes = routes.get("custom", [])
    if isinstance(custom_routes, list):
        for custom in custom_routes:
            sni = custom.get("sni", "")
            dest = custom.get("dest", "")
            if sni:
                domain_to_routes.setdefault(sni, []).append((f"custom:{dest}", dest))
    ocserv_cfg = state.get("ocserv", {})
    if ocserv_cfg.get("enabled") and ocserv_config(state).get("sni_enabled"):
        sni = ocserv_sni(state)
        if not sni:
            fatal_errors.append("ocserv включён, но ocserv.sni не задан")
            err("ocserv включён, но ocserv.sni не задан")
        else:
            domain_to_routes.setdefault(sni, []).append(("ocserv", "ocserv:443"))
        for front_sni in ocserv_front_snis(state):
            domain_to_routes.setdefault(front_sni, []).append(("ocserv-front", "ocserv:443"))
    site_snis = site_domains(state)
    ocserv_primary_sni = ocserv_sni(state)
    for site_sni in site_snis:
        if site_sni != ocserv_primary_sni:
            domain_to_routes.setdefault(site_sni, []).append(("site", "127.0.0.1:8443"))
    # Плюс пользовательские оверрайды
    for user in state.get("users", []):
        for sys_name, dom in user.get("sni_overrides", {}).items():
            if sys_name in NGINX_ROUTED_SYSTEMS and dom:
                route = routes.get(sys_name, {})
                dest = route.get("dest", "") if isinstance(route, dict) else ""
                domain_to_routes.setdefault(dom, []).append((f"user:{user['name']}:{sys_name}", dest))
    collisions = {
        domain: routes_for_domain
        for domain, routes_for_domain in domain_to_routes.items()
        if len({dest for _, dest in routes_for_domain}) > 1
    }
    if collisions:
        fatal_errors.append("SNI-КОЛЛИЗИЯ (роутинг): один домен ведёт в разные бэкенды")
        err("SNI-КОЛЛИЗИЯ (роутинг)! Один домен ведёт в разные бэкенды — трафик уйдёт не туда:")
        for d, route_entries in collisions.items():
            pretty = ", ".join(f"{label}->{dest}" for label, dest in sorted(route_entries))
            err(f"  {d} -> {pretty}")
        err("Исправьте sni_routes/DEVICE_PROFILES: домен должен быть уникален на бэкенд.")

    # 2. Внутри одного юзера каждый протокол обязан иметь СВОЙ SNI (требование: разные SNI на протокол).
    check_systems = USER_SNI_OVERRIDE_SYSTEMS + ["telemt", "mtg"]
    for user in state.get("users", []):
        seen: dict[str, str] = {}
        for sys_name in user_systems(user):
            if sys_name not in check_systems:
                continue
            dom = user_sni(user, sys_name, state)
            if dom in seen:
                fatal_errors.append(f"Юзер {user['name']}: SNI {dom} используется в нескольких протоколах")
                err(f"Юзер {user['name']}: SNI {dom} используется и в {seen[dom]}, и в {sys_name} — задайте разные.")
            else:
                seen[dom] = sys_name

    # 3. Reality: пользовательский serverName должен быть заранее разрешён
    #    в sni_routes, иначе nginx/Xray не будут согласованы.
    for sys_name in REALITY_SYSTEMS:
        allowed = route_server_names(state, sys_name) or [system_sni(state, sys_name)]
        for user in state.get("users", []):
            if sys_name not in user_systems(user):
                continue
            dom = user_sni(user, sys_name, state)
            if dom not in allowed:
                fatal_errors.append(f"Юзер {user['name']}: Reality {sys_name} SNI не разрешён")
                err(f"Юзер {user['name']}: Reality {sys_name} SNI={dom} не входит в sni_routes.{sys_name}.")
    if fatal_errors:
        raise SystemExit("Невалидные SNI/Reality настройки. Рендер остановлен.")


def get_sni_routes(state: dict) -> dict:
    """Возвращает секцию sni_routes из state."""
    return state.get("sni_routes", {})


def ensure_sni_route(state: dict, system: str) -> dict:
    if system not in SNI_ROUTE_SYSTEMS:
        raise SystemExit(f"Система {system} не поддерживает service SNI. Доступные: {', '.join(SNI_ROUTE_SYSTEMS)}")
    routes = state.setdefault("sni_routes", {})
    route = routes.setdefault(system, {})
    if not isinstance(route, dict):
        raise SystemExit(f"sni_routes.{system} должен быть объектом")
    route.setdefault("default", DEFAULT_SNIS[system])
    route.setdefault("dest", DEFAULT_ROUTE_DESTS[system])
    aliases = route.setdefault("aliases", [route["default"]])
    if not isinstance(aliases, list):
        raise SystemExit(f"sni_routes.{system}.aliases должен быть списком")
    if route["default"] not in aliases:
        aliases.insert(0, route["default"])
    return route


def parse_sni_csv(value: str) -> list[str]:
    result: list[str] = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        domain = validate_sni_domain(item)
        if domain not in result:
            result.append(domain)
    return result


def letsencrypt_config(state: dict) -> dict:
    cfg = state.setdefault("letsencrypt", {})
    cfg.setdefault("enabled", False)
    domain = cfg.get("domain", "")
    if domain:
        cfg["domain"] = validate_sni_domain(domain)
    domains = cfg.get("domains", [])
    if isinstance(domains, str):
        domains = [domains]
    if domains is None:
        domains = []
    if not isinstance(domains, list):
        raise SystemExit("letsencrypt.domains должен быть списком доменов")
    normalized_domains: list[str] = []
    for item in domains:
        normalized = validate_sni_domain(str(item))
        if normalized not in normalized_domains:
            normalized_domains.append(normalized)
    if normalized_domains:
        cfg["domains"] = normalized_domains
    return cfg


def letsencrypt_domain(state: dict) -> str:
    cfg = letsencrypt_config(state)
    domain = cfg.get("domain", "")
    if domain:
        return domain
    server = state.get("server", "")
    if server and not re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
        return validate_sni_domain(server)
    return ""


def letsencrypt_domains(state: dict) -> list[str]:
    """Домены site-сертификата Let's Encrypt: основной + SAN-алиасы."""
    cfg = letsencrypt_config(state)
    domains: list[str] = []

    def add(domain: str) -> None:
        if domain and domain not in domains:
            domains.append(domain)

    add(cfg.get("domain", ""))
    for domain in cfg.get("domains", []):
        add(domain)
    portal = state.get("portal", {})
    if isinstance(portal, dict) and portal.get("enabled") and portal.get("domain"):
        portal_host = validate_portal_host(portal["domain"])
        if portal_host_kind(portal_host) == "domain":
            add(validate_sni_domain(portal_host))
    if not domains:
        server = state.get("server", "")
        if server and not re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
            add(validate_sni_domain(server))
    return domains


def site_issue_domains(state: dict, requested_domains: list[str]) -> list[str]:
    """SAN-набор для site-сертификата при ручном issue.

    `site-certs/` используется и основным nginx, и portal-gateway на отдельном
    порту, поэтому ручной выпуск не должен случайно отрезать домен портала.
    """
    domains = normalize_letsencrypt_domain_list(requested_domains)
    portal = state.get("portal", {})
    if isinstance(portal, dict) and portal.get("enabled") and portal.get("domain"):
        portal_host = validate_portal_host(str(portal["domain"]))
        portal_domain = validate_sni_domain(portal_host) if portal_host_kind(portal_host) == "domain" else ""
        if portal_domain not in domains and letsencrypt_eligible_domain(portal_domain):
            domains.append(portal_domain)
            warn(f"домен портала добавлен в site-сертификат: {portal_domain}")
    return domains


LE_PRIVATE_TLDS = {
    "local", "localhost", "loc", "lan", "home", "internal", "intranet",
    "test", "example", "invalid",
}


def letsencrypt_eligible_domain(domain: str) -> bool:
    """Проверяет домен на базовую пригодность для публичного Let's Encrypt."""
    try:
        normalized = validate_sni_domain(domain)
    except SystemExit:
        return False
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", normalized):
        return False
    labels = normalized.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if tld in LE_PRIVATE_TLDS:
        return False
    if len(tld) < 2:
        return False
    if not re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{2,59}", tld):
        return False
    return True


def letsencrypt_issuable_domains(domains: list[str]) -> list[str]:
    """Возвращает только домены, которые не должны ломать certbot HTTP-01."""
    result: list[str] = []
    for domain in domains:
        if letsencrypt_eligible_domain(domain) and domain not in result:
            result.append(domain)
    return result


def site_config(state: dict) -> dict:
    cfg = state.setdefault("site", {})
    if not isinstance(cfg, dict):
        raise SystemExit("site должен быть объектом")
    cfg["title"] = validate_site_title(cfg.get("title", DEFAULT_SITE_TITLE))
    return cfg


def site_domains(state: dict) -> list[str]:
    """Домены, которые nginx stream должен отправлять на HTTPS-сайт/подписку."""
    domains: list[str] = []
    # В local-site режиме SNI обязан снаружи вести в MTProto backend. Тот же
    # сертификат используется внутренним listener nginx:8443, но SAN не должен
    # превращать этот SNI в публичный web-route и создавать петлю.
    internal_decoy_snis = {
        system_sni(state, system)
        for system in MTPROTO_SYSTEMS
        if mtproto_camouflage_origin(state, system) == "local-site"
    }

    def add(domain: str) -> None:
        if domain and domain not in internal_decoy_snis and domain not in domains:
            domains.append(domain)

    if letsencrypt_config(state).get("enabled"):
        for domain in letsencrypt_domains(state):
            add(domain)
    else:
        server = state.get("server", "")
        if server and not re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
            add(validate_sni_domain(server))
    public_host = sub_config(state).get("public_host", "")
    if public_host:
        add(public_host)
    portal = state.get("portal", {})
    if isinstance(portal, dict) and portal.get("enabled") and portal.get("domain"):
        portal_host = validate_portal_host(portal["domain"])
        if portal_host_kind(portal_host) == "domain":
            add(validate_sni_domain(portal_host))
    return domains


def tls_client_sni(state: dict, user: dict) -> str:
    """SNI для VLESS TLS.

    The Let's Encrypt domain is reserved for the website on 443/tcp. Keep
    diagnostic Xray-TLS clients on the per-user TLS SNI so nginx still routes
    them to xray:443.
    """
    return user_sni(user, "tls", state)


def validate_state_inputs(state: dict) -> bool:
    """Validate and normalize fields that are rendered into config files."""
    changed = False
    try:
        _, client_export_changed = normalize_client_export_state(state)
    except ClientExportValidationError as exc:
        raise SystemExit(str(exc)) from exc
    changed = changed or client_export_changed
    updates_before = json.dumps(state.get("updates", {}), sort_keys=True)
    github_updates_config(state, mutate=True)
    if json.dumps(state.get("updates", {}), sort_keys=True) != updates_before:
        changed = True
    for system in MTPROTO_SYSTEMS:
        before_mtproto = json.dumps(state.get(system, {}), sort_keys=True)
        mtproto_config(state, system)
        if json.dumps(state.get(system, {}), sort_keys=True) != before_mtproto:
            changed = True
    site_before = json.dumps(state.get("site", {}), sort_keys=True, ensure_ascii=False)
    site_config(state)
    if json.dumps(state.get("site", {}), sort_keys=True, ensure_ascii=False) != site_before:
        changed = True
    le_before = json.dumps(state.get("letsencrypt", {}), sort_keys=True)
    letsencrypt_config(state)
    if json.dumps(state.get("letsencrypt", {}), sort_keys=True) != le_before:
        changed = True
    sub_before = json.dumps(state.get("subscription", {}), sort_keys=True)
    sub_config(state)
    if json.dumps(state.get("subscription", {}), sort_keys=True) != sub_before:
        changed = True
    portal_before = json.dumps(state.get("portal", {}), sort_keys=True)
    portal_config(state)
    if json.dumps(state.get("portal", {}), sort_keys=True) != portal_before:
        changed = True
    ocserv_before = json.dumps(state.get("ocserv", {}), sort_keys=True)
    ocserv_config(state)
    if json.dumps(state.get("ocserv", {}), sort_keys=True) != ocserv_before:
        changed = True
    wireguard_before = json.dumps(state.get("wireguard", {}), sort_keys=True)
    wireguard_config(state)
    if json.dumps(state.get("wireguard", {}), sort_keys=True) != wireguard_before:
        changed = True
    server = state.get("server", "")
    if server:
        normalized_server = validate_host(server, "server")
        if normalized_server != server:
            state["server"] = normalized_server
            changed = True

    routes = get_sni_routes(state)
    site_domain_set = set(site_domains(state))
    for sys_name, route in routes.items():
        if sys_name == "custom":
            if not isinstance(route, list):
                raise SystemExit("sni_routes.custom должен быть списком")
            for custom in route:
                sni = validate_sni_domain(custom.get("sni", ""))
                dest = validate_backend_dest(custom.get("dest", ""))
                if custom.get("sni") != sni:
                    custom["sni"] = sni
                    changed = True
                if custom.get("dest") != dest:
                    custom["dest"] = dest
                    changed = True
            continue
        if not isinstance(route, dict):
            continue
        if route.get("default"):
            sni = validate_sni_domain(route["default"])
            if route["default"] != sni:
                route["default"] = sni
                changed = True
        if route.get("dest"):
            dest = validate_backend_dest(route["dest"])
            if route["dest"] != dest:
                route["dest"] = dest
                changed = True
        aliases = route.get("aliases", [])
        if aliases:
            if not isinstance(aliases, list):
                raise SystemExit(f"sni_routes.{sys_name}.aliases должен быть списком")
            normalized_aliases = [validate_sni_domain(alias) for alias in aliases]
            if sys_name == "tls" and site_domain_set:
                normalized_aliases = [alias for alias in normalized_aliases if alias not in site_domain_set]
            if aliases != normalized_aliases:
                route["aliases"] = normalized_aliases
                changed = True

    seen_names: set[str] = set()
    for user in state.get("users", []):
        validate_name(user.get("name", ""))
        normalized_name = user["name"].lower()
        if normalized_name in seen_names:
            raise SystemExit(f"Дублирующееся имя пользователя: {user['name']}")
        seen_names.add(normalized_name)
        if user.get("uuid"):
            normalized_uuid = validate_uuid(user["uuid"])
            if user["uuid"] != normalized_uuid:
                user["uuid"] = normalized_uuid
                changed = True
        if user.get("hysteria_password"):
            normalized_password = validate_hysteria_password(user["hysteria_password"])
            if user["hysteria_password"] != normalized_password:
                user["hysteria_password"] = normalized_password
                changed = True
        if user.get("telemt_secret"):
            normalized_secret = validate_telemt_secret(user["telemt_secret"])
            if user["telemt_secret"] != normalized_secret:
                user["telemt_secret"] = normalized_secret
                changed = True
        if user.get("ocserv_password"):
            normalized_password = validate_ocserv_password(user["ocserv_password"])
            if user["ocserv_password"] != normalized_password:
                user["ocserv_password"] = normalized_password
                changed = True
        if user.get("sub_token"):
            try:
                normalized_token = validate_subscription_token(user["sub_token"])
            except ValueError as exc:
                raise SystemExit(f"Пользователь {user['name']}: {exc}") from exc
            if user["sub_token"] != normalized_token:
                user["sub_token"] = normalized_token
                changed = True
        description = validate_description(user.get("description", ""))
        if user.get("description", "") != description:
            user["description"] = description
            changed = True
        if user.get("systems") is not None:
            normalized_systems, systems_changed = normalize_systems(user["systems"], user["name"])
            if systems_changed:
                user["systems"] = normalized_systems
                changed = True
        overrides = user.get("sni_overrides", {})
        if not isinstance(overrides, dict):
            raise SystemExit(f"Пользователь {user.get('name', '<unknown>')}: sni_overrides должен быть объектом")
        for sys_name, domain in list(overrides.items()):
            if sys_name not in ALL_SYSTEMS:
                raise SystemExit(f"Пользователь {user['name']}: неизвестная система в sni_overrides: {sys_name}")
            if sys_name not in USER_SNI_OVERRIDE_SYSTEMS:
                # Старые версии портала могли сохранять Telemt/mtg как
                # per-user SNI, но эти сервисы имеют только service-level SNI.
                del overrides[sys_name]
                changed = True
                continue
            if sys_name not in user_systems(user):
                del overrides[sys_name]
                changed = True
                continue
            normalized_domain = validate_sni_domain(domain)
            if domain != normalized_domain:
                overrides[sys_name] = normalized_domain
                changed = True
            if normalized_domain not in route_sni_choices(state, sys_name):
                route = ensure_sni_route(state, sys_name)
                aliases = route.setdefault("aliases", [])
                aliases.append(normalized_domain)
                changed = True
    return changed


def sub_config(state: dict) -> dict:
    """Настройки эндпоинта подписки. Дозаполняет дефолты в state."""
    cfg = state.setdefault("subscription", {})
    cfg.setdefault("enabled", True)
    if not isinstance(cfg.get("enabled"), bool):
        raise SystemExit("subscription.enabled должен быть boolean: true/false")
    try:
        port = int(cfg.get("port", DEFAULT_SUB_PORT))
    except (TypeError, ValueError):
        raise SystemExit("subscription.port должен быть числом")
    if not (1 <= port <= 65535):
        raise SystemExit("subscription.port должен быть в диапазоне 1-65535")
    if port == 443:
        raise SystemExit("subscription.port не может быть 443: порт занят nginx stream SNI-роутером")
    cfg["port"] = port
    public_host = cfg.get("public_host", "")
    if public_host:
        cfg["public_host"] = validate_sni_domain(str(public_host))
        try:
            public_port = int(cfg.get("public_port", 443))
        except (TypeError, ValueError):
            raise SystemExit("subscription.public_port должен быть числом")
        if not (1 <= public_port <= 65535):
            raise SystemExit("subscription.public_port должен быть в диапазоне 1-65535")
        cfg["public_port"] = public_port
    return cfg


def flag_emoji(country_code: str) -> str:
    """ISO-2 код страны → эмодзи-флаг (regional indicator symbols)."""
    cc = (country_code or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + (ord(c) - ord("A"))) for c in cc)


def ensure_server_country(state: dict) -> bool:
    """Определяет страну сервера по IP (ip-api.com) и кэширует в state.
    Best-effort: при оффлайне/ошибке ничего не меняет. True, если кэш обновлён."""
    server = state.get("server", "")
    if not server or not re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
        return False
    geo = state.setdefault("server_geo", {})
    if geo.get("ip") == server and geo.get("country_code"):
        return False  # уже закэшировано для этого IP
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{server}?fields=countryCode,country"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return False
    cc = data.get("countryCode", "")
    if not cc:
        return False
    geo["ip"] = server
    geo["country_code"] = cc
    geo["country"] = data.get("country", "")
    return True


def system_sni(state: dict, system: str) -> str:
    """Возвращает SNI по умолчанию для системы из sni_routes."""
    routes = get_sni_routes(state)
    if system in routes:
        return routes[system].get("default", DEFAULT_SNIS.get(system, ""))
    return DEFAULT_SNIS.get(system, "")


def route_sni_choices(state: dict, system: str) -> list[str]:
    """Возвращает разрешённые SNI сервиса: default + aliases без дублей."""
    route = get_sni_routes(state).get(system, {})
    values: list[str] = []

    def add(domain: str) -> None:
        if not domain:
            return
        normalized = validate_sni_domain(domain)
        if normalized not in values:
            values.append(normalized)

    if isinstance(route, dict):
        add(route.get("default", ""))
        for alias in route.get("aliases", []):
            add(alias)
    else:
        add(DEFAULT_SNIS.get(system, ""))
    return values


def user_selectable_sni_choices(state: dict) -> dict[str, list[str]]:
    """SNI-варианты, которые можно выбирать на уровне пользователя."""
    return {
        system: route_sni_choices(state, system)
        for system in USER_SNI_OVERRIDE_SYSTEMS
    }


def user_sni(user: dict, system: str, state: dict) -> str:
    """Возвращает SNI для конкретной системы пользователя (оверрайд или дефолт)."""
    overrides = user.get("sni_overrides", {})
    if system in USER_SNI_OVERRIDE_SYSTEMS and system in overrides:
        return overrides[system]
    return system_sni(state, system)


def route_server_names(state: dict, system: str) -> list[str]:
    route = get_sni_routes(state).get(system, {})
    names: list[str] = []

    def add(domain: str) -> None:
        if domain and domain not in names:
            names.append(domain)

    if isinstance(route, dict):
        add(route.get("default", ""))
        for alias in route.get("aliases", []):
            add(alias)
    add(system_sni(state, system))
    return names


def xray_config_state(state: dict) -> dict:
    """Настройки Xray из users.json."""
    cfg = state.setdefault("xray", {})
    mode = cfg.get("xhttp_mode", XHTTP_DEFAULT_MODE)
    if mode not in {"packet-up", "stream-up", "stream-one"}:
        mode = XHTTP_DEFAULT_MODE
    cfg["xhttp_mode"] = mode
    names = cfg.get("reality_xhttp_server_names")
    if not isinstance(names, list) or not names:
        cfg["reality_xhttp_server_names"] = list(REALITY_XHTTP_COMPAT_SNIS)
    for name in route_server_names(state, "reality-xhttp"):
        if name not in cfg["reality_xhttp_server_names"]:
            cfg["reality_xhttp_server_names"].append(name)
    return cfg


def xhttp_mode(state: dict) -> str:
    """Единый режим XHTTP для сервера и клиентских ссылок."""
    return xray_config_state(state).get("xhttp_mode", XHTTP_DEFAULT_MODE)


def reality_xhttp_server_names(state: dict) -> list[str]:
    """Широкий список serverNames для Reality xHTTP, отдельно от nginx map."""
    names = xray_config_state(state).get("reality_xhttp_server_names", REALITY_XHTTP_COMPAT_SNIS)
    result: list[str] = []
    for name in names:
        if isinstance(name, str) and name and name not in result:
            result.append(name)
    return result or list(REALITY_XHTTP_COMPAT_SNIS)


def all_sni_aliases(state: dict) -> dict[str, str]:
    """Собирает все SNI-алиасы → dest для генерации nginx map.
    Возвращает {sni_domain: "service:port"}"""
    routes = get_sni_routes(state)
    mapping: dict[str, str] = {}

    def put(sni: str, dest: str) -> None:
        if not sni or not dest:
            return
        sni = validate_sni_domain(sni)
        dest = validate_backend_dest(dest)
        if sni in mapping and mapping[sni] != dest:
            warn(f"SNI-коллизия: {sni} → {mapping[sni]} (игнорирую {dest})")
            return
        mapping[sni] = dest

    for sys_name, route in routes.items():
        # hysteria — UDP напрямую (не через nginx); custom — обрабатывается ниже.
        if sys_name in ("custom", "hysteria"):
            continue
        if not isinstance(route, dict):
            continue
        dest = route.get("dest", "")
        put(route.get("default", ""), dest)
        for alias in route.get("aliases", []):
            put(alias, dest)

    # Пользовательские TCP SNI тоже должны попадать в nginx map. Hysteria идёт
    # по UDP напрямую, Telemt/mtg имеют только service-level SNI.
    for user in state.get("users", []):
        if not user.get("enabled", True):
            continue
        systems = set(user_systems(user))
        overrides = user.get("sni_overrides", {})
        if not isinstance(overrides, dict):
            continue
        for sys_name, sni in overrides.items():
            if (
                sys_name not in USER_SNI_OVERRIDE_SYSTEMS
                or sys_name not in NGINX_ROUTED_SYSTEMS
                or sys_name not in systems
            ):
                continue
            route = routes.get(sys_name, {})
            if isinstance(route, dict):
                put(sni, route.get("dest", DEFAULT_ROUTE_DESTS.get(sys_name, "")))

    # Кастомные маршруты
    for custom in routes.get("custom", []):
        put(custom.get("sni", ""), custom.get("dest", ""))

    oc_sni = ""
    oc_cfg = ocserv_config(state)
    if oc_cfg.get("enabled") and oc_cfg.get("sni_enabled"):
        oc_sni = ocserv_sni(state)
        if oc_sni:
            put(oc_sni, "ocserv:443")
        for front_sni in ocserv_front_snis(state):
            put(front_sni, "ocserv:443")

    for site_sni in site_domains(state):
        if site_sni and site_sni != oc_sni:
            put(site_sni, "127.0.0.1:8443")

    return mapping


def str_to_bool(value: str) -> bool:
    """Парсинг строкового булева значения для argparse."""
    if value.lower() in ("true", "1", "yes", "on"):
        return True
    if value.lower() in ("false", "0", "no", "off"):
        return False
    raise argparse.ArgumentTypeError(f"Ожидается true/false, получено: {value}")


# ── Криптография ─────────────────────────────────────────────────────────


def run_capture(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def run_command_text(command: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def utc_now_iso() -> str:
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_public_key(output: str) -> str:
    for line in output.splitlines():
        if "Public key:" in line:
            return line.split("Public key:", 1)[1].strip()
    return ""


def b64url_decode_key(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def b64url_encode_key(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def x25519_public_key(private_key: str) -> str:
    try:
        scalar_bytes = bytearray(b64url_decode_key(private_key))
    except (ValueError, TypeError):
        return ""
    if len(scalar_bytes) != 32:
        return ""

    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 127
    scalar_bytes[31] |= 64
    scalar = int.from_bytes(scalar_bytes, "little")
    public = x25519_scalar_mult(scalar, 9)
    return b64url_encode_key(public.to_bytes(32, "little"))


def x25519_scalar_mult(scalar: int, point: int) -> int:
    x1 = point
    x2 = 1
    z2 = 0
    x3 = point
    z3 = 1
    swap = 0

    for bit_index in range(254, -1, -1):
        bit = (scalar >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit

        a = (x2 + z2) % X25519_P
        aa = (a * a) % X25519_P
        b = (x2 - z2) % X25519_P
        bb = (b * b) % X25519_P
        e = (aa - bb) % X25519_P
        c = (x3 + z3) % X25519_P
        d = (x3 - z3) % X25519_P
        da = (d * a) % X25519_P
        cb = (c * b) % X25519_P
        x3 = ((da + cb) ** 2) % X25519_P
        z3 = (x1 * ((da - cb) ** 2)) % X25519_P
        x2 = (aa * bb) % X25519_P
        z2 = (e * (aa + 121665 * e)) % X25519_P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, X25519_P - 2, X25519_P)) % X25519_P


def derive_reality_public_key(private_key: str) -> str:
    if not private_key:
        return ""

    public_key = x25519_public_key(private_key)
    if public_key:
        return public_key

    if shutil.which("xray"):
        public_key = parse_public_key(run_capture(["xray", "x25519", "-i", private_key]))
        if public_key:
            return public_key

    if shutil.which("docker"):
        public_key = parse_public_key(
            run_capture(["docker", "run", "--rm", XRAY_IMAGE, "x25519", "-i", private_key])
        )
        if public_key:
            return public_key

    return ""


def read_reality_private_key() -> str:
    try:
        with XRAY_CONFIG.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ""
    for inbound in config.get("inbounds", []):
        rs = inbound.get("streamSettings", {}).get("realitySettings", {})
        if "privateKey" in rs:
            return rs["privateKey"]
    return ""


def ensure_reality_public_key(state: dict, key_name: str = "reality") -> tuple[str, bool]:
    reality = state.setdefault(key_name, {})
    changed = False

    # 1. Приватный ключ: из state, из xray-конфига или генерируем новый.
    private_key = reality.get("privateKey", "")
    if not private_key:
        candidate = read_reality_private_key()
        if candidate and not candidate.startswith("<"):
            private_key = candidate
    if not private_key:
        private_key = random_x25519_private()
        changed = True
    if reality.get("privateKey") != private_key:
        reality["privateKey"] = private_key
        changed = True

    # 2. shortId: должен быть хотя бы один.
    if not reality.get("shortIds"):
        short_id = reality.get("short_id") or random_short_id()
        reality["shortIds"] = [short_id]
        reality["short_id"] = short_id
        changed = True

    # 3. Публичный ключ ВСЕГДА пересчитываем из приватного — гарантируем соответствие.
    expected_public = derive_reality_public_key(private_key)
    if expected_public:
        if reality.get("public_key") != expected_public:
            reality["public_key"] = expected_public
            changed = True
        return expected_public, changed
    return "<ВСТАВЬТЕ_PUBLIC_KEY_ЗДЕСЬ>", changed


def ensure_mtg_secret(state: dict) -> bool:
    """Генерит 16-байтный секрет mtg (32 hex), если пуст. Домен берётся из sni_routes.mtg."""
    cfg = state.setdefault("mtg", {})
    if not cfg.get("secret16"):
        cfg["secret16"] = secrets.token_hex(16)
        return True
    return False


def mtproto_config(state: dict, system: str) -> dict:
    """Возвращает настройки MTProto, сохраняя старый state совместимым.

    Отсутствующий ``camouflage_origin`` означает внешний сайт — это прежнее
    поведение Telemt/mtg и безопасная миграция без неожиданной смены маршрута.
    """
    if system not in MTPROTO_SYSTEMS:
        raise SystemExit(f"Неизвестный MTProto-сервис: {system}")
    cfg = state.setdefault(system, {})
    if not isinstance(cfg, dict):
        raise SystemExit(f"{system} должен быть объектом")
    origin = cfg.get("camouflage_origin", "external")
    if origin not in CAMOUFLAGE_ORIGINS:
        raise SystemExit(
            f"{system}.camouflage_origin: допустимы {', '.join(CAMOUFLAGE_ORIGINS)}"
        )
    cfg["camouflage_origin"] = origin
    return cfg


def mtproto_camouflage_origin(state: dict, system: str) -> str:
    return str(mtproto_config(state, system)["camouflage_origin"])


def mtg_compose_alias(state: dict) -> str:
    """Docker DNS alias для внутреннего decoy; внешний режим не перехватываем."""
    if mtproto_camouflage_origin(state, "mtg") == "local-site":
        return mtg_domain(state)
    return "mtg-decoy.invalid"


def awg_config(state: dict) -> dict:
    """Настройки AmneziaWG. Дозаполняет дефолты в state."""
    cfg = state.setdefault("amneziawg", {})
    cfg.setdefault("enabled", True)
    try:
        cfg["port"] = int(cfg.get("port", 51820))
    except (TypeError, ValueError):
        raise SystemExit("amneziawg.port должен быть числом")
    if not (1 <= cfg["port"] <= 65535):
        raise SystemExit("amneziawg.port должен быть в диапазоне 1-65535")
    cfg["interface"] = validate_iface(cfg.get("interface", "awg0"))
    try:
        cfg["network"] = str(ipaddress.ip_network(cfg.get("network", "10.66.66.0/24"), strict=False))
    except ValueError:
        raise SystemExit(f"Невалидная сеть AmneziaWG: {cfg.get('network')}")
    try:
        cfg["server_address"] = str(ipaddress.ip_interface(cfg.get("server_address", "10.66.66.1/24")))
    except ValueError:
        raise SystemExit(f"Невалидный адрес сервера AmneziaWG: {cfg.get('server_address')}")
    cfg.setdefault("dns", ["1.1.1.1", "8.8.8.8"])
    try:
        cfg["mtu"] = int(cfg.get("mtu", 1280))
    except (TypeError, ValueError):
        raise SystemExit("amneziawg.mtu должен быть числом")
    if not (576 <= cfg["mtu"] <= 1500):
        raise SystemExit("amneziawg.mtu должен быть в диапазоне 576-1500")
    if cfg.get("route_mode") in (None, "", "compact"):
        cfg["route_mode"] = "amnezia"
    if cfg.get("route_mode") == "strict":
        cfg.setdefault("route_excludes", list(AWG_DEFAULT_ROUTE_EXCLUDES))
    else:
        cfg.pop("route_excludes", None)
        cfg.pop("compact_route_excludes", None)

    obfs = cfg.setdefault("obfuscation", {})
    obfs.setdefault("Jc", 5)
    obfs.setdefault("Jmin", 64)
    obfs.setdefault("Jmax", 1024)
    obfs.setdefault("S1", 32)
    obfs.setdefault("S2", 48)
    used_headers = set()
    for key in ("H1", "H2", "H3", "H4"):
        value = obfs.get(key)
        if isinstance(value, int) and value not in used_headers:
            used_headers.add(value)
            continue
        while True:
            candidate = secrets.randbelow(3_000_000_000) + 1_000_000_000
            if candidate not in used_headers:
                obfs[key] = candidate
                used_headers.add(candidate)
                break
    # DNS-похожий CPS-пакет для AWG 1.5+: клиент и сервер должны иметь одинаковое значение.
    obfs.setdefault("I1", "<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>")
    return cfg


def wireguard_config(state: dict) -> dict:
    """Настройки чистого WireGuard. Работает отдельной host systemd-службой."""
    cfg = state.setdefault("wireguard", {})
    cfg.setdefault("enabled", True)
    try:
        cfg["port"] = int(cfg.get("port", 51821))
    except (TypeError, ValueError):
        raise SystemExit("wireguard.port должен быть числом")
    if not (1 <= cfg["port"] <= 65535):
        raise SystemExit("wireguard.port должен быть в диапазоне 1-65535")

    awg = awg_config(state)
    awg_port = int(awg.get("port", 51820))
    ocserv_udp = int(state.get("ocserv", {}).get("udp_port", 4443) or 4443)
    if cfg["port"] in {443, awg_port, ocserv_udp}:
        raise SystemExit(
            f"wireguard.port={cfg['port']} конфликтует с занятым UDP-портом "
            "(443/hysteria, AmneziaWG или ocserv DTLS)"
        )

    cfg["interface"] = validate_iface(cfg.get("interface", "wg0"))
    if cfg["interface"] == awg.get("interface", "awg0"):
        raise SystemExit("wireguard.interface не должен совпадать с amneziawg.interface")

    try:
        cfg["network"] = str(ipaddress.ip_network(cfg.get("network", "10.88.88.0/24"), strict=False))
    except ValueError:
        raise SystemExit(f"Невалидная сеть WireGuard: {cfg.get('network')}")
    try:
        cfg["server_address"] = str(ipaddress.ip_interface(cfg.get("server_address", "10.88.88.1/24")))
    except ValueError:
        raise SystemExit(f"Невалидный адрес сервера WireGuard: {cfg.get('server_address')}")
    try:
        network = ipaddress.ip_network(cfg["network"], strict=False)
        awg_network = ipaddress.ip_network(awg.get("network", "10.66.66.0/24"), strict=False)
        ocserv_network = ipaddress.ip_network(state.get("ocserv", {}).get("network", "10.77.77.0/24"), strict=False)
    except ValueError as exc:
        raise SystemExit(f"Невалидная сеть WireGuard/AmneziaWG/ocserv: {exc}") from None
    if network.overlaps(awg_network):
        raise SystemExit(f"wireguard.network {network} пересекается с amneziawg.network {awg_network}")
    if network.overlaps(ocserv_network):
        raise SystemExit(f"wireguard.network {network} пересекается с ocserv.network {ocserv_network}")

    cfg.setdefault("dns", ["1.1.1.1", "8.8.8.8"])
    try:
        cfg["mtu"] = int(cfg.get("mtu", 1420))
    except (TypeError, ValueError):
        raise SystemExit("wireguard.mtu должен быть числом")
    if not (576 <= cfg["mtu"] <= 1500):
        raise SystemExit("wireguard.mtu должен быть в диапазоне 576-1500")
    return cfg


def ocserv_config(state: dict) -> dict:
    """Настройки OpenConnect/ocserv.

    По умолчанию ocserv доступен на 443/tcp через nginx default/no-SNI
    route, чтобы основной домен сайта оставался за внутренним HTTPS backend.
    SNI-routing на конкретный домен можно включить явно через
    ocserv.sni_enabled=true.
    """
    cfg = state.setdefault("ocserv", {})
    cfg.setdefault("enabled", False)
    if not isinstance(cfg.get("enabled"), bool):
        raise SystemExit("ocserv.enabled должен быть boolean: true/false")
    cfg.setdefault("sni_enabled", False)
    if not isinstance(cfg.get("sni_enabled"), bool):
        raise SystemExit("ocserv.sni_enabled должен быть boolean: true/false")

    default_sni = letsencrypt_domain(state) or state.get("server", "")
    if cfg.get("sni_enabled") and default_sni and not re.match(r"^\d+\.\d+\.\d+\.\d+$", default_sni):
        cfg.setdefault("sni", default_sni)
    sni = cfg.get("sni", "")
    if sni:
        cfg["sni"] = validate_sni_domain(sni)
    cfg["tcp_port"] = 443
    cfg.setdefault("dtls_enabled", True)
    if not isinstance(cfg.get("dtls_enabled"), bool):
        raise SystemExit("ocserv.dtls_enabled должен быть boolean: true/false")
    try:
        cfg["udp_port"] = int(cfg.get("udp_port", 4443))
    except (TypeError, ValueError):
        raise SystemExit("ocserv.udp_port должен быть числом")
    if not (1 <= cfg["udp_port"] <= 65535):
        raise SystemExit("ocserv.udp_port должен быть в диапазоне 1-65535")
    if cfg["dtls_enabled"] and cfg["udp_port"] == 443:
        raise SystemExit("ocserv.udp_port=443 конфликтует с Hysteria2 443/udp")
    front_snis = cfg.get("front_snis", [])
    if isinstance(front_snis, str):
        front_snis = [front_snis]
    if not isinstance(front_snis, list):
        raise SystemExit("ocserv.front_snis должен быть списком SNI-доменов")
    normalized_front_snis: list[str] = []
    for front_sni in front_snis:
        normalized = validate_sni_domain(str(front_sni))
        if normalized not in normalized_front_snis and normalized != cfg.get("sni", ""):
            normalized_front_snis.append(normalized)
    cfg["front_snis"] = normalized_front_snis

    try:
        cfg["network"] = str(ipaddress.ip_network(cfg.get("network", "10.77.77.0/24"), strict=False))
    except ValueError:
        raise SystemExit(f"Невалидная сеть ocserv: {cfg.get('network')}")
    network = ipaddress.ip_network(cfg["network"], strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise SystemExit("ocserv.network должен быть IPv4 CIDR")
    if network.prefixlen > 29:
        raise SystemExit("ocserv.network должен содержать достаточно адресов для клиентов")

    awg_network = ipaddress.ip_network(awg_config(state).get("network", "10.66.66.0/24"), strict=False)
    if network.overlaps(awg_network):
        raise SystemExit(f"ocserv.network {network} пересекается с amneziawg.network {awg_network}")

    dns = cfg.get("dns", ["1.1.1.1", "8.8.8.8"])
    if isinstance(dns, str):
        dns = [dns]
    if not isinstance(dns, list) or not dns:
        raise SystemExit("ocserv.dns должен быть непустым списком IP")
    normalized_dns = []
    for item in dns:
        try:
            normalized_dns.append(str(ipaddress.ip_address(str(item))))
        except ValueError:
            raise SystemExit(f"Невалидный DNS в ocserv.dns: {item}") from None
    cfg["dns"] = normalized_dns

    for key, default, low, high in (
        ("max_clients", 64, 1, 4096),
        ("max_same_clients", 3, 1, 32),
        ("mtu", 1280, 576, 1500),
    ):
        try:
            value = int(cfg.get(key, default))
        except (TypeError, ValueError):
            raise SystemExit(f"ocserv.{key} должен быть числом")
        if not (low <= value <= high):
            raise SystemExit(f"ocserv.{key} должен быть в диапазоне {low}-{high}")
        cfg[key] = value

    return cfg


def ocserv_sni(state: dict) -> str:
    cfg = ocserv_config(state)
    if not cfg.get("sni_enabled"):
        return ""
    return cfg.get("sni", "")


def ocserv_cert_domain(state: dict) -> str:
    """Домен сертификата ocserv, если он работает через SNI."""
    return ocserv_sni(state)


def ocserv_cert_domains(state: dict) -> list[str]:
    """Домены ocserv-сертификата: основной SNI + совместимые алиасы."""
    domains: list[str] = []

    def add(domain: str) -> None:
        if domain and domain not in domains:
            domains.append(domain)

    add(ocserv_sni(state))
    for domain in ocserv_front_snis(state):
        add(domain)
    return domains


def ocserv_front_snis(state: dict) -> list[str]:
    cfg = ocserv_config(state)
    return list(cfg.get("front_snis", []))


def ocserv_public_tcp_port(state: dict) -> int:
    return int(ocserv_config(state).get("tcp_port", 443))


def ensure_amneziawg_state(state: dict) -> bool:
    """Генерирует серверные ключи AmneziaWG и ключи пользователей, у которых включён amneziawg."""
    before = json.dumps(state.get("amneziawg", {}), sort_keys=True, ensure_ascii=False)
    cfg = awg_config(state)
    changed = json.dumps(cfg, sort_keys=True, ensure_ascii=False) != before
    private_key = cfg.get("private_key", "")
    if not private_key:
        private_key = random_wg_private_key()
        cfg["private_key"] = private_key
        changed = True
    public_key = wg_public_key(private_key)
    if public_key and cfg.get("public_key") != public_key:
        cfg["public_key"] = public_key
        changed = True

    used_addresses = {
        user.get("amneziawg", {}).get("address", "")
        for user in state.get("users", [])
        if isinstance(user.get("amneziawg"), dict)
    }
    for user in state.get("users", []):
        if "amneziawg" not in user_systems(user):
            continue
        if ensure_amneziawg_user(state, user, used_addresses):
            changed = True
    return changed


def next_awg_client_address(state: dict, used_addresses: set[str]) -> str:
    cfg = awg_config(state)
    network = ipaddress.ip_network(cfg.get("network", "10.66.66.0/24"), strict=False)
    server_ip = ipaddress.ip_interface(cfg.get("server_address", "10.66.66.1/24")).ip
    used_ips = set()
    for address in used_addresses:
        if not address:
            continue
        try:
            used_ips.add(ipaddress.ip_interface(address).ip)
        except ValueError:
            continue
    for ip in network.hosts():
        if ip == server_ip or ip in used_ips:
            continue
        address = f"{ip}/32"
        used_addresses.add(address)
        return address
    raise SystemExit(f"В сети AmneziaWG {network} закончились адреса")


def ensure_amneziawg_user(state: dict, user: dict, used_addresses: set[str]) -> bool:
    cfg = user.setdefault("amneziawg", {})
    changed = False
    private_key = cfg.get("private_key", "")
    if not private_key:
        private_key = random_wg_private_key()
        cfg["private_key"] = private_key
        changed = True
    public_key = wg_public_key(private_key)
    if public_key and cfg.get("public_key") != public_key:
        cfg["public_key"] = public_key
        changed = True
    if not cfg.get("preshared_key"):
        cfg["preshared_key"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        changed = True
    if not cfg.get("address"):
        cfg["address"] = next_awg_client_address(state, used_addresses)
        changed = True
    return changed


def ensure_wireguard_state(state: dict) -> bool:
    """Генерирует серверные и пользовательские ключи чистого WireGuard."""
    before = json.dumps(state.get("wireguard", {}), sort_keys=True, ensure_ascii=False)
    cfg = wireguard_config(state)
    changed = json.dumps(cfg, sort_keys=True, ensure_ascii=False) != before
    private_key = cfg.get("private_key", "")
    if not private_key:
        private_key = random_wg_private_key()
        cfg["private_key"] = private_key
        changed = True
    public_key = wg_public_key(private_key)
    if public_key and cfg.get("public_key") != public_key:
        cfg["public_key"] = public_key
        changed = True

    used_addresses = {
        user.get("wireguard", {}).get("address", "")
        for user in state.get("users", [])
        if isinstance(user.get("wireguard"), dict)
    }
    for user in state.get("users", []):
        if "wireguard" not in user_systems(user):
            continue
        if ensure_wireguard_user(state, user, used_addresses):
            changed = True
    return changed


def next_wireguard_client_address(state: dict, used_addresses: set[str]) -> str:
    cfg = wireguard_config(state)
    network = ipaddress.ip_network(cfg.get("network", "10.88.88.0/24"), strict=False)
    server_ip = ipaddress.ip_interface(cfg.get("server_address", "10.88.88.1/24")).ip
    used_ips = set()
    for address in used_addresses:
        if not address:
            continue
        try:
            used_ips.add(ipaddress.ip_interface(address).ip)
        except ValueError:
            continue
    for ip in network.hosts():
        if ip == server_ip or ip in used_ips:
            continue
        address = f"{ip}/32"
        used_addresses.add(address)
        return address
    raise SystemExit(f"В сети WireGuard {network} закончились адреса")


def ensure_wireguard_user(state: dict, user: dict, used_addresses: set[str]) -> bool:
    cfg = user.setdefault("wireguard", {})
    changed = False
    private_key = cfg.get("private_key", "")
    if not private_key:
        private_key = random_wg_private_key()
        cfg["private_key"] = private_key
        changed = True
    public_key = wg_public_key(private_key)
    if public_key and cfg.get("public_key") != public_key:
        cfg["public_key"] = public_key
        changed = True
    if not cfg.get("preshared_key"):
        cfg["preshared_key"] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        changed = True
    if not cfg.get("address"):
        cfg["address"] = next_wireguard_client_address(state, used_addresses)
        changed = True
    return changed


def awg_route_excludes(state: dict) -> list[ipaddress.IPv4Network]:
    """CIDR, которые клиент AmneziaWG не должен отправлять через туннель."""
    cfg = awg_config(state)
    values = list(cfg.get("route_excludes", AWG_DEFAULT_ROUTE_EXCLUDES))
    server = state.get("server", "")
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", server):
        values.append(f"{server}/32")

    networks: list[ipaddress.IPv4Network] = []
    seen: set[str] = set()
    for value in values:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            warn(f"AmneziaWG route_excludes: пропускаю невалидный CIDR {value}")
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        key = str(net)
        if key in seen:
            continue
        seen.add(key)
        networks.append(net)
    return sorted(networks, key=lambda n: (int(n.network_address), n.prefixlen))


def awg_allowed_ips(state: dict) -> list[str]:
    """Маршруты клиента AmneziaWG.

    amnezia: минимальный full-tunnel для AmneziaVPN/AmneziaWG.
    strict: математически вычитает route_excludes и IP сервера, но даёт большой QR.
    """
    cfg = awg_config(state)
    if cfg.get("route_mode", "amnezia") != "strict":
        return ["0.0.0.0/0"]

    routes = [ipaddress.ip_network("0.0.0.0/0")]
    for excluded in awg_route_excludes(state):
        next_routes: list[ipaddress.IPv4Network] = []
        for route in routes:
            if not excluded.subnet_of(route):
                next_routes.append(route)
                continue
            next_routes.extend(route.address_exclude(excluded))
        routes = next_routes
    routes = sorted(routes, key=lambda n: (int(n.network_address), n.prefixlen))
    return [str(route) for route in routes]


def ensure_user_secrets(state: dict) -> bool:
    """Дозаполняет hysteria_password/telemt_secret у пользователей. Возвращает True, если что-то добавлено."""
    changed = False
    for user in state.get("users", []):
        if not user.get("hysteria_password"):
            user["hysteria_password"] = random_password()
            changed = True
        if not user.get("telemt_secret"):
            user["telemt_secret"] = random_hex32()
            changed = True
        if "ocserv" in user_systems(user) and not user.get("ocserv_password"):
            user["ocserv_password"] = random_password()
            changed = True
        if not user.get("sub_token"):
            # Неугадываемый токен для URL подписки (32 hex).
            user["sub_token"] = secrets.token_hex(16)
            changed = True
        else:
            try:
                normalized = validate_subscription_token(user["sub_token"])
            except ValueError:
                warn(f"Пользователь {user.get('name', '<unknown>')}: sub_token был невалиден и заменён")
                user["sub_token"] = secrets.token_hex(16)
                changed = True
            else:
                if user["sub_token"] != normalized:
                    user["sub_token"] = normalized
                    changed = True
    return changed


def certificate_pin_sha256(cert_path: Path) -> str:
    try:
        text = cert_path.read_text(encoding="ascii")
    except OSError:
        return ""
    match = re.search(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        text,
        re.S,
    )
    if not match:
        return ""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
    except ValueError:
        return ""
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def certificate_sha256_hex(cert_path: Path) -> str:
    """Возвращает SHA-256 fingerprint сертификата в hex (без двоеточий).
    Xray pinnedPeerCertSha256 ожидает hex (или hex с двоеточиями), НЕ base64."""
    try:
        text = cert_path.read_text(encoding="ascii")
    except OSError:
        return ""
    match = re.search(
        r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
        text,
        re.S,
    )
    if not match:
        return ""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", match.group(1)), validate=True)
    except ValueError:
        return ""
    return hashlib.sha256(der).hexdigest().lower()


# ── Генерация сертификатов ────────────────────────────────────────────────


def generate_openssl_config(
    server_ip: str,
    state: dict | None = None,
    site_domain: str = "",
    extra_domains: list[str] | None = None,
) -> str:
    """Генерирует openssl.cnf.

    Без site_domain это self-signed сертификат для Xray/Hysteria/ocserv с
    маскировочными SNI. С site_domain это fallback-сертификат только для nginx
    сайта/подписки, пока Let's Encrypt ещё не установлен.
    """
    domains = set(CERT_SAN_DOMAINS)
    common_name = "www.microsoft.com"
    if site_domain:
        site_domain = validate_sni_domain(site_domain)
        domains = {site_domain}
        common_name = site_domain
        for domain in extra_domains or []:
            domains.add(validate_sni_domain(domain))
    # Добавляем все алиасы из sni_routes для сервисного self-signed сертификата.
    if state is not None:
        if not site_domain:
            oc_sni = state.get("ocserv", {}).get("sni", "")
            if oc_sni:
                domains.add(validate_sni_domain(oc_sni))
            for sys_name, route in get_sni_routes(state).items():
                if isinstance(route, dict):
                    if route.get("default"):
                        domains.add(validate_sni_domain(route["default"]))
                    domains.update(validate_sni_domain(alias) for alias in route.get("aliases", []))
                elif sys_name == "custom" and isinstance(route, list):
                    for c in route:
                        if c.get("sni"):
                            domains.add(validate_sni_domain(c["sni"]))
            for user in state.get("users", []):
                overrides = user.get("sni_overrides", {})
                if not isinstance(overrides, dict):
                    continue
                for sys_name in USER_SNI_OVERRIDE_SYSTEMS:
                    if overrides.get(sys_name):
                        domains.add(validate_sni_domain(overrides[sys_name]))
    domains.discard("")

    lines = [
        "[req]",
        "default_bits = 2048",
        "prompt = no",
        "default_md = sha256",
        "x509_extensions = v3_req",
        "distinguished_name = dn",
        "",
        "[dn]",
        f"CN = {common_name}",
        "",
        "[v3_req]",
        "subjectAltName = @alt_names",
        "basicConstraints = critical,CA:FALSE",
        "keyUsage = digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth",
        "",
        "[alt_names]",
    ]
    i = 1
    for d in sorted(domains):
        lines.append(f"DNS.{i} = {d}")
        i += 1
    if server_ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", server_ip):
        lines.append(f"IP.1 = {server_ip}")

    return "\n".join(lines) + "\n"


def generate_cert(
    cert_dir: Path,
    server_ip: str,
    state: dict | None = None,
    site_domain: str = "",
    extra_domains: list[str] | None = None,
) -> None:
    """Генерирует самоподписанный сертификат с SAN."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    cnf_path = cert_dir / "openssl.cnf"
    cnf_path.write_text(
        generate_openssl_config(server_ip, state, site_domain=site_domain, extra_domains=extra_domains),
        encoding="utf-8",
    )

    try:
        result = subprocess.run(
            [
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-days", "3650",
                "-keyout", str(cert_dir / "server.key"),
                "-out", str(cert_dir / "server.crt"),
                "-config", str(cnf_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        result = None
    if result is None or result.returncode != 0:
        # Fallback через docker
        if shutil.which("docker"):
            try:
                result2 = subprocess.run(
                    [
                        "docker", "run", "--rm",
                        "-v", str(cnf_path).replace(chr(92), '/') + ":/tmp/openssl.cnf:ro",
                        "-v", str(cert_dir).replace(chr(92), '/') + ":/out",
                        "alpine/openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                        "-days", "3650",
                        "-keyout", "/out/server.key",
                        "-out", "/out/server.crt",
                        "-config", "/tmp/openssl.cnf",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired):
                result2 = None
            if result2 is None or result2.returncode != 0:
                warn(f"не удалось сгенерировать сертификат в {cert_dir}")
        else:
            warn(f"openssl и docker недоступны, сертификат не обновлён в {cert_dir}")

    # Настраиваем права для Docker volume-файлов, systemd-конфига AmneziaWG и секретов.
    key_path = cert_dir / "server.key"
    crt_path = cert_dir / "server.crt"
    if key_path.exists():
        key_path.chmod(0o600)
    if crt_path.exists():
        crt_path.chmod(0o644)
    cnf_path.unlink(missing_ok=True)


def fix_permissions() -> None:
    """Устанавливает права на директории, сгенерированные конфиги и секреты проекта."""
    private_dirs = [
        "certs", "site-certs", "hy2", "hy2/certs", "xray", "nginx",
        "telemt", "mtg", "amneziawg", "wireguard", "ocserv", "ocserv/certs",
    ]
    for subdir in private_dirs:
        path = ROOT / subdir
        if not path.exists():
            continue
        if path.is_dir():
            path.chmod(0o700)
        for item in path.rglob("*"):
            if item.is_dir():
                item.chmod(0o700)
            else:
                item.chmod(0o600)

    # Статический сайт и public subscription не содержат пользовательских секретов.
    for subdir in ("nginx/web", "nginx/site"):
        path = ROOT / subdir
        if not path.exists():
            continue
        path.chmod(0o755)
        for item in path.rglob("*"):
            item.chmod(0o755 if item.is_dir() else 0o644)

    if CLIENTS_DIR.exists():
        CLIENTS_DIR.chmod(0o700)
        for item in CLIENTS_DIR.rglob("*"):
            if item.is_dir():
                item.chmod(0o700)
            else:
                item.chmod(0o600)
    # Nginx открывает сертификаты root master-процессом; ключи не нужны world-read.
    for cert_path in (
        ROOT / "certs" / "server.crt",
        ROOT / "site-certs" / "server.crt",
        ROOT / "ocserv" / "certs" / "server.crt",
        ROOT / "hy2" / "certs" / "server.crt",
    ):
        if cert_path.exists():
            cert_path.chmod(0o644)

    # Xray и Telemt в закреплённых образах работают от непривилегированного UID 65532.
    # Режим 600 сохраняется: секреты читает только соответствующий процесс контейнера.
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        container_uid = 65532
        container_gid = 65532
        container_paths = [ROOT / "xray" / "config.json", ROOT / "telemt" / "config.toml"]
        certs_dir = ROOT / "certs"
        if certs_dir.exists():
            container_paths.extend([certs_dir, *certs_dir.rglob("*")])
        for path in container_paths:
            if path.exists():
                os.chown(path, container_uid, container_gid)
    for secret_path in (
        USERS_FILE,
        CLIENT_LINKS_FILE,
        ROOT / "clients" / "all-links.txt",
    ):
        if secret_path.exists():
            secret_path.chmod(0o600)
    if AMNEZIAWG_CONFIG.exists():
        AMNEZIAWG_CONFIG.chmod(0o600)
    if WIREGUARD_CONFIG.exists():
        WIREGUARD_CONFIG.chmod(0o600)
    if OCSERV_USERS.exists():
        OCSERV_USERS.chmod(0o600)
    state = load_state()
    if state.get("portal", {}).get("enabled"):
        runtime_path = PORTAL_RUNTIME_STATE
        if STATE_STORE.path.resolve() != USERS_FILE.resolve():
            runtime_path = STATE_STORE.path.parent / "portal-runtime" / "users.json"
        if runtime_path.parent.exists():
            runtime_path.parent.chmod(0o750)
        if runtime_path.exists():
            runtime_path.chmod(0o640)
            try:
                if grp is None:
                    raise KeyError("kvn-portal")
                portal_gid = grp.getgrnam("kvn-portal").gr_gid
                os.chown(runtime_path.parent, -1, portal_gid)
                os.chown(runtime_path, -1, portal_gid)
            except (KeyError, OSError, PermissionError):
                # На Windows/в тестах системной группы может не быть; права остаются строгими.
                pass
    for script in (ROOT / "amneziawg").glob("*.sh"):
        script.chmod(0o755)
    for script in (ROOT / "wireguard").glob("*.sh"):
        script.chmod(0o755)
    for script in (ROOT / "ocserv").glob("*.sh"):
        script.chmod(0o755)
    for script in (ROOT / "tools").glob("*.sh"):
        script.chmod(0o755)
    ok("Права установлены: секретные конфиги 600, private dirs 700, portal runtime 640")


def generate_all_certs(state: dict) -> None:
    """Генерирует сертификаты для всех нужных директорий.

    certs/ и hy2/certs/ — self-signed для VPN-профилей с pin/SNI-маскировкой.
    site-certs/ — Let's Encrypt для сайта/подписки, либо временный self-signed
    fallback на домен сайта.
    ocserv/certs/ — Let's Encrypt для ocserv SNI, либо временный self-signed.
    """
    le_domains = letsencrypt_domains(state) if letsencrypt_config(state).get("enabled") else []
    le_domain = le_domains[0] if le_domains else ""
    if le_domain:
        live_source_domain = existing_letsencrypt_live_domain(le_domains)
        live_dir = LE_LIVE_DIR / (live_source_domain or le_domain)
        if live_source_domain:
            copy_letsencrypt_certificate(le_domains, target="site")
        else:
            warn(
                f"Let's Encrypt включён для {', '.join(le_domains)}, но live-сертификат не найден в {live_dir}. "
                "Генерирую временный self-signed site-certs; браузер будет показывать предупреждение до "
                f"`python3 tools/kvnctl.py letsencrypt issue --domain {le_domain} --restart`."
            )
            generate_cert(SITE_CERTS_DIR, state.get("server", ""), state, site_domain=le_domain, extra_domains=le_domains)
    else:
        site_domain = state.get("server", "")
        if site_domain and not re.match(r"^\d+\.\d+\.\d+\.\d+$", site_domain):
            generate_cert(SITE_CERTS_DIR, site_domain, state, site_domain=site_domain)
        else:
            generate_cert(SITE_CERTS_DIR, state.get("server", ""), state)

    oc_domains = ocserv_cert_domains(state)
    oc_domain = oc_domains[0] if oc_domains else ""
    if oc_domain:
        live_source_domain = existing_letsencrypt_live_domain(oc_domains)
        live_dir = LE_LIVE_DIR / (live_source_domain or oc_domain)
        if live_source_domain:
            copy_letsencrypt_certificate(oc_domains, target="ocserv")
        else:
            warn(
                f"Let's Encrypt для ocserv включён через SNI {', '.join(oc_domains)}, но live-сертификат не найден в {live_dir}. "
                "Генерирую временный self-signed ocserv/certs; клиенты будут предупреждать до выпуска сертификата."
            )
            generate_cert(OCSERV_CERTS_DIR, state.get("server", ""), state, site_domain=oc_domain, extra_domains=oc_domains)
    else:
        generate_cert(OCSERV_CERTS_DIR, state.get("server", ""), state)

    server_ip = state.get("server", "")
    generate_cert(ROOT / "certs", server_ip, state)
    generate_cert(ROOT / "hy2" / "certs", server_ip, state)
    ok("Сертификаты обновлены")


def normalize_letsencrypt_domain_list(domains: str | list[str]) -> list[str]:
    if isinstance(domains, str):
        domains = [domains]
    normalized_domains: list[str] = []
    for domain in domains:
        normalized = validate_sni_domain(domain)
        if normalized not in normalized_domains:
            normalized_domains.append(normalized)
    return normalized_domains


def existing_letsencrypt_live_domain(domains: str | list[str]) -> str:
    """Возвращает домен live-каталога Certbot с готовым fullchain/privkey."""
    for domain in normalize_letsencrypt_domain_list(domains):
        live_dir = LE_LIVE_DIR / domain
        if (live_dir / "fullchain.pem").exists() and (live_dir / "privkey.pem").exists():
            return domain
    return ""


def existing_certbot_cert_name(domains: str | list[str]) -> str:
    """Возвращает имя существующего certbot renewal-конфига для SAN-набора."""
    for domain in normalize_letsencrypt_domain_list(domains):
        if (LE_RENEWAL_DIR / f"{domain}.conf").exists():
            return domain
    return existing_letsencrypt_live_domain(domains)


def copy_letsencrypt_certificate(domains: str | list[str], target: str = "site") -> None:
    """Копирует live-сертификат Certbot в каталог, смонтированный в сервис."""
    domain_list = normalize_letsencrypt_domain_list(domains)
    if not domain_list:
        raise SystemExit("Домен Let's Encrypt не задан")
    targets = {
        "site": SITE_CERTS_DIR,
        "ocserv": OCSERV_CERTS_DIR,
    }
    if target not in targets:
        raise SystemExit(f"Неизвестный target сертификата: {target}")
    source_domain = existing_letsencrypt_live_domain(domain_list) or domain_list[0]
    live_dir = LE_LIVE_DIR / source_domain
    fullchain = live_dir / "fullchain.pem"
    privkey = live_dir / "privkey.pem"
    if not fullchain.exists() or not privkey.exists():
        raise SystemExit(
            f"Сертификат Let's Encrypt не найден: {live_dir}. "
            f"Проверенные домены: {', '.join(domain_list)}. "
            "Сначала выполните команду letsencrypt issue."
        )

    cert_dir = targets[target]
    cert_dir.mkdir(parents=True, exist_ok=True)
    for source, destination in (
        (fullchain, cert_dir / "server.crt"),
        (privkey, cert_dir / "server.key"),
    ):
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            shutil.copyfile(source, temporary)
            temporary.chmod(0o644)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    ok(f"Let's Encrypt сертификат установлен в {cert_dir.relative_to(ROOT)}/: {source_domain}")


def cert_target_dir(target: str) -> Path:
    if target == "site":
        return SITE_CERTS_DIR
    if target == "ocserv":
        return OCSERV_CERTS_DIR
    raise SystemExit(f"Неизвестный target сертификата: {target}")


def letsencrypt_target_domains(state: dict, target: str) -> list[str]:
    if target == "site":
        if not letsencrypt_config(state).get("enabled"):
            return []
        return letsencrypt_issuable_domains(letsencrypt_domains(state))
    if target == "ocserv":
        return ocserv_cert_domains(state)
    raise SystemExit(f"Неизвестный target Let's Encrypt: {target}")


def letsencrypt_target_list(target: str) -> list[str]:
    if target == "all":
        return ["site", "ocserv"]
    if target in ("site", "ocserv"):
        return [target]
    raise SystemExit(f"Неизвестный target Let's Encrypt: {target}")


def openssl_x509(cert_path: Path, args: list[str]) -> str:
    if not cert_path.exists() or not shutil.which("openssl"):
        return ""
    code, stdout, _stderr = run_command_text(["openssl", "x509", "-in", str(cert_path), *args], timeout=15)
    if code != 0:
        return ""
    return stdout


def x509_value(output: str, prefix: str) -> str:
    if output.startswith(prefix):
        return output[len(prefix):].strip()
    return output.strip()


def certificate_subject(cert_path: Path) -> str:
    return x509_value(openssl_x509(cert_path, ["-noout", "-subject"]), "subject=")


def certificate_issuer(cert_path: Path) -> str:
    return x509_value(openssl_x509(cert_path, ["-noout", "-issuer"]), "issuer=")


def certificate_dates(cert_path: Path) -> tuple[str, str]:
    output = openssl_x509(cert_path, ["-noout", "-dates"])
    not_before = ""
    not_after = ""
    for line in output.splitlines():
        if line.startswith("notBefore="):
            not_before = line.split("=", 1)[1].strip()
        elif line.startswith("notAfter="):
            not_after = line.split("=", 1)[1].strip()
    return not_before, not_after


def certificate_sans(cert_path: Path) -> list[str]:
    output = openssl_x509(cert_path, ["-noout", "-ext", "subjectAltName"])
    values: list[str] = []
    for value in re.findall(r"(?:DNS:|IP Address:)([^,\s]+)", output):
        if value not in values:
            values.append(value)
    return values


def normalize_x509_name(value: str) -> str:
    return re.sub(r"\s+", "", value).lower()


def certificate_source(cert_path: Path) -> str:
    if not cert_path.exists():
        return "missing"
    issuer = certificate_issuer(cert_path)
    subject = certificate_subject(cert_path)
    if not issuer:
        return "unknown"
    if "Let's Encrypt" in issuer:
        return "letsencrypt"
    if subject and normalize_x509_name(subject) == normalize_x509_name(issuer):
        return "self-signed"
    return "other"


def update_letsencrypt_tracking(state: dict, target: str, domains: list[str]) -> None:
    domains = normalize_letsencrypt_domain_list(domains)
    if not domains:
        return
    cert_dir = cert_target_dir(target)
    cert_path = cert_dir / "server.crt"
    live_source = existing_letsencrypt_live_domain(domains)
    live_dir = LE_LIVE_DIR / live_source if live_source else None
    cfg = letsencrypt_config(state)
    tracking = cfg.setdefault("tracking", {})
    tracking[target] = {
        "domains": domains,
        "cert_name": existing_certbot_cert_name(domains) or domains[0],
        "source": certificate_source(cert_path),
        "deployed_cert": cert_path.relative_to(ROOT).as_posix(),
        "fingerprint_sha256": certificate_sha256_hex(cert_path),
        "live_dir": str(live_dir) if live_dir else "",
        "updated_at": utc_now_iso(),
    }


def print_certificate_status(state: dict, target: str = "all") -> None:
    header("Let's Encrypt status")
    for item in letsencrypt_target_list(target):
        domains = letsencrypt_target_domains(state, item)
        cert_dir = cert_target_dir(item)
        cert_path = cert_dir / "server.crt"
        source = certificate_source(cert_path)
        issuer = certificate_issuer(cert_path)
        not_before, not_after = certificate_dates(cert_path)
        sans = certificate_sans(cert_path)
        live_source = existing_letsencrypt_live_domain(domains) if domains else ""
        live_cert = LE_LIVE_DIR / live_source / "fullchain.pem" if live_source else None
        live_match = (
            live_cert is not None
            and cert_path.exists()
            and certificate_sha256_hex(cert_path)
            and certificate_sha256_hex(cert_path) == certificate_sha256_hex(live_cert)
        )
        tracking = letsencrypt_config(state).get("tracking", {}).get(item, {})
        label = "site" if item == "site" else "ocserv"
        print(f"{C.bold}{label}{C.reset}")
        print(f"  домены: {', '.join(domains) if domains else '-'}")
        print(f"  проект: {cert_path.relative_to(ROOT).as_posix()} ({source})")
        if issuer:
            print(f"  issuer: {issuer}")
        if not_after:
            print(f"  срок: {not_before or '-'} → {not_after}")
        if sans:
            print(f"  SAN: {', '.join(sans)}")
        print(f"  certbot live: {LE_LIVE_DIR / live_source if live_source else 'не найден'}")
        if live_source:
            print(f"  проект совпадает с live: {'да' if live_match else 'нет'}")
        if tracking:
            print(f"  tracking: {tracking.get('source', '-')} / {tracking.get('updated_at', '-')}")
        if domains:
            print(f"  выпуск: python3 tools/kvnctl.py letsencrypt issue-configured --target {item} --restart")
            print(f"  перевыпуск: python3 tools/kvnctl.py letsencrypt reissue --target {item} --restart")
        print()

    if shutil.which("systemctl"):
        active = run_capture(["systemctl", "is-active", "kvn-letsencrypt-renew.timer"]) or "unknown"
        enabled = run_capture(["systemctl", "is-enabled", "kvn-letsencrypt-renew.timer"]) or "unknown"
        next_run = run_capture(["systemctl", "list-timers", "kvn-letsencrypt-renew.timer", "--no-pager", "--no-legend"])
        print(f"timer: active={active}, enabled={enabled}")
        if next_run:
            print(next_run)
    else:
        print("timer: systemctl недоступен")


def issue_configured_letsencrypt(
    state: dict,
    target: str,
    email: str | None = None,
    staging: bool = False,
    restart: bool = False,
    force_renewal: bool = False,
) -> None:
    deployed = False
    targets = letsencrypt_target_list(target)
    for item in targets:
        domains = letsencrypt_target_domains(state, item)
        if item == "site":
            skipped = [domain for domain in letsencrypt_domains(state) if domain not in domains]
            if skipped:
                warn(
                    "домены не подходят для публичного Let's Encrypt и пропущены: "
                    + ", ".join(skipped)
                )
        if not domains:
            warn(f"домены для {item} не настроены — выпуск пропущен")
            continue
        effective_email = email or letsencrypt_config(state).get("email", "")
        run_certbot_issue(domains, email=effective_email or None, staging=staging, force_renewal=force_renewal)
        if item == "site":
            if effective_email:
                letsencrypt_config(state)["email"] = effective_email
        else:
            cfg = ocserv_config(state)
            cfg["enabled"] = True
            cfg["sni_enabled"] = True
            cfg["sni"] = domains[0]
            cfg["front_snis"] = [domain for domain in domains[1:] if domain != domains[0]]
            if effective_email:
                letsencrypt_config(state)["email"] = effective_email
        save_state(state)
        deploy_letsencrypt_certificate(state, domains, restart=False, target=item)
        deployed = True

    if not deployed:
        warn("сертификаты не выпускались: нет настроенных доменов")
        return
    install_letsencrypt_renewal_best_effort()
    if restart:
        restart_services(True)
    ok("Let's Encrypt сертификаты обработаны")


def run_certbot_issue(
    domains: str | list[str],
    email: str | None = None,
    staging: bool = False,
    force_renewal: bool = False,
) -> str:
    """Выпускает один SAN-сертификат через HTTP-01 standalone Certbot."""
    if not shutil.which("certbot"):
        raise SystemExit(
            "certbot не найден. Установите: apt-get install -y certbot "
            "(setup.sh теперь делает это автоматически)."
        )
    domain_list = normalize_letsencrypt_domain_list(domains)
    if not domain_list:
        raise SystemExit("Нужно указать хотя бы один домен для Let's Encrypt")
    existing_cert_name = existing_certbot_cert_name(domain_list)
    cert_name = existing_cert_name or domain_list[0]
    command = [
        "certbot",
        "certonly",
        "--standalone",
        "--preferred-challenges",
        "http",
        "--non-interactive",
        "--agree-tos",
        "--cert-name",
        cert_name,
    ]
    if force_renewal:
        command.append("--force-renewal")
    else:
        command.append("--keep-until-expiring")
    if existing_cert_name and len(domain_list) > 1:
        command.append("--expand")
    for domain in domain_list:
        command.extend(["-d", domain])
    if email:
        command.extend(["--email", email])
    else:
        command.append("--register-unsafely-without-email")
    if staging:
        command.append("--test-cert")

    info("Запускаю certbot standalone HTTP-01. Домен должен вести на этот сервер, порт 80/tcp должен быть открыт.")
    nginx_stopped = _stop_docker_service_best_effort("nginx")
    try:
        result = subprocess.run(command, cwd=ROOT, check=False, timeout=180)
    finally:
        if nginx_stopped:
            _start_docker_service_best_effort("nginx")
    if result.returncode != 0:
        raise SystemExit("certbot завершился с ошибкой. Проверьте DNS, firewall 80/tcp и отсутствие другого сервиса на :80.")
    ok(f"Let's Encrypt сертификат выпущен/обновлён: {', '.join(domain_list)}")
    return cert_name


def certbot_supports_ip_certificates(version_output: str | None = None) -> bool:
    """IP certificates появились в Certbot 5.4; старые версии не обновляем из PyPI."""
    output = version_output
    if output is None:
        output = run_capture(["certbot", "--version"]) if shutil.which("certbot") else ""
    match = re.search(r"certbot\s+(\d+)\.(\d+)", output or "", re.IGNORECASE)
    return bool(match and (int(match.group(1)), int(match.group(2))) >= (5, 4))


def run_certbot_issue_ip(ip: str, email: str | None = None) -> str:
    """Выпускает short-lived сертификат Let's Encrypt для публичного IPv4."""
    ip = validate_portal_host(ip)
    if portal_host_kind(ip) != "ipv4":
        raise SystemExit("Для IP-сертификата нужен публичный IPv4")
    if not certbot_supports_ip_certificates():
        raise SystemExit(
            "IP-сертификаты требуют Certbot 5.4+. Используйте пакет Debian после его обновления "
            "или явный self-signed fallback; PyPI/unstable автоматически не подключаются."
        )
    command = [
        "certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--preferred-profile", "shortlived", "--ip-address", ip,
        "--cert-name", ip, "--keep-until-expiring",
    ]
    if email:
        command.extend(["--email", email])
    else:
        command.append("--register-unsafely-without-email")
    nginx_stopped = _stop_docker_service_best_effort("nginx")
    try:
        result = subprocess.run(command, cwd=ROOT, check=False, timeout=180)
    finally:
        if nginx_stopped:
            _start_docker_service_best_effort("nginx")
    if result.returncode != 0:
        raise SystemExit("Certbot не выпустил short-lived IP-сертификат.")
    ok(f"Let's Encrypt IP-сертификат выпущен/обновлён: {ip}")
    return ip


def deploy_letsencrypt_ip_certificate(state: dict, ip: str, restart: bool = False) -> None:
    """Атомарно раскладывает `/etc/letsencrypt/live/<IP>/` в site-certs."""
    ip = validate_portal_host(ip)
    if portal_host_kind(ip) != "ipv4":
        raise SystemExit("Для deploy IP-сертификата нужен публичный IPv4")
    live_dir = LE_LIVE_DIR / ip
    fullchain, privkey = live_dir / "fullchain.pem", live_dir / "privkey.pem"
    if not fullchain.exists() or not privkey.exists():
        raise SystemExit(f"IP-сертификат Let's Encrypt не найден: {live_dir}")
    SITE_CERTS_DIR.mkdir(parents=True, exist_ok=True)
    for source, destination in (
        (fullchain, SITE_CERTS_DIR / "server.crt"),
        (privkey, SITE_CERTS_DIR / "server.key"),
    ):
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
        try:
            shutil.copyfile(source, temporary)
            temporary.chmod(0o644)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
    render_all(state)
    save_state(state)
    if restart:
        reload_certificate_consumers(state, "site")
    ok(f"Let's Encrypt IP-сертификат установлен в site-certs/: {ip}")


def configure_letsencrypt_state(state: dict, domains: str | list[str], email: str | None = None) -> bool:
    if isinstance(domains, str):
        domains = [domains]
    normalized_domains: list[str] = []
    for domain in domains:
        normalized = validate_sni_domain(domain)
        if normalized not in normalized_domains:
            normalized_domains.append(normalized)
    if not normalized_domains:
        raise SystemExit("Нужно указать хотя бы один домен Let's Encrypt")
    domain = normalized_domains[0]
    domain = validate_sni_domain(domain)
    changed = False
    if state.get("server") != domain:
        state["server"] = domain
        changed = True
    cfg = letsencrypt_config(state)
    if cfg.get("enabled") is not True:
        cfg["enabled"] = True
        changed = True
    if cfg.get("domain") != domain:
        cfg["domain"] = domain
        changed = True
    if cfg.get("domains", []) != normalized_domains:
        cfg["domains"] = normalized_domains
        changed = True
    if email is not None and cfg.get("email", "") != email:
        cfg["email"] = email
        changed = True
    return changed


def deploy_letsencrypt_certificate(
    state: dict,
    domain: str | list[str] | None = None,
    restart: bool = False,
    target: str = "site",
) -> None:
    default_domains = ocserv_cert_domains(state) if target == "ocserv" else letsencrypt_domains(state)
    domains = normalize_letsencrypt_domain_list(domain or default_domains)
    if not domains:
        raise SystemExit("Домен Let's Encrypt не задан")
    copy_letsencrypt_certificate(domains, target=target)
    render_all(state)
    update_letsencrypt_tracking(state, target, domains)
    save_state(state)
    if restart:
        reload_certificate_consumers(state, target)


def reload_certificate_consumers(state: dict, target: str) -> dict:
    report = {"reloaded": [], "recreated": [], "warnings": []}
    services = ["nginx"] if target == "site" else ["ocserv"]
    for service in services:
        cert_dir = "/etc/nginx/certs" if service == "nginx" else "/etc/ocserv/certs"
        visible = _docker_service_files_visible(
            service, [f"{cert_dir}/server.crt", f"{cert_dir}/server.key"],
        )
        if visible and _reload_docker_service(service):
            report["reloaded"].append(service)
        elif not visible and _recreate_docker_service(service):
            report["recreated"].append(service)
        else:
            report["warnings"].append(f"{service}: reload не выполнен")
    cfg = state.get("portal", {})
    if target == "site" and cfg.get("enabled") and cfg.get("port") != 443:
        visible = _docker_service_files_visible(
            "portal-gateway",
            ["/etc/nginx/certs/server.crt", "/etc/nginx/certs/server.key"],
        )
        try:
            checked = _run_compose(["exec", "-T", "portal-gateway", "nginx", "-t"], timeout=30)
            reloaded = visible and checked.returncode == 0 and _run_compose(
                ["exec", "-T", "portal-gateway", "nginx", "-s", "reload"], timeout=30
            ).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            reloaded = False
        if reloaded:
            report["reloaded"].append("portal-gateway")
        elif not visible and _recreate_docker_service("portal-gateway"):
            report["recreated"].append("portal-gateway")
        else:
            report["warnings"].append("portal-gateway: reload не выполнен")
    return report


def install_letsencrypt_renewal_best_effort() -> None:
    script = ROOT / "tools" / "install-letsencrypt-renewal.sh"
    if not script.exists():
        warn("install-letsencrypt-renewal.sh не найден — автопродление Let's Encrypt не установлено")
        return
    if not shutil.which("systemctl"):
        warn("systemctl не найден — автопродление Let's Encrypt не установлено")
        return
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        warn("Автопродление Let's Encrypt требует root. Выполните: sudo python3 tools/kvnctl.py letsencrypt install-renewal")
        return
    result = subprocess.run([str(script)], cwd=ROOT, check=False, timeout=60)
    if result.returncode != 0:
        warn("install-letsencrypt-renewal.sh завершился с ошибкой")
    else:
        ok("systemd timer автопродления Let's Encrypt установлен")


# ── Рендер nginx ──────────────────────────────────────────────────────────


def sub_server_block(state: dict) -> str:
    """HTTP(S)-server для раздачи подписки по токену (если включено)."""
    cfg = sub_config(state)
    if not cfg.get("enabled", True):
        return ""
    port = int(cfg.get("port", DEFAULT_SUB_PORT))
    return f"""
    # Старый endpoint /<token> сохраняется без изменений. Именованные endpoints
    # /happ/, /karing/ и /karing-wg/ позволяют выдавать совместимые payload.
    server {{
        listen {port} ssl;
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_tickets off;
        server_tokens off;
        access_log off;

        root /var/www/sub;
        autoindex off;

        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header Cache-Control "no-store" always;
        add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
        add_header X-Frame-Options "DENY" always;

        location = / {{ return 404; }}
        location ~ "^/[0-9a-f]{{32}}$" {{
            limit_except GET {{ deny all; }}
            default_type text/plain;
            limit_req zone=sub burst=10 nodelay;
            add_header X-Content-Type-Options "nosniff" always;
            add_header Referrer-Policy "no-referrer" always;
            add_header Cache-Control "no-store" always;
            add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
            add_header X-Frame-Options "DENY" always;
            add_header Profile-Update-Interval "12" always;
            try_files $uri =404;
        }}
        location ~ "^/(?:happ|karing|karing-wg)/[0-9a-f]{{32}}$" {{
            limit_except GET {{ deny all; }}
            default_type text/plain;
            limit_req zone=sub burst=10 nodelay;
            add_header X-Content-Type-Options "nosniff" always;
            add_header Referrer-Policy "no-referrer" always;
            add_header Cache-Control "no-store" always;
            add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
            add_header X-Frame-Options "DENY" always;
            add_header Profile-Update-Interval "12" always;
            try_files $uri =404;
        }}
        location / {{ return 404; }}
    }}
"""


def portal_public_ready(state: dict) -> bool:
    cfg = portal_config(state)
    if not cfg.get("enabled"):
        return False
    cert_path = SITE_CERTS_DIR / "server.crt"
    source = certificate_source(cert_path)
    san_matches = cfg["domain"] in certificate_sans(cert_path)
    if portal_host_kind(cfg["domain"]) == "ipv4":
        return san_matches and (
            source == "letsencrypt"
            or source == "self-signed" and cfg["allow_self_signed_ip"]
        )
    return source == "letsencrypt" and san_matches


def portal_proxy_locations(state: dict, *, custom_gateway: bool = False) -> str:
    cfg = portal_config(state)
    if not cfg.get("enabled") or (cfg["port"] != 443) != custom_gateway:
        return ""
    path = cfg["path"]
    if not portal_public_ready(state):
        return f"""
        location = {path} {{ return 404; }}
        location ^~ {path}/ {{ return 404; }}
"""
    domain = cfg["domain"]
    secret = cfg["proxy_secret"]
    return f"""
        location = {path} {{
            if ($host != {domain}) {{ return 404; }}
            return 308 {path}/;
        }}

        location ^~ {path}/ {{
            if ($host != {domain}) {{ return 404; }}
            client_max_body_size 2g;
            limit_req zone=portal burst=20 nodelay;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-KVN-Proxy-Secret {secret};
            proxy_set_header Connection "";
            proxy_connect_timeout 3s;
            proxy_read_timeout 30m;
            proxy_send_timeout 30m;
            proxy_request_buffering off;
            proxy_buffering off;
            set $portal_backend portal:8080;
            proxy_pass http://$portal_backend$request_uri;
            add_header Cache-Control "no-store" always;
        }}
"""


def render_portal_gateway(state: dict) -> None:
    cfg = portal_config(state)
    locations = portal_proxy_locations(state, custom_gateway=True)
    server_name = cfg.get("domain", "invalid.local") if cfg.get("enabled") else "invalid.local"
    content = f"""worker_processes 1;
events {{ worker_connections 1024; }}
http {{
    include /etc/nginx/mime.types;
    resolver 127.0.0.11 valid=10s ipv6=off;
    client_max_body_size 2g;
    limit_req_zone $binary_remote_addr zone=portal:10m rate=120r/m;
    server {{
        listen 8443 ssl;
        server_name {server_name};
        client_max_body_size 2g;
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        server_tokens off;
        access_log off;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
{locations}
        location / {{ return 404; }}
    }}
}}
"""
    if PORTAL_GATEWAY_CONFIG.is_dir():
        if any(PORTAL_GATEWAY_CONFIG.iterdir()):
            raise SystemExit(
                f"{PORTAL_GATEWAY_CONFIG} должен быть файлом, но является непустым каталогом; "
                "проверьте его содержимое вручную"
            )
        PORTAL_GATEWAY_CONFIG.rmdir()
        warn(
            f"удалён пустой каталог {PORTAL_GATEWAY_CONFIG}, "
            "созданный Docker вместо файла конфигурации"
        )
    PORTAL_GATEWAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    PORTAL_GATEWAY_CONFIG.write_text(content, encoding="utf-8")


def decoy_server_block(state: dict) -> str:
    """Внутренний HTTPS-сайт для домена Let's Encrypt и fallback на 443/tcp."""
    portal_locations = portal_proxy_locations(state)
    template = """
    # Сайт для домена Let's Encrypt и default-трафика.
    # Внешний порт не публикуется: stream-прокси отправляет сюда нужные SNI.
    server {
        listen 8443 ssl;
        client_max_body_size 2g;
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        server_tokens off;
        access_log off;
        error_log /dev/stderr warn;

        root /var/www/site;
        index index.html;

        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header Cache-Control "public, max-age=300" always;
        add_header Content-Security-Policy "default-src 'self'; base-uri 'none'; frame-ancestors 'none'" always;
        add_header X-Frame-Options "DENY" always;

__PORTAL_LOCATIONS__

        location ~ "^/[0-9a-f]{32}$" {
            root /var/www/sub;
            limit_except GET { deny all; }
            default_type text/plain;
            limit_req zone=sub burst=10 nodelay;
            add_header X-Content-Type-Options "nosniff" always;
            add_header Referrer-Policy "no-referrer" always;
            add_header Cache-Control "no-store" always;
            add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
            add_header X-Frame-Options "DENY" always;
            add_header Profile-Update-Interval "12" always;
            try_files $uri =404;
        }

        location ~ "^/(?:happ|karing|karing-wg)/[0-9a-f]{32}$" {
            root /var/www/sub;
            limit_except GET { deny all; }
            default_type text/plain;
            limit_req zone=sub burst=10 nodelay;
            add_header X-Content-Type-Options "nosniff" always;
            add_header Referrer-Policy "no-referrer" always;
            add_header Cache-Control "no-store" always;
            add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
            add_header X-Frame-Options "DENY" always;
            add_header Profile-Update-Interval "12" always;
            try_files $uri =404;
        }

        location / {
            try_files $uri $uri/ /index.html;
        }
    }

    # HTTP backend для legacy Xray TLS fallback на старых диагностических SNI:
    # обычный браузер получает сайт, а валидный VLESS-клиент обрабатывается Xray.
    server {
        listen 8080;
        server_tokens off;
        access_log off;
        error_log /dev/stderr warn;

        root /var/www/site;
        index index.html;

        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header Cache-Control "public, max-age=300" always;
        add_header Content-Security-Policy "default-src 'self'; base-uri 'none'; frame-ancestors 'none'" always;
        add_header X-Frame-Options "DENY" always;

        location / {
            try_files $uri $uri/ /index.html;
        }
    }
"""
    return template.replace("__PORTAL_LOCATIONS__", portal_locations)


def render_decoy_site_text(state: dict) -> str:
    """Возвращает HTML нейтрального статического сайта."""
    server = html.escape(state.get("server", ""), quote=True)
    title = html.escape(site_config(state).get("title", DEFAULT_SITE_TITLE), quote=True)
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
    :root {{ color-scheme: light dark; }}
    body {{
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.55;
      color: #1f2933;
      background: #f6f7f9;
    }}
    main {{
      max-width: 760px;
      margin: 0 auto;
      padding: 56px 20px;
    }}
    h1 {{
      margin: 0 0 14px;
      font-size: 30px;
      font-weight: 700;
    }}
    p {{ margin: 0 0 16px; }}
    section {{
      margin-top: 28px;
      padding-top: 22px;
      border-top: 1px solid #d8dde5;
    }}
    ul {{ padding-left: 20px; }}
    li {{ margin: 8px 0; }}
    small {{ color: #64748b; }}
    @media (prefers-color-scheme: dark) {{
      body {{ color: #d9e2ec; background: #111827; }}
      section {{ border-color: #334155; }}
      small {{ color: #94a3b8; }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>{title}</h1>
    <p>Этот узел используется для служебных сетевых задач и проверки доступности HTTPS.</p>
    <section>
      <h2>Статус</h2>
      <ul>
        <li>Узел: {title}.</li>
        <li>HTTPS доступен.</li>
        <li>Адрес: {server or "не указан"}.</li>
        <li>Страница обновляется автоматически при деплое.</li>
      </ul>
    </section>
    <section>
      <small>Если вы попали сюда случайно, дополнительных действий не требуется.</small>
    </section>
  </main>
</body>
</html>
"""


def render_decoy_site(state: dict) -> None:
    """Пишет нейтральный статический сайт."""
    DECOY_SITE_DIR.mkdir(parents=True, exist_ok=True)
    html_doc = render_decoy_site_text(state)
    (DECOY_SITE_DIR / "index.html").write_text(html_doc, encoding="utf-8")


def nginx_backend_name(dest: str) -> str:
    """Стабильное имя upstream-группы для stream backend."""
    digest = hashlib.sha1(dest.encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^A-Za-z0-9]+", "_", dest).strip("_").lower() or "backend"
    return f"backend_{slug[:36]}_{digest}"


def nginx_upstream_server_line(dest: str) -> str:
    """Строка server для nginx upstream.

    DNS-имена Docker-сервисов помечаем resolve, чтобы nginx переживал recreate
    backend-контейнера без полного пересоздания фронта.
    """
    if dest.startswith("unix:"):
        return f"server {dest};"
    host = dest.rsplit(":", 1)[0].strip("[]")
    try:
        ipaddress.ip_address(host)
        return f"server {dest};"
    except ValueError:
        if host in {"localhost"}:
            return f"server {dest};"
        return f"server {dest} resolve;"


def render_nginx(state: dict) -> None:
    """Генерирует nginx.conf из sni_routes."""
    aliases = all_sni_aliases(state)
    sub_block = sub_server_block(state)

    # Собираем map-строки (mtg теперь faketls → его домен тоже здесь, как TLS).
    map_lines = []
    for sni, dest in sorted(aliases.items(), key=lambda x: x[0]):
        map_lines.append(f'        "1:{sni}"    "{dest}";')
        if dest in {"telemt:3129", "mtg:3128", "ocserv:443"}:
            # Some MTProto FakeTLS/TLS-emulation clients expose SNI while nginx
            # cannot classify ssl_preread_protocol. OpenConnect clients can hit
            # the same edge case on some TLS stacks. Keep routing by SNI instead
            # of falling through to the decoy site.
            map_lines.append(f'        "0:{sni}"    "{dest}";')

    # Убираем дубли (алиасы могут пересекаться)
    seen: dict[str, str] = {}
    for line in map_lines:
        m = re.match(r'\s*"(\d+):([^"]+)"\s+"([^"]+)"', line)
        if m:
            key = f"{m.group(1)}:{m.group(2)}"
            if key not in seen:
                seen[key] = m.group(3)

    # Пересобираем map
    final_map_lines = []
    for key, dest in sorted(seen.items()):
        final_map_lines.append(f'        "{key}"    "{dest}";')

    # Hysteria работает на UDP напрямую, её алиасы уже исключены из map.
    all_backend_dests = set(seen.values())

    # Default/no-SNI route. In the current production profile ocserv uses an
    # explicit SNI, so unknown/no-SNI traffic lands on the website fallback.
    default_backend = "127.0.0.1:8443"
    oc_cfg = ocserv_config(state)
    if oc_cfg.get("enabled") and not oc_cfg.get("sni_enabled"):
        default_backend = "ocserv:443"
    all_backend_dests.add(default_backend)

    backend_names = {dest: nginx_backend_name(dest) for dest in sorted(all_backend_dests)}
    upstream_blocks = []
    for dest, name in backend_names.items():
        upstream_blocks.append(
            f"""    upstream {name} {{
        zone {name} 64k;
        {nginx_upstream_server_line(dest)}
    }}"""
        )

    tcp_map_lines = []
    for line in final_map_lines:
        m = re.match(r'\s*"([^"]+)"\s+"([^"]+)"', line)
        if not m:
            continue
        tcp_map_lines.append(f'        "{m.group(1)}"    {backend_names[m.group(2)]};')
    tcp_map_lines.append(f"        default    {backend_names[default_backend]};")

    nginx_conf = f"""worker_processes auto;
worker_rlimit_nofile 262144;
worker_shutdown_timeout 10s;

error_log /var/log/nginx/error.log warn;

events {{
    use epoll;
    worker_connections 16384;
    multi_accept on;
}}

# HTTP-блок нужен для HTTPS-подписки.
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    resolver 127.0.0.11 valid=10s ipv6=off;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 15s;
    keepalive_requests 1000;
    server_tokens off;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    open_file_cache max=1000 inactive=60s;
    open_file_cache_valid 120s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    limit_req_zone $binary_remote_addr zone=sub:10m rate=120r/m;
    limit_req_zone $binary_remote_addr zone=portal:10m rate=120r/m;

    include /etc/nginx/conf.d/*.conf;

    # Публичный HTTP endpoint для доменных проверок. Корень отдаёт 200 OK для
    # регистраторов/health-checker'ов, остальные HTTP-пути уходят на HTTPS.
    server {{
        listen 80 default_server;
        server_name _;
        access_log off;
        error_log /dev/stderr warn;

        location = / {{
            default_type text/plain;
            return 200 "ok\\n";
        }}

        location / {{
            return 301 https://$host$request_uri;
        }}
    }}
{decoy_server_block(state)}
{sub_block}}}

# STREAM-блок: L4-проксирование VPN/прокси трафика.
stream {{
    resolver 127.0.0.11 valid=10s ipv6=off;
    resolver_timeout 2s;
    preread_buffer_size 16k;
    preread_timeout 10s;
    proxy_buffer_size 32k;
    proxy_connect_timeout 3s;
    proxy_timeout 2h;
    proxy_half_close on;
    proxy_socket_keepalive on;
    tcp_nodelay on;

{chr(10).join(upstream_blocks)}

    log_format stream_basic
        '$time_iso8601 client=$remote_addr:$remote_port '
        'listen=$server_addr:$server_port '
        'tls="$ssl_preread_protocol" '
        'sni="$ssl_preread_server_name" '
        'backend="$backend_443" '
        'upstream="$upstream_addr" '
        'status=$status bytes_in=$bytes_received bytes_out=$bytes_sent';
    access_log off;

    map $ssl_preread_protocol $is_tls {{
        ""      0;
        default 1;
    }}

    # SNI-роутинг: автоматически из sni_routes в users.json.
    map "$is_tls:$ssl_preread_server_name" $backend_443 {{
{chr(10).join(tcp_map_lines)}
    }}

    server {{
        listen 443 reuseport backlog=65535 so_keepalive=on;
        ssl_preread on;
        proxy_pass $backend_443;
    }}

    # Hysteria v2 (QUIC/UDP) публикуется напрямую контейнером hysteria.
}}
"""

    NGINX_CONFIG.write_text(nginx_conf, encoding="utf-8")
    render_portal_gateway(state)


# ── Рендер серверных конфигов ────────────────────────────────────────────


def default_xray_config(state: dict) -> dict:
    """Базовый Xray-конфиг для чистого deploy без сгенерированного xray/config.json."""
    xhttp_sni = system_sni(state, "reality-xhttp")
    tcp_sni = system_sni(state, "reality-tcp")
    return {
        "log": {"loglevel": "warning"},
        "policy": {
            "levels": {
                "0": {
                    "handshake": 10,
                    "connIdle": 300,
                    "uplinkOnly": 2,
                    "downlinkOnly": 5,
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            }
        },
        "stats": {},
        "inbounds": [
            {
                "listen": "0.0.0.0",
                "port": 443,
                "protocol": "vless",
                "tag": TLS_INBOUND_TAG,
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "rejectUnknownSni": True,
                        "minVersion": "1.2",
                        "certificates": [
                            {
                                "certificateFile": "/etc/xray/certs/server.crt",
                                "keyFile": "/etc/xray/certs/server.key",
                            }
                        ],
                    },
                },
            },
            {
                "listen": "0.0.0.0",
                "port": 2053,
                "protocol": "vless",
                "tag": REALITY_XHTTP_INBOUND_TAG,
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "xhttp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": f"{xhttp_sni}:443",
                        "serverNames": reality_xhttp_server_names(state),
                        "fingerprint": "chrome",
                    },
                    "xhttpSettings": {
                        "path": REALITY_XHTTP_PATH,
                        "mode": xhttp_mode(state),
                        "extra": {"xPaddingBytes": "100-1000"},
                    },
                },
            },
            {
                "listen": "0.0.0.0",
                "port": 2054,
                "protocol": "vless",
                "tag": REALITY_TCP_INBOUND_TAG,
                "settings": {"clients": [], "decryption": "none"},
                "streamSettings": {
                    "network": "raw",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "target": f"{tcp_sni}:443",
                        "serverNames": route_server_names(state, "reality-tcp") or [tcp_sni],
                        "fingerprint": "chrome",
                    },
                },
            },
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
    }


def render_xray(state: dict) -> None:
    if XRAY_CONFIG.exists():
        with XRAY_CONFIG.open("r", encoding="utf-8") as f:
            config = json.load(f)
    else:
        XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
        config = default_xray_config(state)

    xray_state = state.get("xray", {})
    loglevel = xray_state.get("loglevel", "warning")
    if loglevel not in {"debug", "info", "warning", "error", "none"}:
        loglevel = "warning"
    log = config.setdefault("log", {})
    log["loglevel"] = loglevel
    if loglevel in {"debug", "info"}:
        log["access"] = "/dev/stdout"
        log["error"] = "/dev/stderr"
    else:
        log.pop("access", None)
        log.pop("error", None)

    policy = config.setdefault("policy", {})
    levels = policy.setdefault("levels", {})
    level0 = levels.setdefault("0", {})
    level0.pop("bufferSize", None)
    level0["statsUserUplink"] = True
    level0["statsUserDownlink"] = True
    policy["system"] = {
        "statsInboundUplink": True,
        "statsInboundDownlink": True,
        "statsOutboundUplink": True,
        "statsOutboundDownlink": True,
    }
    config["api"] = {
        "tag": "api",
        "services": ["HandlerService", "StatsService"],
    }
    config["stats"] = {}

    api_inbound = next(
        (item for item in config.setdefault("inbounds", []) if item.get("tag") == "api-inbound"),
        None,
    )
    if api_inbound is None:
        api_inbound = {
            "listen": "127.0.0.1",
            "port": 10085,
            "protocol": "dokodemo-door",
            "tag": "api-inbound",
            "settings": {"address": "127.0.0.1"},
        }
        config["inbounds"].append(api_inbound)

    users = enabled_users(state)
    tls_clients = xray_client_entries(users, "tls", flow=True)
    reality_xhttp_clients = xray_client_entries(users, "reality-xhttp", flow=False)
    reality_tcp_clients = xray_client_entries(users, "reality-tcp", flow=True)

    tls_inbound = ensure_inbound(config, TLS_INBOUND_TAG)
    xhttp_inbound = ensure_inbound(config, REALITY_XHTTP_INBOUND_TAG)
    tcp_inbound = ensure_reality_tcp_inbound(config, state)

    tls_inbound["settings"]["clients"] = tls_clients
    xhttp_inbound["settings"]["clients"] = reality_xhttp_clients
    tcp_inbound["settings"]["clients"] = reality_tcp_clients

    # Reality xHTTP принимает широкий список serverNames, как на рабочем профиле.
    # nginx map при этом содержит только неконфликтные SNI для маршрутизации на xray:2053.
    xhttp_snis = reality_xhttp_server_names(state)
    xhttp_rs = xhttp_inbound.setdefault("streamSettings", {}).setdefault("realitySettings", {})
    xhttp_rs["serverNames"] = xhttp_snis

    # privateKey/shortIds берём из state (единый источник правды, см. ensure_reality_public_key)
    xhttp_state = state.get("reality", {})
    if xhttp_state.get("privateKey"):
        xhttp_rs["privateKey"] = xhttp_state["privateKey"]
    if xhttp_state.get("shortIds"):
        xhttp_rs["shortIds"] = xhttp_state["shortIds"]

    # xhttpSettings: сервер и клиентские ссылки должны использовать один режим.
    xhttp_ss = xhttp_inbound.setdefault("streamSettings", {})
    xhttp_ss["network"] = "xhttp"
    xhttp_ss["security"] = "reality"
    xhttp_settings = xhttp_ss.setdefault("xhttpSettings", {})
    xhttp_settings["path"] = REALITY_XHTTP_PATH
    xhttp_settings["mode"] = xhttp_mode(state)
    xhttp_settings.pop("extra", None)
    xhttp_settings["extra"] = {"xPaddingBytes": "100-1000"}

    tcp_snis = route_server_names(state, "reality-tcp") or ["apple.com"]
    tcp_rs = tcp_inbound.setdefault("streamSettings", {}).setdefault("realitySettings", {})
    tcp_rs["serverNames"] = tcp_snis

    tcp_state = state.get("reality_tcp", {})
    if tcp_state.get("privateKey"):
        tcp_rs["privateKey"] = tcp_state["privateKey"]
    if tcp_state.get("shortIds"):
        tcp_rs["shortIds"] = tcp_state["shortIds"]

    # maxTimeDiff опционален. В рабочем профиле пользователя не задан.
    max_time_diff = xray_state.get("reality_max_time_diff_ms", REALITY_MAX_TIME_DIFF_MS)
    if isinstance(max_time_diff, int) and max_time_diff > 0:
        xhttp_rs["maxTimeDiff"] = max_time_diff
        tcp_rs["maxTimeDiff"] = max_time_diff
    else:
        xhttp_rs.pop("maxTimeDiff", None)
        tcp_rs.pop("maxTimeDiff", None)

    # Target для reality = default SNI
    xhttp_target = system_sni(state, "reality-xhttp")
    xhttp_rs["target"] = f"{xhttp_target}:443"

    tcp_target = system_sni(state, "reality-tcp")
    tcp_rs["target"] = f"{tcp_target}:443"

    # Очищаем устаревшие fallbacks и allocate
    for inbound in config["inbounds"]:
        if inbound.get("tag") == "api-inbound":
            continue
        inbound["settings"].pop("fallbacks", None)
        inbound.pop("allocate", None)
        sockopt = inbound.setdefault("streamSettings", {}).setdefault("sockopt", {})
        sockopt.pop("tcpcongestion", None)
        sockopt.pop("tcpMptcp", None)
        # Профиль как на рабочем сервере пользователя.
        sockopt["tcpFastOpen"] = True
        sockopt["tcpCongestion"] = "bbr"
        sockopt["tcpNoDelay"] = True
        sockopt.pop("tcpKeepAliveIdle", None)
        sockopt.pop("tcpKeepAliveInterval", None)

    if letsencrypt_config(state).get("enabled") and letsencrypt_domain(state):
        tls_inbound["settings"]["fallbacks"] = [{"dest": "nginx:8080"}]
        tls_settings = tls_inbound.setdefault("streamSettings", {}).setdefault("tlsSettings", {})
        tls_settings["alpn"] = ["http/1.1"]

    # Sniffing как на рабочем сервере: только для маршрутизации, без подмены назначения.
    for inbound in config["inbounds"]:
        if inbound.get("tag") == "api-inbound":
            continue
        inbound["sniffing"] = {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": True,
        }

    routing = config.setdefault("routing", {})
    routing["domainStrategy"] = "IPIfNonMatch"
    rules = routing.setdefault("rules", [])
    rules[:] = [
        rule for rule in rules
        if not (
            rule.get("inboundTag") == ["api-inbound"]
            and rule.get("outboundTag") == "api"
        )
    ]
    rules.insert(0, {
        "type": "field",
        "inboundTag": ["api-inbound"],
        "outboundTag": "api",
    })
    # Вычищаем устаревшие geosite-категории, которых нет в geosite.dat v26+
    _KNOWN_BAD_GEOSITES = {"microsoft-cn"}
    for rule in rules:
        domains = rule.get("domain", [])
        if isinstance(domains, list):
            rule["domain"] = [d for d in domains if not (isinstance(d, str) and d.startswith("geosite:") and d.split(":", 1)[1] in _KNOWN_BAD_GEOSITES)]
    has_private = any(
        r.get("type") == "field" and "geoip:private" in r.get("ip", [])
        for r in rules
    )
    if not has_private:
        rules.insert(0, {
            "type": "field",
            "outboundTag": "block",
            "ip": ["geoip:private"],
        })

    XRAY_CONFIG.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def xray_client_entries(users: list[dict], system: str, flow: bool) -> list[dict]:
    clients = []
    for user in users:
        if system not in user_systems(user):
            continue
        client = {
            "id": user["uuid"],
            "email": f"{user['name']}-{system}",
            "level": 0,
        }
        if flow:
            client["flow"] = "xtls-rprx-vision"
        clients.append(client)
    return clients


def ensure_inbound(config: dict, tag: str) -> dict:
    for inbound in config["inbounds"]:
        if inbound.get("tag") == tag:
            return inbound
    raise SystemExit(f"В xray/config.json не найден inbound: {tag}")


def ensure_reality_tcp_inbound(config: dict, state: dict) -> dict:
    for inbound in config["inbounds"]:
        if inbound.get("tag") == REALITY_TCP_INBOUND_TAG:
            return inbound

    # Создаём TCP Reality inbound
    xhttp_inbound = ensure_inbound(config, REALITY_XHTTP_INBOUND_TAG)
    reality_settings = dict(xhttp_inbound["streamSettings"]["realitySettings"])

    tcp_sni = system_sni(state, "reality-tcp")
    tcp_aliases = route_server_names(state, "reality-tcp") or [tcp_sni]

    reality_settings["target"] = f"{tcp_sni}:443"
    reality_settings["serverNames"] = tcp_aliases
    # Ключи Reality-TCP берём из state (заполняется ensure_reality_public_key).
    reality_tcp_state = state.get("reality_tcp", {})
    reality_settings["privateKey"] = reality_tcp_state.get("privateKey", reality_settings.get("privateKey", ""))
    reality_settings["shortIds"] = reality_tcp_state.get("shortIds", reality_settings.get("shortIds", []))

    inbound = {
        "listen": "0.0.0.0",
        "port": 2054,
        "protocol": "vless",
        "tag": REALITY_TCP_INBOUND_TAG,
        "settings": {
            "clients": [],
            "decryption": "none",
            "fallbacks": [],
        },
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": reality_settings,
            "sockopt": {
                "tcpFastOpen": True,
                "tcpCongestion": "bbr",
                "tcpNoDelay": True,
            },
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": True,
        },
    }
    config["inbounds"].append(inbound)
    return inbound


def render_hysteria(state: dict) -> None:
    portal = state.get("portal", {})
    use_portal_auth = bool(
        portal.get("enabled")
        and portal.get("hysteria_secret")
    )
    lines = [
        "listen: :443",
        "",
        "tls:",
        "  cert: /etc/hysteria/certs/server.crt",
        "  key: /etc/hysteria/certs/server.key",
        "  sniGuard: disable",
        "",
    ]
    if use_portal_auth:
        token = quote(str(portal["hysteria_secret"]), safe="")
        lines.extend([
            "auth:",
            "  type: http",
            "  http:",
            f"    url: http://portal:8080/internal/hysteria/auth?token={token}",
            "    insecure: true",
            "",
            "trafficStats:",
            "  listen: 127.0.0.1:9090",
            f"  secret: {json.dumps(str(portal['hysteria_secret']))}",
        ])
    else:
        lines.extend(["auth:", "  type: userpass", "  userpass:"])
        for user in enabled_users(state):
            if "hysteria" not in user_systems(user):
                continue
            lines.append(f"    {user['name']}: {json.dumps(user['hysteria_password'])}")

    lines.extend(
        [
            "",
            "masquerade:",
            "  type: proxy",
            "  proxy:",
            "    url: https://www.apple.com/",
            "    rewriteHost: true",
            "",
            "quic:",
            "  initStreamReceiveWindow: 16777216",
            "  maxStreamReceiveWindow: 16777216",
            "  initConnReceiveWindow: 67108864",
            "  maxConnReceiveWindow: 67108864",
            "  maxIdleTimeout: 60s",
            "",
        ]
    )
    HY2_CONFIG.write_text("\n".join(lines), encoding="utf-8")


def telemt_config_text(state: dict) -> str:
    """Рендерит Telemt 3.4.24 без вывода ссылок/секретов в журнал."""
    server = state.get("server", "YOUR_SERVER_IP")
    telemt_cfg = state.get("telemt", {})
    tls_domain = system_sni(state, "telemt")
    local_site = mtproto_camouflage_origin(state, "telemt") == "local-site"
    access_users = dict(telemt_cfg.get("extra_users", {}))
    for user in enabled_users(state):
        if "telemt" not in user_systems(user):
            continue
        access_users[user["name"]] = user["telemt_secret"]

    lines = [
        "# Конфиг Telemt: отдельная реализация MTProto proxy.",
        "# Внешний порт 443 принимает nginx, поэтому Telemt слушает внутренний порт 3129.",
        "",
        "[general]",
        "use_middle_proxy = true",
        "me2dc_fallback = true",
        "me2dc_fast = true",
        "me_keepalive_enabled = true",
        "me_keepalive_interval_secs = 8",
        "me_keepalive_jitter_secs = 2",
        "me_keepalive_payload_random = true",
        "me_reconnect_backoff_base_ms = 500",
        "me_reconnect_backoff_cap_ms = 30000",
        'log_level = "normal"',
        'proxy_secret_path = "/tmp/telemt/proxy-secret"',
        'proxy_config_v4_cache_path = "/tmp/telemt/proxy-config-v4.txt"',
        'proxy_config_v6_cache_path = "/tmp/telemt/proxy-config-v6.txt"',
        'beobachten_file = "/tmp/telemt/beobachten.txt"',
        "",
        "[general.modes]",
        "classic = false",
        "secure = true",
        "tls = true",
        "",
        "[general.links]",
        "show = []",
        f"public_host = {json.dumps(server)}",
        "public_port = 443",
        "",
        "[server]",
        "port = 3129",
        "",
        "[server.api]",
        "enabled = true",
        'listen = "0.0.0.0:9091"',
        "whitelist = [",
        '  "127.0.0.1/32",',
        '  "172.16.0.0/12"',
        "]",
        "",
        "[[server.listeners]]",
        'ip = "0.0.0.0"',
        "",
        "[timeouts]",
        "client_handshake = 30",
        "client_first_byte_idle_secs = 300",
        "relay_idle_policy_v2_enabled = true",
        "relay_client_idle_soft_secs = 120",
        "relay_client_idle_hard_secs = 360",
        "relay_idle_grace_after_downstream_activity_secs = 30",
        "client_keepalive = 15",
        "client_ack = 90",
        "",
        "[censorship]",
        f"tls_domain = {json.dumps(tls_domain)}",
        'unknown_sni_action = "mask"',
        "mask = true",
        *( ['mask_host = "nginx"', "mask_port = 8443"] if local_site else [] ),
        "tls_emulation = true",
        "alpn_enforce = true",
        "mask_shape_hardening = true",
        "mask_shape_hardening_aggressive_mode = false",
        'tls_front_dir = "/tmp/telemt/tlsfront"',
        "",
        "[access]",
        "replay_check_len = 65536",
        "replay_window_secs = 120",
        "ignore_time_skew = false",
        "",
        "[access.users]",
    ]
    for name, secret in access_users.items():
        lines.append(f"{json.dumps(name)} = {json.dumps(secret)}")
    lines.append("")

    return "\n".join(lines)


def render_telemt(state: dict) -> None:
    TELEMT_CONFIG.write_text(telemt_config_text(state), encoding="utf-8")


def awg_obfuscation_lines(state: dict) -> list[str]:
    """Общие параметры маскировки AmneziaWG для сервера и клиентов."""
    obfs = awg_config(state).get("obfuscation", {})
    lines: list[str] = []
    for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"):
        value = obfs.get(key)
        if value is not None:
            lines.append(f"{key} = {value}")
    i1 = obfs.get("I1", "")
    if i1:
        lines.append(f"I1 = {i1}")
    return lines


def render_amneziawg(state: dict) -> None:
    """Пишет серверный конфиг AmneziaWG. Пользователи добавляются только если system=amneziawg."""
    cfg = awg_config(state)
    AMNEZIAWG_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    network = cfg.get("network", "10.66.66.0/24")
    iface = cfg.get("interface", "awg0")
    lines = [
        "# Конфиг AmneziaWG. Генерируется из users.json — не править вручную.",
        "[Interface]",
        f"PrivateKey = {cfg['private_key']}",
        f"Address = {cfg.get('server_address', '10.66.66.1/24')}",
        f"ListenPort = {int(cfg.get('port', 51820))}",
        f"MTU = {int(cfg.get('mtu', 1280))}",
        *awg_obfuscation_lines(state),
        f"PostUp = iptables -I INPUT 1 -p udp --dport {int(cfg.get('port', 51820))} -j ACCEPT; iptables -I FORWARD 1 -i {iface} -j ACCEPT; iptables -I FORWARD 1 -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -s {network} -o eth0 -j MASQUERADE",
        f"PostDown = iptables -D INPUT -p udp --dport {int(cfg.get('port', 51820))} -j ACCEPT; iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -s {network} -o eth0 -j MASQUERADE",
        "",
    ]
    for user in enabled_users(state):
        if "amneziawg" not in user_systems(user):
            continue
        awg_user = user.get("amneziawg", {})
        public_key = awg_user.get("public_key", "")
        address = awg_user.get("address", "")
        if not public_key or not address:
            continue
        lines.extend([
            "[Peer]",
            f"# {user['name']}",
            f"PublicKey = {public_key}",
            f"PresharedKey = {awg_user.get('preshared_key', '')}",
            f"AllowedIPs = {address}",
            "",
        ])
    AMNEZIAWG_CONFIG.write_text("\n".join(lines), encoding="utf-8")
    AMNEZIAWG_CONFIG.chmod(0o600)
    ok(f"amneziawg/{iface}.conf обновлён")


def render_wireguard(state: dict) -> None:
    """Пишет серверный конфиг стандартного WireGuard."""
    cfg = wireguard_config(state)
    WIREGUARD_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    network = cfg.get("network", "10.88.88.0/24")
    iface = cfg.get("interface", "wg0")
    port = int(cfg.get("port", 51821))
    lines = [
        "# Конфиг WireGuard. Генерируется из users.json — не править вручную.",
        "[Interface]",
        f"PrivateKey = {cfg['private_key']}",
        f"Address = {cfg.get('server_address', '10.88.88.1/24')}",
        f"ListenPort = {port}",
        f"MTU = {int(cfg.get('mtu', 1420))}",
        f"PostUp = iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT; iptables -I FORWARD 1 -i {iface} -j ACCEPT; iptables -I FORWARD 1 -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -s {network} -o eth0 -j MASQUERADE",
        f"PostDown = iptables -D INPUT -p udp --dport {port} -j ACCEPT; iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -s {network} -o eth0 -j MASQUERADE",
        "",
    ]
    for user in enabled_users(state):
        if "wireguard" not in user_systems(user):
            continue
        wg_user = user.get("wireguard", {})
        public_key = wg_user.get("public_key", "")
        address = wg_user.get("address", "")
        if not public_key or not address:
            continue
        lines.extend([
            "[Peer]",
            f"# {user['name']}",
            f"PublicKey = {public_key}",
            f"PresharedKey = {wg_user.get('preshared_key', '')}",
            f"AllowedIPs = {address}",
            "",
        ])
    WIREGUARD_CONFIG.write_text("\n".join(lines), encoding="utf-8")
    WIREGUARD_CONFIG.chmod(0o600)
    ok(f"wireguard/{iface}.conf обновлён")


def ocserv_conf_text(state: dict) -> str:
    cfg = ocserv_config(state)
    network = ipaddress.ip_network(cfg.get("network", "10.77.77.0/24"), strict=False)
    lines = [
        "# Конфиг ocserv/OpenConnect. Генерируется из users.json — не править вручную.",
        'auth = "plain[passwd=/run/ocserv/ocpasswd]"',
        "",
        "tcp-port = 443",
    ]
    if cfg.get("dtls_enabled", True):
        lines.extend([
            "# DTLS/UDP data-channel для скорости. 443/udp занят Hysteria2, поэтому используем отдельный порт.",
            f"udp-port = {cfg.get('udp_port', 4443)}",
            "",
        ])
    else:
        lines.extend([
            "# DTLS/UDP отключён: клиенты используют TCP fallback.",
            "# udp-port не задаётся.",
            "",
        ])
    lines.extend([
        "run-as-user = nobody",
        "run-as-group = nogroup",
        "device = vpns",
        "socket-file = /run/ocserv/ocserv.sock",
        "pid-file = /run/ocserv/ocserv.pid",
        "",
        "server-cert = /etc/ocserv/certs/server.crt",
        "server-key = /etc/ocserv/certs/server.key",
        "",
        f"max-clients = {cfg.get('max_clients', 64)}",
        f"max-same-clients = {cfg.get('max_same_clients', 3)}",
        "keepalive = 32400",
        "dpd = 90",
        "mobile-dpd = 1800",
        "switch-to-tcp-timeout = 25",
        "try-mtu-discovery = true",
        f"mtu = {cfg.get('mtu', 1400)}",
        "cisco-client-compat = true",
        "deny-roaming = false",
        "isolate-workers = false",
        'tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"',
        "",
        f"ipv4-network = {network.network_address}",
        f"ipv4-netmask = {network.netmask}",
        "# Full-tunnel для ocserv: route-строки не задаются.",
        "tunnel-all-dns = true",
        "ping-leases = false",
    ])
    for dns in cfg.get("dns", ["1.1.1.1", "8.8.8.8"]):
        lines.append(f"dns = {dns}")
    lines.append("")
    return "\n".join(lines)


def ocserv_users_text(state: dict) -> str:
    lines = [
        "# username:password для ocserv entrypoint. Генерируется из users.json — не править вручную.",
    ]
    for user in enabled_users(state):
        if "ocserv" not in user_systems(user):
            continue
        password = validate_ocserv_password(user.get("ocserv_password", ""))
        lines.append(f"{user['name']}:{password}")
    return "\n".join(lines) + "\n"


def render_ocserv(state: dict) -> None:
    cfg = ocserv_config(state)
    OCSERV_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    OCSERV_CONFIG.write_text(ocserv_conf_text(state), encoding="utf-8")
    OCSERV_USERS.write_text(ocserv_users_text(state), encoding="utf-8")
    OCSERV_ENV.write_text(f"OCSERV_NETWORK={cfg.get('network', '10.77.77.0/24')}\n", encoding="utf-8")
    OCSERV_USERS.chmod(0o600)
    ok("ocserv/ocserv.conf и ocserv/users.txt обновлены")


# ── Генерация клиентских ссылок ───────────────────────────────────────────


def vless_tls_link(state: dict, user: dict, port: int = 443, label_suffix: str = "TLS") -> str:
    sni = tls_client_sni(state, user)
    query = {
        "type": "tcp",
        "security": "tls",
        "encryption": "none",
        "flow": "xtls-rprx-vision",
        "sni": sni,
        "fp": "chrome",
    }
    # Xray 26.3.27+: allowInsecure удалён. Пин самоподписанного серта в share-link —
    # параметр pcs (pinnedPeerCertSha256), hex без двоеточий, иначе urlencode даст %3A.
    pin = certificate_sha256_hex(ROOT / "certs" / "server.crt")
    if pin:
        query["pcs"] = pin
    label = quote(f"KVN-{user['name']}-{label_suffix}")
    return f"vless://{user['uuid']}@{client_connection_host(state)}:{port}?{urlencode(query)}#{label}"


def vless_reality_link(state: dict, user: dict, public_key: str, port: int = 443, label_suffix: str = "Reality") -> str:
    sni = user_sni(user, "reality-xhttp", state)
    reality = state.get("reality", {})
    query = {
        "type": "xhttp",
        "security": "reality",
        "encryption": "none",
        "sni": sni,
        "fp": "chrome",
        "pbk": public_key,
        "sid": reality.get("short_id", "a3f9c1b82d4e6f90"),
        "path": REALITY_XHTTP_PATH,
        "mode": xhttp_mode(state),
    }
    label = quote(f"KVN-{user['name']}-{label_suffix}")
    return f"vless://{user['uuid']}@{client_connection_host(state)}:{port}?{urlencode(query)}#{label}"


def vless_reality_tcp_link(state: dict, user: dict, public_key: str, port: int = 443, label_suffix: str = "Reality-TCP") -> str:
    sni = user_sni(user, "reality-tcp", state)
    reality_tcp = state.get("reality_tcp", {})
    query = {
        "type": "tcp",
        "security": "reality",
        "encryption": "none",
        "sni": sni,
        "fp": "chrome",
        "pbk": reality_tcp.get("public_key", public_key),
        "sid": reality_tcp.get("short_id", "e7a4b2c91f5d8e30"),
        "flow": "xtls-rprx-vision",
    }
    label = quote(f"KVN-{user['name']}-{label_suffix}")
    return f"vless://{user['uuid']}@{client_connection_host(state)}:{port}?{urlencode(query)}#{label}"


def hysteria2_link(state: dict, user: dict) -> str:
    sni = user_sni(user, "hysteria", state)
    # Hysteria 2 userpass: auth-компонент должен быть "username:password",
    # поэтому двоеточие кодируем как часть userinfo.
    auth = quote(f"{user['name']}:{user['hysteria_password']}", safe="")
    query = {"sni": sni}
    pin = certificate_pin_sha256(ROOT / "hy2" / "certs" / "server.crt")
    if pin:
        # URI: непрерывный hex без двоеточий, иначе urlencode превращает их в %3A.
        query["pinSHA256"] = pin.replace(":", "")
    label = quote(f"KVN-{user['name']}-Hysteria2")
    return f"hysteria2://{auth}@{client_connection_host(state)}:443/?{urlencode(query)}#{label}"


def telemt_tls_secret(state: dict, user: dict) -> str:
    domain = system_sni(state, "telemt")
    return "ee" + user["telemt_secret"] + domain.encode("utf-8").hex()


def telemt_link(state: dict, user: dict, port: int = 443) -> str:
    query = {
        "server": client_connection_host(state),
        "port": str(port),
        "secret": telemt_tls_secret(state, user),
    }
    return f"tg://proxy?{urlencode(query)}"


def telemt_secure_link(state: dict, user: dict, port: int = DIRECT_PORTS["telemt"]) -> str:
    """Padded/secure (dd) link только для прямого порта без SNI-router."""
    query = {
        "server": client_connection_host(state),
        "port": str(port),
        "secret": "dd" + user["telemt_secret"],
    }
    return f"tg://proxy?{urlencode(query)}"


def write_optional_qr(payload: str, path: Path, label: str, username: str) -> None:
    if shutil.which("qrencode"):
        if not write_qr_png(payload, path):
            if path.exists():
                warn(f"не удалось обновить QR {label} для {username}; старый файл оставлен")
            else:
                warn(f"не удалось создать QR {label} для {username}")
    elif path.exists():
        warn(f"qrencode не найден — существующий QR {label} оставлен: {path}")
    else:
        warn(f"qrencode не найден — QR {label} не создан для {username}")


def hysteria_client_yaml(state: dict, user: dict) -> str:
    sni = user_sni(user, "hysteria", state)
    auth_value = f"{user['name']}:{user['hysteria_password']}"
    lines = [
        f"server: {client_connection_host(state)}:443",
        f"auth: {json.dumps(auth_value)}",
    ]
    tls_lines = ["tls:", f"  sni: {sni}"]
    pin_lines = hysteria_pin_yaml_lines()
    if pin_lines:
        tls_lines.extend(pin_lines)
    else:
        tls_lines.append("  insecure: true")
    lines.extend(
        [
            *tls_lines,
            "quic:",
            "  initStreamReceiveWindow: 16777216",
            "  maxStreamReceiveWindow: 16777216",
            "  initConnReceiveWindow: 67108864",
            "  maxConnReceiveWindow: 67108864",
            "  maxIdleTimeout: 60s",
            "",
        ]
    )
    return "\n".join(lines)


def amneziawg_client_conf(state: dict, user: dict) -> str:
    cfg = awg_config(state)
    awg_user = user.get("amneziawg", {})
    dns = cfg.get("dns", ["1.1.1.1", "8.8.8.8"])
    if isinstance(dns, str):
        dns_line = dns
    else:
        dns_line = ", ".join(str(item) for item in dns)
    lines = [
        "[Interface]",
        f"PrivateKey = {awg_user.get('private_key', '')}",
        f"Address = {awg_user.get('address', '')}",
        f"DNS = {dns_line}",
        f"MTU = {int(cfg.get('mtu', 1280))}",
        *awg_obfuscation_lines(state),
        "",
        "[Peer]",
        f"PublicKey = {cfg.get('public_key', '')}",
        f"PresharedKey = {awg_user.get('preshared_key', '')}",
        f"Endpoint = {client_connection_host(state)}:{int(cfg.get('port', 51820))}",
        f"AllowedIPs = {', '.join(awg_allowed_ips(state))}",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


def wireguard_client_conf(state: dict, user: dict) -> str:
    """Чистый WireGuard-конфиг для отдельной host-службы kvn-wireguard."""
    cfg = wireguard_config(state)
    wg_user = user.get("wireguard", {})
    dns = cfg.get("dns", ["1.1.1.1", "8.8.8.8"])
    dns_line = dns if isinstance(dns, str) else ", ".join(str(item) for item in dns)
    lines = [
        "# Стандартный WireGuard-профиль для отдельного сервиса KVN WireGuard.",
        "[Interface]",
        f"PrivateKey = {wg_user.get('private_key', '')}",
        f"Address = {wg_user.get('address', '')}",
        f"DNS = {dns_line}",
        f"MTU = {int(cfg.get('mtu', 1420))}",
        "",
        "[Peer]",
        f"PublicKey = {cfg.get('public_key', '')}",
        f"PresharedKey = {wg_user.get('preshared_key', '')}",
        f"Endpoint = {client_connection_host(state)}:{int(cfg.get('port', 51821))}",
        "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)


def karing_wireguard_yaml(state: dict, user: dict) -> str:
    """Clash-профиль стандартного WireGuard для импорта ссылкой в Karing."""
    cfg = wireguard_config(state)
    wg_user = user.get("wireguard", {})
    address = str(wg_user.get("address", ""))
    try:
        client_ip = str(ipaddress.ip_interface(address).ip)
    except ValueError:
        client_ip = address.split("/", 1)[0]
    name = f"KVN-{user['name']}-WireGuard"
    lines = [
        "# Karing/Clash: стандартный WireGuard через host-службу wg0, не AmneziaWG.",
        "proxies:",
        f"  - name: {json.dumps(name, ensure_ascii=False)}",
        "    type: wireguard",
        f"    server: {json.dumps(client_connection_host(state))}",
        f"    port: {int(cfg.get('port', 51821))}",
        f"    ip: {json.dumps(client_ip)}",
        f"    private-key: {json.dumps(str(wg_user.get('private_key', '')))}",
        f"    public-key: {json.dumps(str(cfg.get('public_key', '')))}",
        f"    pre-shared-key: {json.dumps(str(wg_user.get('preshared_key', '')))}",
        "    allowed-ips:",
        "      - \"0.0.0.0/0\"",
        "    udp: true",
        f"    mtu: {int(cfg.get('mtu', 1420))}",
        "    persistent-keepalive: 25",
        "proxy-groups:",
        "  - name: \"KVN\"",
        "    type: select",
        "    proxies:",
        f"      - {json.dumps(name, ensure_ascii=False)}",
        "rules:",
        "  - \"MATCH,KVN\"",
        "",
    ]
    return "\n".join(lines)


def openconnect_client_text(state: dict, user: dict) -> str:
    oc_cfg = ocserv_config(state)
    password = validate_ocserv_password(user.get("ocserv_password", ""))
    pin = certificate_sha256_hex(OCSERV_CERTS_DIR / "server.crt")
    policy = ClientExportPolicy.from_state(state)
    ip_export = policy.address_mode == "public-ip"
    connection_host = client_connection_host(state, policy)
    server_ip = connection_host if ip_export else state.get("server", "")
    if not ip_export and not re.match(r"^\d+\.\d+\.\d+\.\d+$", server_ip):
        geo_ip = state.get("server_geo", {}).get("ip", "")
        server_ip = geo_ip if re.match(r"^\d+\.\d+\.\d+\.\d+$", geo_ip) else ""
    host = (
        connection_host
        if ip_export
        else (
            ocserv_sni(state)
            if oc_cfg.get("sni_enabled")
            else (server_ip or state.get("server", "YOUR_SERVER_DOMAIN"))
        )
    )
    port = ocserv_public_tcp_port(state)
    main_command = f"openconnect --protocol=anyconnect --user={user['name']}"
    if ip_export and oc_cfg.get("sni_enabled"):
        main_command += f" --sni={ocserv_sni(state)}"
    if ip_export and pin:
        main_command += f" --servercert=sha256:{pin}"
    main_command += f" https://{host}:{port}/"
    lines = [
        "OpenConnect / Cisco AnyConnect",
        f"Server: https://{host}:{port}/",
        f"Username: {user['name']}",
        f"Password: {password}",
        f"DTLS/UDP: {'enabled on UDP ' + str(oc_cfg.get('udp_port', 4443)) if oc_cfg.get('dtls_enabled', True) else 'disabled'}",
        "",
        "CLI:",
        main_command,
    ]
    if oc_cfg.get("sni_enabled") and ocserv_front_snis(state):
        lines.extend([
            "",
            "Дополнительные адреса:",
        ])
        for front_sni in ocserv_front_snis(state):
            lines.append(f"https://{front_sni}:{port}/")
    direct_host = (
        connection_host
        if ip_export
        else (
            ocserv_sni(state)
            if oc_cfg.get("sni_enabled")
            else state.get("server", "YOUR_SERVER_DOMAIN")
        )
    )
    direct_command = (
        f"openconnect --protocol=anyconnect --user={user['name']} "
        f"https://{direct_host}:{DIRECT_PORTS['ocserv']}/"
    )
    if pin:
        sni_option = (
            f"--sni={ocserv_sni(state)} "
            if ip_export and oc_cfg.get("sni_enabled")
            else ""
        )
        direct_command = (
            f"openconnect --protocol=anyconnect --user={user['name']} "
            f"{sni_option}--servercert=sha256:{pin} "
            f"https://{direct_host}:{DIRECT_PORTS['ocserv']}/"
        )
    lines.extend([
        "",
        "Прямой резерв без nginx:",
        f"https://{direct_host}:{DIRECT_PORTS['ocserv']}/",
        direct_command,
    ])
    if server_ip and not oc_cfg.get("sni_enabled") and host != server_ip:
        command = f"openconnect --protocol=anyconnect --user={user['name']}"
        if pin:
            command += f" --servercert=sha256:{pin}"
        command += f" https://{server_ip}:{port}/"
        lines.extend([
            "",
            "CLI по IP (сертификат фиксируется pin):",
            command,
        ])
    front_snis = [] if oc_cfg.get("sni_enabled") else ocserv_front_snis(state)
    if front_snis:
        lines.extend([
            "",
            "CLI с front SNI для теста DPI:",
        ])
        for front_sni in front_snis:
            if server_ip:
                command = (
                    f"openconnect --protocol=anyconnect --user={user['name']} "
                    f"--resolve={front_sni}:{server_ip}"
                )
                if pin:
                    command += f" --servercert=sha256:{pin}"
                command += f" https://{front_sni}:{port}/"
                lines.append(command)
            command = f"openconnect --protocol=anyconnect --user={user['name']} --sni={front_sni}"
            if pin:
                command += f" --servercert=sha256:{pin}"
            command += f" https://{host}:{port}/"
            lines.append(command)
        lines.extend([
            "",
            "Первый вариант с --resolve делает и SNI, и HTTP Host фронтовым доменом; второй вариант меняет только SNI.",
            "Front SNI требует OpenConnect с поддержкой --sni/--resolve; Cisco AnyConnect GUI обычно так не умеет.",
            "Для 360.yandex.com/disk используется только SNI host 360.yandex.com; URL path /disk/ в TLS не виден.",
        ])
    lines.extend([
        "",
        (
            f"Примечание: OpenConnect TCP доступен на {port}/tcp через отдельный SNI-домен ocserv."
            if oc_cfg.get("sni_enabled")
            else f"Примечание: OpenConnect TCP доступен на {port}/tcp через nginx default/no-SNI route; основной домен сайта остаётся на 443/tcp."
        ),
        "Для нормальной скорости должен быть открыт UDP-порт DTLS; иначе клиент работает в медленном TCP fallback.",
    ])
    return "\n".join(lines)


def write_qr_png(text: str, path: Path) -> bool:
    """Пишет PNG QR через qrencode, не портя старый файл при ошибке."""
    if not shutil.which("qrencode"):
        return False
    tmp_path = path.with_name(f".{path.name}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", str(tmp_path), "-m", "2"],
            input=text,
            text=True,
            encoding="utf-8",
            cwd=ROOT,
            check=False,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0 or not tmp_path.exists() or tmp_path.stat().st_size == 0:
            return False
        tmp_path.replace(path)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass


def terminal_qr(text: str) -> str:
    """Возвращает QR для терминала через qrencode ANSIUTF8."""
    if not shutil.which("qrencode"):
        return ""
    try:
        result = subprocess.run(
            ["qrencode", "-t", "ANSIUTF8", "-m", "1"],
            input=text,
            text=True,
            encoding="utf-8",
            cwd=ROOT,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


def client_json_tls(state: dict, user: dict, port: int = 443, remarks_suffix: str = "VLESS TLS Vision") -> dict:
    sni = tls_client_sni(state, user)
    cert_path = ROOT / "certs" / "server.crt"
    pin = certificate_sha256_hex(cert_path)

    tls_settings: dict = {"serverName": sni, "fingerprint": "chrome"}
    if pin:
        # Xray 26.3.27+: allowInsecure удалён, pinning самоподписанного серта обязателен.
        # Поле — pinnedPeerCertSha256 (строка, hex), НЕ pinnedPeerCertChainSha256 и НЕ список.
        tls_settings["pinnedPeerCertSha256"] = pin
    else:
        warn(f"Сертификат certs/server.crt не найден — клиентский JSON для TLS не будет работать в Xray 26.3.27+")

    return {
        "remarks": f"KVN {user['name']} {remarks_suffix}",
        "vnext": [
            {
                "address": client_connection_host(state),
                "port": port,
                "users": [
                    {
                        "id": user["uuid"],
                        "flow": "xtls-rprx-vision",
                        "encryption": "none",
                    }
                ],
            }
        ],
        "streamSettings": {
            "network": "raw",
            "security": "tls",
            "tlsSettings": tls_settings,
        },
    }


def client_json_reality(state: dict, user: dict, public_key: str, port: int = 443, remarks_suffix: str = "Reality xHTTP") -> dict:
    sni = user_sni(user, "reality-xhttp", state)
    reality = state.get("reality", {})
    return {
        "remarks": f"KVN {user['name']} {remarks_suffix}",
        "vnext": [
            {
                "address": client_connection_host(state),
                "port": port,
                "users": [{"id": user["uuid"], "encryption": "none"}],
            }
        ],
        "streamSettings": {
            "network": "xhttp",
            "security": "reality",
            "realitySettings": {
                "serverName": sni,
                "fingerprint": "chrome",
                "publicKey": public_key,
                "shortId": reality.get("short_id", "a3f9c1b82d4e6f90"),
            },
            "xhttpSettings": {"path": REALITY_XHTTP_PATH, "mode": xhttp_mode(state)},
        },
    }


def client_json_reality_tcp(state: dict, user: dict, public_key: str, port: int = 443, remarks_suffix: str = "Reality TCP Vision") -> dict:
    sni = user_sni(user, "reality-tcp", state)
    reality_tcp = state.get("reality_tcp", {})
    return {
        "remarks": f"KVN {user['name']} {remarks_suffix}",
        "vnext": [
            {
                "address": client_connection_host(state),
                "port": port,
                "users": [
                    {
                        "id": user["uuid"],
                        "encryption": "none",
                        "flow": "xtls-rprx-vision",
                    }
                ],
            }
        ],
        "streamSettings": {
            "network": "raw",
            "security": "reality",
            "realitySettings": {
                "serverName": sni,
                "fingerprint": "chrome",
                "publicKey": reality_tcp.get("public_key", public_key),
                "shortId": reality_tcp.get("short_id", "e7a4b2c91f5d8e30"),
            },
        },
    }


def xray_hysteria2_json(state: dict, user: dict) -> dict:
    """Полный Xray JSON конфиг для Hysteria2 (Xray 26.3.27+).
    pinnedPeerCertSha256 обязателен для самоподписанного серта (allowInsecure удалён)."""
    sni = user_sni(user, "hysteria", state)
    pin = certificate_sha256_hex(ROOT / "hy2" / "certs" / "server.crt")

    tls_settings = {"serverName": sni}
    if pin:
        tls_settings["pinnedPeerCertSha256"] = pin
    # allowInsecure НЕ указываем — удалён в Xray 26.3.27

    server = {
        "address": client_connection_host(state),
        "port": 443,
        "password": f"{user['name']}:{user['hysteria_password']}",
        "tls": tls_settings,
    }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"port": 10808, "protocol": "socks", "settings": {"udp": True}, "tag": "socks-in"}
        ],
        "outbounds": [
            {"tag": "proxy", "protocol": "hysteria2", "settings": {"servers": [server]}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "outboundTag": "block", "ip": ["geoip:private"]},
                {"type": "field", "outboundTag": "direct", "domain": ["geosite:cn", "geosite:apple-cn", "geosite:google-cn"]},
            ],
        },
    }


def singbox_subscription(state: dict, user: dict, public_key: str) -> dict:
    """sing-box JSON subscription.

    Main order mirrors the URL subscription: Hysteria2, Reality TCP,
    then Reality xHTTP. VLESS TLS remains in diagnostic exports because this
    profile is fragile under DPI; its SNI stays on the per-user routed TLS SNI,
    while the Let's Encrypt SNI is reserved for the website.
    """
    outbounds: list[dict] = []
    systems = user_systems(user)
    server = client_connection_host(state)

    if "hysteria" in systems:
        sni = user_sni(user, "hysteria", state)
        outbounds.append({
            "tag": "Hysteria2",
            "type": "hysteria2",
            "server": server,
            "server_port": 443,
            "password": f"{user['name']}:{user['hysteria_password']}",
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": True,
            },
        })

    if "reality-tcp" in systems:
        sni = user_sni(user, "reality-tcp", state)
        reality_tcp = state.get("reality_tcp", {})
        base = {
            "type": "vless",
            "server": server,
            "server_port": 443,
            "uuid": user["uuid"],
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": sni,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": reality_tcp.get("public_key", public_key),
                    "short_id": reality_tcp.get("short_id", ""),
                },
            },
        }
        outbounds.append({"tag": "Reality-TCP", **base})
        direct = copy.deepcopy(base)
        direct["server_port"] = DIRECT_PORTS["reality-tcp"]
        outbounds.append({"tag": "Reality-TCP-direct", **direct})

    if "reality-xhttp" in systems:
        sni = user_sni(user, "reality-xhttp", state)
        reality = state.get("reality", {})
        base = {
            "type": "vless",
            "server": server,
            "server_port": 443,
            "uuid": user["uuid"],
            "tls": {
                "enabled": True,
                "server_name": sni,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": public_key,
                    "short_id": reality.get("short_id", ""),
                },
            },
            "transport": {
                "type": "xhttp",
                "path": "/api/v1/data",
                "mode": xhttp_mode(state),
            },
        }
        outbounds.append({"tag": "Reality-xHTTP", **base})
        direct = copy.deepcopy(base)
        direct["server_port"] = DIRECT_PORTS["reality-xhttp"]
        outbounds.append({"tag": "Reality-xHTTP-direct", **direct})

    ocserv_claims_le_sni = (
        ocserv_config(state).get("enabled")
        and ocserv_sni(state)
        and ocserv_sni(state) == letsencrypt_domain(state)
    )
    if "tls" in systems and not ocserv_claims_le_sni:
        sni = tls_client_sni(state, user)
        base = {
            "type": "vless",
            "server": server,
            "server_port": 443,
            "uuid": user["uuid"],
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": sni,
                "insecure": True,
                "utls": {"enabled": True, "fingerprint": "chrome"},
            },
        }
        outbounds.append({"tag": "VLESS-TLS", **base})
        direct = copy.deepcopy(base)
        direct["server_port"] = DIRECT_PORTS["tls"]
        outbounds.append({"tag": "VLESS-TLS-direct", **direct})

    preferred_final = next(
        (
            tag for tag in ("Hysteria2", "Reality-TCP", "Reality-xHTTP", "VLESS-TLS")
            if any(outbound.get("tag") == tag for outbound in outbounds)
        ),
        (outbounds[0]["tag"] if outbounds else "direct"),
    )

    return {
        "log": {"level": "warn"},
        "outbounds": outbounds,
        "route": {"final": preferred_final},
    }


def preferred_uri_systems(systems: list[str]) -> list[str]:
    """Исторический порядок URI для старого endpoint подписки.

    Функция и порядок сохранены для byte-compatible legacy payload. Telemt/mtg
    работают только в Telegram.
    VLESS TLS оставляем последним: профиль часто режется DPI, но нужен в URL-
    подписке для общей картины и ручной проверки.
    """
    preferred = ["hysteria", "reality-tcp", "reality-xhttp", "tls"]
    return [system for system in preferred if system in systems]


def happ_uri_systems(systems: list[str]) -> list[str]:
    """Поддерживаемые URI HAPP в детерминированном порядке."""
    return preferred_uri_systems(systems)


def karing_uri_systems(systems: list[str]) -> list[str]:
    """Поддерживаемые URI актуального Karing в детерминированном порядке.

    xHTTP поддерживается актуальными версиями Karing. Стандартный WireGuard
    выдаётся отдельным Clash-профилем, а AmneziaWG сюда намеренно не попадает:
    его параметры маскировки не являются WireGuard.
    """
    return preferred_uri_systems(systems)


def all_uri_systems(systems: list[str]) -> list[str]:
    """Все URI-профили для ручной диагностики, включая спорные для HAPP/Karing."""
    preferred = ["hysteria", "reality-tcp", "reality-xhttp", "tls"]
    return [system for system in preferred if system in systems]


def uri_list_for_systems(state: dict, user: dict, public_key: str, systems: list[str], direct: bool = False) -> list[str]:
    uris: list[str] = []
    for system in systems:
        if system == "hysteria":
            if not direct:
                uris.append(hysteria2_link(state, user))
        elif system == "reality-tcp":
            port = DIRECT_PORTS["reality-tcp"] if direct else 443
            suffix = "Reality-TCP-direct" if direct else "Reality-TCP"
            uris.append(vless_reality_tcp_link(state, user, public_key, port=port, label_suffix=suffix))
        elif system == "reality-xhttp":
            port = DIRECT_PORTS["reality-xhttp"] if direct else 443
            suffix = "Reality-direct" if direct else "Reality"
            uris.append(vless_reality_link(state, user, public_key, port=port, label_suffix=suffix))
        elif system == "tls":
            port = DIRECT_PORTS["tls"] if direct else 443
            suffix = "TLS-direct" if direct else "TLS"
            uris.append(vless_tls_link(state, user, port=port, label_suffix=suffix))
    return uris


def direct_uri_list_for_user(state: dict, user: dict, public_key: str) -> list[str]:
    """URI-профили, которые обходят nginx и идут на опубликованные прямые TCP-порты."""
    systems = user_systems(user)
    direct_systems = [system for system in ["reality-tcp", "reality-xhttp", "tls"] if system in systems]
    return uri_list_for_systems(state, user, public_key, direct_systems, direct=True)


def encoded_uri_subscription(state: dict, user: dict, public_key: str, systems: list[str]) -> str:
    """Кодирует детерминированный список URI в совместимый base64 payload."""
    uris = uri_list_for_systems(state, user, public_key, systems)
    payload = "\n".join(uris) + "\n"
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def legacy_subscription_txt(state: dict, user: dict, public_key: str) -> str:
    """Старый payload /<token>; формат и порядок менять нельзя."""
    systems = user_systems(user)
    return encoded_uri_subscription(state, user, public_key, preferred_uri_systems(systems))


def subscription_txt(state: dict, user: dict, public_key: str) -> str:
    """Совместимое имя старого base64 payload."""
    return legacy_subscription_txt(state, user, public_key)


def happ_subscription_txt(state: dict, user: dict, public_key: str) -> str:
    """Отдельный HAPP payload."""
    systems = user_systems(user)
    return encoded_uri_subscription(state, user, public_key, happ_uri_systems(systems))


def karing_subscription_txt(state: dict, user: dict, public_key: str) -> str:
    """Отдельный Karing URI payload без AmneziaWG."""
    systems = user_systems(user)
    return encoded_uri_subscription(state, user, public_key, karing_uri_systems(systems))


def subscription_raw_txt(state: dict, user: dict, public_key: str) -> str:
    """Plain-text URI list, совпадает со старым endpoint до base64."""
    systems = user_systems(user)
    uris = uri_list_for_systems(state, user, public_key, preferred_uri_systems(systems))
    return "\n".join(uris) + "\n"


def subscription_raw_all_txt(state: dict, user: dict, public_key: str) -> str:
    """Plain-text список всех URI для ручной диагностики."""
    systems = user_systems(user)
    uris = uri_list_for_systems(state, user, public_key, all_uri_systems(systems))
    direct_uris = direct_uri_list_for_user(state, user, public_key)
    if direct_uris:
        uris.extend(direct_uris)
    return "\n".join(uris) + "\n"


def ready_ip_subscription_host(state: dict) -> str:
    """Возвращает IP для URL подписки только после route + IP SAN gate."""
    policy = ClientExportPolicy.from_state(state)
    if policy.address_mode != "public-ip":
        return ""
    cfg = sub_config(state)
    connection_host = client_connection_host(state, policy)
    routed_hosts = (
        (connection_host,)
        if cfg.get("enabled", True) and int(cfg.get("port", DEFAULT_SUB_PORT)) > 0
        else ()
    )
    readiness = subscription_ip_readiness(
        state,
        routed_hosts=routed_hosts,
        certificate_ip_sans=certificate_sans(SITE_CERTS_DIR / "server.crt"),
    )
    return connection_host if readiness.ready else ""


def sub_url(state: dict, user: dict) -> str:
    """Старый основной URL /<token>, сохранённый для существующих клиентов."""
    cfg = sub_config(state)
    token = user.get("sub_token", "")
    if ready_ip_subscription_host(state):
        return legacy_sub_url(state, user)
    public_host = cfg.get("public_host", "")
    if public_host:
        public_port = int(cfg.get("public_port", 443))
        port_part = "" if public_port == 443 else f":{public_port}"
        return f"https://{public_host}{port_part}/{token}"
    return legacy_sub_url(state, user)


def legacy_sub_url(state: dict, user: dict) -> str:
    """Прямой URL подписки через опубликованный порт nginx."""
    cfg = sub_config(state)
    port = cfg.get("port", DEFAULT_SUB_PORT)
    server = ready_ip_subscription_host(state) or state.get("server", "YOUR_SERVER_IP")
    return f"https://{server}:{port}/{user.get('sub_token', '')}"


def named_sub_url(state: dict, user: dict, profile: str, *, direct: bool = False) -> str:
    """URL именованного профиля через public host или резервный порт 2096."""
    if profile not in {"happ", "karing", "karing-wg"}:
        raise ValueError("unknown subscription profile")
    cfg = sub_config(state)
    token = user.get("sub_token", "")
    ip_host = ready_ip_subscription_host(state)
    if ip_host:
        return f"https://{ip_host}:{cfg.get('port', DEFAULT_SUB_PORT)}/{profile}/{token}"
    if not direct and cfg.get("public_host"):
        public_port = int(cfg.get("public_port", 443))
        port_part = "" if public_port == 443 else f":{public_port}"
        return f"https://{cfg['public_host']}{port_part}/{profile}/{token}"
    server = state.get("server", "YOUR_SERVER_IP")
    return f"https://{server}:{cfg.get('port', DEFAULT_SUB_PORT)}/{profile}/{token}"


def happ_sub_url(state: dict, user: dict) -> str:
    return named_sub_url(state, user, "happ")


def karing_sub_url(state: dict, user: dict) -> str:
    return named_sub_url(state, user, "karing")


def karing_wireguard_sub_url(state: dict, user: dict) -> str:
    return named_sub_url(state, user, "karing-wg")


def named_sub_urls(state: dict, user: dict, profile: str) -> list[str]:
    """Публичный и прямой URL именованного профиля без дублей."""
    urls: list[str] = []
    for url in (named_sub_url(state, user, profile), named_sub_url(state, user, profile, direct=True)):
        if url not in urls:
            urls.append(url)
    return urls


def sub_urls(state: dict, user: dict) -> list[str]:
    """Все URL подписки: основной публичный и резервный прямой, без дублей."""
    urls: list[str] = []
    for url in (sub_url(state, user), legacy_sub_url(state, user)):
        if url and url not in urls:
            urls.append(url)
    return urls


def write_sub_web(state: dict, public_key: str) -> None:
    """Пишет legacy и именованные профили в закрытые token endpoints."""
    cfg = sub_config(state)
    managed_profiles = ("happ", "karing", "karing-wg")

    def remove_managed_files() -> None:
        if not SUB_WEB_DIR.exists():
            return
        for item in SUB_WEB_DIR.iterdir():
            if item.is_file() and re.fullmatch(r"[0-9a-f]{32}", item.name):
                item.unlink()
        for profile in managed_profiles:
            profile_dir = SUB_WEB_DIR / profile
            if not profile_dir.is_dir():
                continue
            for item in profile_dir.iterdir():
                if item.is_file() and re.fullmatch(r"[0-9a-f]{32}", item.name):
                    item.unlink()

    if not cfg.get("enabled", True):
        remove_managed_files()
        return

    SUB_WEB_DIR.mkdir(parents=True, exist_ok=True)
    for profile in managed_profiles:
        (SUB_WEB_DIR / profile).mkdir(exist_ok=True)
    valid_tokens: set[str] = set()
    valid_wireguard_tokens: set[str] = set()
    for user in enabled_users(state):
        token = validate_subscription_token(user.get("sub_token", ""))
        if not token:
            continue
        (SUB_WEB_DIR / token).write_text(
            legacy_subscription_txt(state, user, public_key),
            encoding="utf-8",
        )
        (SUB_WEB_DIR / "happ" / token).write_text(
            happ_subscription_txt(state, user, public_key), encoding="utf-8"
        )
        (SUB_WEB_DIR / "karing" / token).write_text(
            karing_subscription_txt(state, user, public_key), encoding="utf-8"
        )
        valid_tokens.add(token)
        if "wireguard" in user_systems(user):
            (SUB_WEB_DIR / "karing-wg" / token).write_text(
                karing_wireguard_yaml(state, user), encoding="utf-8"
            )
            valid_wireguard_tokens.add(token)

    # Удаляем только управляемые token-файлы удалённых/отключённых пользователей.
    for item in SUB_WEB_DIR.iterdir():
        if item.is_file() and re.fullmatch(r"[0-9a-f]{32}", item.name) and item.name not in valid_tokens:
            item.unlink()
    for profile in ("happ", "karing"):
        for item in (SUB_WEB_DIR / profile).iterdir():
            if item.is_file() and re.fullmatch(r"[0-9a-f]{32}", item.name) and item.name not in valid_tokens:
                item.unlink()
    for item in (SUB_WEB_DIR / "karing-wg").iterdir():
        if item.is_file() and re.fullmatch(r"[0-9a-f]{32}", item.name) and item.name not in valid_wireguard_tokens:
            item.unlink()


def _user_export_markdown_source(state: dict, user: dict, public_key: str) -> str:
    systems = user_systems(user)
    lines = [f"# {user['name']}", ""]

    if "tls" in systems:
        lines.extend([
            "## VLESS TLS Vision",
            vless_tls_link(state, user),
            f"Прямой резерв без nginx ({DIRECT_PORTS['tls']}/tcp):",
            vless_tls_link(state, user, port=DIRECT_PORTS["tls"], label_suffix="TLS-direct"),
            "ℹ️ Пин серта зашит в ссылку (pcs). Если клиент его не понимает — импортируйте `xray-vless-tls.json`",
            "",
        ])
    if "reality-xhttp" in systems:
        lines.extend([
            "## Reality xHTTP",
            vless_reality_link(state, user, public_key),
            f"Прямой резерв без nginx ({DIRECT_PORTS['reality-xhttp']}/tcp):",
            vless_reality_link(state, user, public_key, port=DIRECT_PORTS["reality-xhttp"], label_suffix="Reality-direct"),
            "",
        ])
    if "reality-tcp" in systems:
        lines.extend([
            "## Reality TCP Vision (низкая задержка)",
            vless_reality_tcp_link(state, user, public_key),
            f"Прямой резерв без nginx ({DIRECT_PORTS['reality-tcp']}/tcp):",
            vless_reality_tcp_link(state, user, public_key, port=DIRECT_PORTS["reality-tcp"], label_suffix="Reality-TCP-direct"),
            "",
        ])
    if "hysteria" in systems:
        lines.extend([
            "## Hysteria 2",
            hysteria2_link(state, user),
            "⚠️ Xray 26.3.27+: URI не работает с самоподписанным сертом. Используйте `xray-hysteria2.json`",
            "",
        ])
    if "amneziawg" in systems:
        lines.extend([
            "## AmneziaWG app",
            "Импортируйте этот конфиг только в AmneziaVPN/AmneziaWG app:",
            "QR-файл: `amneziawg.png`",
            "```ini",
            amneziawg_client_conf(state, user).rstrip(),
            "```",
            "",
        ])
    if "wireguard" in systems:
        lines.extend([
            "## WireGuard standard",
            "Импортируйте этот конфиг в официальный WireGuard-клиент:",
            "QR-файл: `wireguard.png`",
            "Для Karing используйте отдельную ссылку `karing-wireguard.txt`.",
            "```ini",
            wireguard_client_conf(state, user).rstrip(),
            "```",
            "",
        ])
    if "ocserv" in systems:
        lines.extend([
            "## OpenConnect / Cisco AnyConnect (ocserv)",
            "Импорт в HAPP/Karing не поддерживается; используйте OpenConnect или Cisco AnyConnect.",
            "```text",
            openconnect_client_text(state, user),
            "```",
            "",
        ])
    if "telemt" in systems:
        lines.extend([
            "## Telemt MTProto TLS",
            telemt_link(state, user),
            f"Прямой резерв без nginx ({DIRECT_PORTS['telemt']}/tcp):",
            telemt_link(state, user, port=DIRECT_PORTS["telemt"]),
            f"secret: {telemt_tls_secret(state, user)}",
            "",
        ])
    if "mtg" in systems:
        lines.extend([
            "## MTProto (mtg, общий для всех)",
            mtg_link(state),
            f"Прямой резерв без nginx ({DIRECT_PORTS['mtg']}/tcp):",
            mtg_link(state, port=DIRECT_PORTS["mtg"]),
            "",
        ])

    if sub_config(state).get("enabled", True):
        lines.extend([
            "## Подписка HAPP (для self-signed сертификата включить insecure)",
            *named_sub_urls(state, user, "happ"),
            "",
            "## Подписка Karing (Reality xHTTP/TCP, Hysteria2, VLESS TLS)",
            *named_sub_urls(state, user, "karing"),
            "",
        ])
        if "wireguard" in systems:
            lines.extend([
                "## Karing — стандартный WireGuard (Clash profile, wg0/51821)",
                *named_sub_urls(state, user, "karing-wg"),
                "",
            ])
        lines.extend([
            "## Legacy endpoint (не менять у уже подключённых клиентов)",
            *sub_urls(state, user),
            "",
        ])

    lines.extend([
        "## Подписка",
        "- `subscription.json` — sing-box: Hysteria2 + Reality TCP + Reality xHTTP + VLESS TLS",
        "- `subscription.txt` — legacy base64 URI list для старых клиентов",
        "- `subscription-raw.txt` — legacy raw URI list",
        "- `happ-subscription.txt` / `karing-subscription.txt` — отдельные URL клиентов",
        "- `karing-wireguard.yaml` — стандартный WireGuard Clash-профиль для Karing",
        "- `subscription-raw-all.txt` — все URI, включая прямые резервы 2443-2445",
        "",
    ])

    return "\n".join(lines)


def user_export_sections(
    state: dict,
    user: dict,
    public_key: str,
) -> tuple[ExportSection, ...]:
    """Строит единые structured sections для файлов, CLI и портала."""
    source = _user_export_markdown_source(state, user, public_key)
    sections: list[ExportSection] = []
    title = ""
    body: list[str] = []

    def append_section() -> None:
        if not title:
            return
        while body and not body[-1]:
            body.pop()
        markdown_lines = tuple(body)
        plain_lines = tuple(
            line.replace("`", "")
            for line in body
            if not line.startswith("```")
        )
        sections.append(
            ExportSection(
                key=re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-"),
                title=title,
                lines=plain_lines,
                markdown_lines=markdown_lines,
            )
        )

    for line in source.splitlines()[2:]:
        if line.startswith("## "):
            append_section()
            title = line[3:]
            body = []
        else:
            body.append(line)
    append_section()
    return tuple(sections)


def user_links_text(state: dict, user: dict, public_key: str) -> str:
    """Markdown export из общего набора structured sections."""
    return render_export_document(
        user["name"],
        user_export_sections(state, user, public_key),
        markdown=True,
    )


def telemt_client_text(state: dict, user: dict) -> str:
    """Текстовые параметры Telemt для ручного добавления MTProto в Telegram."""
    return "\n".join([
        "Telemt MTProto TLS",
        f"link: {telemt_link(state, user)}",
        f"direct {DIRECT_PORTS['telemt']}/tcp: {telemt_link(state, user, port=DIRECT_PORTS['telemt'])}",
        f"direct secure/padded {DIRECT_PORTS['telemt']}/tcp: {telemt_secure_link(state, user)}",
        f"server: {client_connection_host(state)}",
        "port: 443",
        f"direct_port: {DIRECT_PORTS['telemt']}",
        f"sni: {system_sni(state, 'telemt')}",
        f"secret: {telemt_tls_secret(state, user)}",
        "",
    ])


def mtg_client_text(state: dict) -> str:
    """Текстовые параметры mtg FakeTLS для ручного добавления MTProto в Telegram."""
    return "\n".join([
        "MTProto mtg FakeTLS — общий endpoint/secret для всех, без user attribution",
        f"link: {mtg_link(state)}",
        f"direct {DIRECT_PORTS['mtg']}/tcp: {mtg_link(state, port=DIRECT_PORTS['mtg'])}",
        f"server: {client_connection_host(state)}",
        "port: 443",
        f"direct_port: {DIRECT_PORTS['mtg']}",
        f"sni: {mtg_domain(state)}",
        f"secret: {mtg_faketls_secret(state)}",
        "",
    ])


def telegram_proxy_text(state: dict, user: dict) -> str:
    """Сводка Telegram-прокси, доступных пользователю."""
    systems = user_systems(user)
    blocks: list[str] = []
    if "telemt" in systems:
        blocks.append(telemt_client_text(state, user).rstrip())
    if "mtg" in systems:
        blocks.append(mtg_client_text(state).rstrip())
    return "\n\n".join(blocks) + ("\n" if blocks else "")


def user_send_text(state: dict, user: dict, public_key: str) -> str:
    """Текст для отправки из того же structured export, что links/manifest."""
    return serialize_user_export(
        username=user["name"],
        connection_host=client_connection_host(state),
        sections=user_export_sections(state, user, public_key),
        output_format="text",
    )


def client_links_markdown(state: dict, public_key: str) -> str:
    connection_host = client_connection_host(state)
    lines = [
        "# Актуальные ссылки для подключения",
        "",
        f"Адрес подключения: `{connection_host}`",
        "",
        "Файл генерируется автоматически из `users.json` командой `python3 tools/kvnctl.py render`.",
        "Не редактируйте ссылки вручную: при добавлении пользователя файл будет перезаписан.",
        "",
    ]
    if connection_host == "YOUR_SERVER_IP":
        lines.extend([
            "> Внимание: сейчас используется placeholder `YOUR_SERVER_IP`.",
            "> Перед выдачей ссылок выполните `./setup.sh REAL_SERVER_IP` или `python3 tools/kvnctl.py render --server REAL_SERVER_IP`.",
            "",
        ])

    for user in enabled_users(state):
        desc = user.get("description", "")
        title = user["name"] + (f" — {desc}" if desc else "")
        lines.append(
            render_export_document(
                title,
                user_export_sections(state, user, public_key),
                markdown=True,
                title_level=2,
            )
        )

    return "\n".join(lines)


def mtg_domain(state: dict) -> str:
    """FakeTLS-домен mtg (берётся из sni_routes.mtg.default)."""
    return validate_sni_domain(system_sni(state, "mtg") or "ya.ru")


def mtg_faketls_secret(state: dict) -> str:
    """Секрет mtg в формате FakeTLS: ee + 16 байт (32 hex) + hex(домен)."""
    secret16 = state.get("mtg", {}).get("secret16", "")
    if not secret16:
        return ""
    return "ee" + secret16 + mtg_domain(state).encode("utf-8").hex()


def mtg_link(state: dict, port: int = 443) -> str:
    """tg:// ссылка на mtg. Секрет общий для всех (mtg v2 = один секрет)."""
    secret = mtg_faketls_secret(state)
    if not secret:
        return "# mtg: секрет не настроен (запустите render)"
    query = {
        "server": client_connection_host(state),
        "port": str(port),
        "secret": secret,
    }
    return f"tg://proxy?{urlencode(query)}"


def certificate_name_matches(hostname: str, sans: list[str]) -> bool:
    """Минимальная RFC-совместимая проверка exact и одноуровневого wildcard SAN."""
    hostname = hostname.lower().rstrip(".")
    for san in sans:
        candidate = str(san).lower().rstrip(".")
        if candidate == hostname:
            return True
        if candidate.startswith("*."):
            suffix = candidate[1:]
            if hostname.endswith(suffix) and hostname.count(".") == candidate.count("."):
                return True
    return False


def bounded_resolve_addresses(host: str, timeout: float) -> tuple[str, set[str]]:
    """Ограниченный DNS lookup; адреса возвращаются только внутреннему коду."""
    addresses: set[str] = set()
    finished = threading.Event()

    def resolve() -> None:
        try:
            for _family, _type, _proto, _canonname, sockaddr in socket.getaddrinfo(
                host, 443, type=socket.SOCK_STREAM
            ):
                if sockaddr:
                    addresses.add(str(sockaddr[0]))
        except OSError:
            pass
        finally:
            finished.set()

    threading.Thread(target=resolve, name="kvn-mtproto-resolve", daemon=True).start()
    finished.wait(max(0.05, min(float(timeout), 3.0)))
    if not finished.is_set():
        return "timeout", set()
    return ("ok" if addresses else "unavailable"), addresses


def _mtproto_runtime_check(command: list[str], timeout: float) -> str:
    """Запускает bounded check, полностью отбрасывая потенциально чувствительный вывод."""
    if not shutil.which("docker"):
        return "not_available"
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(0.1, min(float(timeout), 10.0)),
        )
    except (OSError, subprocess.TimeoutExpired):
        return "timeout_or_unavailable"
    return "ok" if result.returncode == 0 else "failed"


def mtproto_diagnose(
    state: dict,
    system: str,
    *,
    timeout: float = 3.0,
    runtime_checks: bool = True,
) -> dict[str, object]:
    """Диагностика MTProto без изменения state и без раскрытия IP/секретов."""
    if system not in MTPROTO_SYSTEMS:
        raise SystemExit(f"Неизвестный MTProto-сервис: {system}")
    timeout = max(0.5, min(float(timeout), 10.0))
    started = time.monotonic()
    deadline = started + timeout

    def remaining() -> float:
        return max(0.0, deadline - time.monotonic())

    probe_state = copy.deepcopy(state)
    origin = mtproto_camouflage_origin(probe_state, system)
    sni = validate_sni_domain(system_sni(probe_state, system))
    expected_dest = DEFAULT_ROUTE_DESTS[system]
    checks: list[dict[str, str]] = []

    def add(identifier: str, status: str, detail: str) -> None:
        checks.append({"id": identifier, "status": status, "detail": detail})

    route = ensure_sni_route(probe_state, system)
    route_ok = route.get("dest") == expected_dest and sni in route.get("aliases", [])
    add("sni_route", "ok" if route_ok else "error", "route_ready" if route_ok else "route_mismatch")

    conflicting = []
    for other in NGINX_ROUTED_SYSTEMS:
        if other == system:
            continue
        other_route = ensure_sni_route(probe_state, other)
        if sni == other_route.get("default") or sni in other_route.get("aliases", []):
            conflicting.append(other)
    add(
        "route_collision",
        "error" if conflicting else "ok",
        "conflict:" + ",".join(sorted(conflicting)) if conflicting else "unique",
    )

    try:
        config_text = telemt_config_text(probe_state) if system == "telemt" else mtg_config_text(probe_state)
        parsed = tomllib.loads(config_text)
        config_ok = bool(parsed)
    except (SystemExit, tomllib.TOMLDecodeError, TypeError, ValueError):
        config_ok = False
    add("config_syntax", "ok" if config_ok else "error", "valid" if config_ok else "invalid")

    dns_probe = probe_sni_target(sni, timeout=max(0.5, min(remaining(), 3.0)))
    dns_status = str(dns_probe.get("dns", "unavailable"))
    tls_status = str(dns_probe.get("tls", "not_checked"))
    add("dns", "ok" if dns_status == "ok" else "warning", dns_status)
    add("public_tls", "ok" if tls_status == "ok" else "warning", tls_status)

    server = str(probe_state.get("server", "")).strip()
    relation_budget = remaining()
    if relation_budget > 0.1:
        each_budget = max(0.05, min(relation_budget / 2, 1.0))
        sni_resolve, sni_addresses = bounded_resolve_addresses(sni, each_budget)
        server_resolve, server_addresses = bounded_resolve_addresses(server, each_budget) if server else ("unavailable", set())
    else:
        sni_resolve, sni_addresses = "timeout", set()
        server_resolve, server_addresses = "timeout", set()
    same_server = bool(sni_addresses and server_addresses and sni_addresses & server_addresses)
    relation_status = "ok"
    relation_detail = "same_server" if same_server else "external_target"
    if sni_resolve != "ok" or server_resolve != "ok":
        relation_status, relation_detail = "warning", "not_checked"
    elif origin == "external" and same_server:
        relation_status, relation_detail = "error", "public_443_loop_risk"
    elif origin == "local-site" and not same_server:
        relation_status, relation_detail = "warning", "dns_not_on_server"
    add("dns_ip_relation", relation_status, relation_detail)

    sans = certificate_sans(SITE_CERTS_DIR / "server.crt")
    san_ok = certificate_name_matches(sni, sans)
    if origin == "local-site":
        add("certificate_san", "ok" if san_ok else "error", "match" if san_ok else "missing")
        target = "nginx:8443"
    else:
        add("certificate_san", "ok", "external_not_required")
        target = f"{sni}:443"

    if runtime_checks and origin == "local-site" and remaining() > 0.1:
        runtime_timeout = remaining()
        decoy = _mtproto_runtime_check(
            [
                "docker", "compose", "-f", "docker-compose.yml", "exec", "-T", "nginx",
                "wget", "-q", "-T", str(max(1, int(timeout))), "--no-check-certificate",
                "-O", "/dev/null", "https://127.0.0.1:8443/",
            ],
            runtime_timeout,
        )
        add("decoy_response", "ok" if decoy == "ok" else "warning", decoy)
    else:
        add("decoy_response", "ok" if origin == "external" else "warning", "external" if origin == "external" else "not_checked")

    if runtime_checks and system == "mtg" and remaining() > 0.1:
        doctor = _mtproto_runtime_check(
            [
                "docker", "compose", "-f", "docker-compose.yml", "run", "--rm", "--no-deps",
                "mtg", "doctor", "/config.toml",
            ],
            remaining(),
        )
        add("mtg_doctor", "ok" if doctor == "ok" else "warning", doctor)
    elif system == "mtg":
        add("mtg_doctor", "warning", "not_checked")

    errors = [item["id"] for item in checks if item["status"] == "error"]
    warnings = [item["id"] for item in checks if item["status"] == "warning"]
    return {
        "system": system,
        "origin": origin,
        "sni": sni,
        "target": target,
        "status": "ready" if not errors and not warnings else "needs_attention",
        "can_apply": not errors,
        "timeout_seconds": timeout,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "limitations": "Полную блокировку IP/TCP/TLS гарантированно обойти невозможно.",
    }


def hysteria_pin_yaml_lines() -> list[str]:
    pin = certificate_pin_sha256(ROOT / "hy2" / "certs" / "server.crt")
    if not pin:
        return []
    return [f"  pinSHA256: {pin}"]


def write_client_files(state: dict, public_key: str) -> None:
    CLIENTS_DIR.mkdir(exist_ok=True)
    all_links: list[str] = []

    for user in enabled_users(state):
        systems = user_systems(user)
        user_dir = CLIENTS_DIR / user["name"]
        user_dir.mkdir(parents=True, exist_ok=True)

        if "tls" in systems:
            (user_dir / "xray-vless-tls.json").write_text(
                json.dumps(client_json_tls(state, user), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (user_dir / "xray-vless-tls-direct.json").write_text(
                json.dumps(
                    client_json_tls(
                        state,
                        user,
                        port=DIRECT_PORTS["tls"],
                        remarks_suffix="VLESS TLS Vision direct",
                    ),
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
        if "reality-xhttp" in systems:
            (user_dir / "xray-reality.json").write_text(
                json.dumps(client_json_reality(state, user, public_key), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (user_dir / "xray-reality-direct.json").write_text(
                json.dumps(
                    client_json_reality(
                        state,
                        user,
                        public_key,
                        port=DIRECT_PORTS["reality-xhttp"],
                        remarks_suffix="Reality xHTTP direct",
                    ),
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
        if "reality-tcp" in systems:
            (user_dir / "xray-reality-tcp.json").write_text(
                json.dumps(client_json_reality_tcp(state, user, public_key), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            (user_dir / "xray-reality-tcp-direct.json").write_text(
                json.dumps(
                    client_json_reality_tcp(
                        state,
                        user,
                        public_key,
                        port=DIRECT_PORTS["reality-tcp"],
                        remarks_suffix="Reality TCP Vision direct",
                    ),
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
        if "hysteria" in systems:
            (user_dir / "hysteria2.yaml").write_text(
                hysteria_client_yaml(state, user),
                encoding="utf-8",
            )
            # Xray 26.3.27+ JSON: URI не работает с самоподписанным сертом (allowInsecure удалён)
            (user_dir / "xray-hysteria2.json").write_text(
                json.dumps(xray_hysteria2_json(state, user), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        if "amneziawg" in systems:
            awg_conf = amneziawg_client_conf(state, user)
            (user_dir / "amneziawg.conf").write_text(
                awg_conf,
                encoding="utf-8",
            )
            old_bypass = user_dir / "amneziawg-bypass.txt"
            if old_bypass.exists():
                old_bypass.unlink()
            qr_path = user_dir / "amneziawg.png"
            write_optional_qr(awg_conf, qr_path, "AmneziaWG", user["name"])
        else:
            for old_name in ("amneziawg.conf", "amneziawg.png", "amneziawg-bypass.txt"):
                old_path = user_dir / old_name
                if old_path.exists():
                    old_path.unlink()

        if "wireguard" in systems:
            wg_conf = wireguard_client_conf(state, user)
            (user_dir / "wireguard.conf").write_text(
                wg_conf,
                encoding="utf-8",
            )
            write_optional_qr(wg_conf, user_dir / "wireguard.png", "WireGuard", user["name"])
        else:
            for old_name in ("wireguard.conf", "wireguard.png"):
                old_path = user_dir / old_name
                if old_path.exists():
                    old_path.unlink()

        if "telemt" in systems:
            (user_dir / "telemt.txt").write_text(
                telemt_client_text(state, user),
                encoding="utf-8",
            )
            write_optional_qr(telemt_link(state, user), user_dir / "telemt.png", "Telemt", user["name"])
        else:
            for old_name in ("telemt.png", "telemt.txt"):
                old_path = user_dir / old_name
                if old_path.exists():
                    old_path.unlink()

        if "mtg" in systems:
            (user_dir / "mtg.txt").write_text(
                mtg_client_text(state),
                encoding="utf-8",
            )
            write_optional_qr(mtg_link(state), user_dir / "mtg.png", "mtg", user["name"])
        else:
            for old_name in ("mtg.png", "mtg.txt"):
                old_path = user_dir / old_name
                if old_path.exists():
                    old_path.unlink()

        if "telemt" in systems or "mtg" in systems:
            (user_dir / "telegram-proxy.txt").write_text(
                telegram_proxy_text(state, user),
                encoding="utf-8",
            )
        else:
            old_path = user_dir / "telegram-proxy.txt"
            if old_path.exists():
                old_path.unlink()

        if "ocserv" in systems:
            (user_dir / "openconnect.txt").write_text(
                openconnect_client_text(state, user) + "\n",
                encoding="utf-8",
            )
        else:
            old_path = user_dir / "openconnect.txt"
            if old_path.exists():
                old_path.unlink()

        # Подписка: sing-box JSON (HAPP/Hiddify/Karing)
        (user_dir / "subscription.json").write_text(
            json.dumps(singbox_subscription(state, user, public_key), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        # Старый base64 payload сохраняется для подключённых клиентов.
        (user_dir / "subscription.txt").write_text(
            subscription_txt(state, user, public_key),
            encoding="utf-8",
        )
        # Старый raw URI list для ручного импорта и диагностики.
        (user_dir / "subscription-raw.txt").write_text(
            subscription_raw_txt(state, user, public_key),
            encoding="utf-8",
        )
        # Полный raw URI list для ручной диагностики вне HAPP/Karing.
        (user_dir / "subscription-raw-all.txt").write_text(
            subscription_raw_all_txt(state, user, public_key),
            encoding="utf-8",
        )
        happ_url = happ_sub_url(state, user)
        (user_dir / "happ-subscription.txt").write_text(happ_url + "\n", encoding="utf-8")
        happ_qr_path = user_dir / "happ-subscription.png"
        write_optional_qr(happ_url, happ_qr_path, "HAPP", user["name"])
        karing_url = karing_sub_url(state, user)
        (user_dir / "karing-subscription.txt").write_text(karing_url + "\n", encoding="utf-8")
        karing_qr_path = user_dir / "karing-subscription.png"
        write_optional_qr(karing_url, karing_qr_path, "Karing", user["name"])
        if "wireguard" in systems:
            karing_wg_url = karing_wireguard_sub_url(state, user)
            (user_dir / "karing-wireguard.txt").write_text(karing_wg_url + "\n", encoding="utf-8")
            (user_dir / "karing-wireguard.yaml").write_text(
                karing_wireguard_yaml(state, user), encoding="utf-8"
            )
            write_optional_qr(
                karing_wg_url, user_dir / "karing-wireguard.png", "Karing WireGuard", user["name"]
            )
        else:
            for old_name in ("karing-wireguard.txt", "karing-wireguard.yaml", "karing-wireguard.png"):
                old_path = user_dir / old_name
                if old_path.exists():
                    old_path.unlink()

        text = user_links_text(state, user, public_key)
        (user_dir / "links.txt").write_text(text, encoding="utf-8")
        (user_dir / "send.txt").write_text(user_send_text(state, user, public_key), encoding="utf-8")
        all_links.append(text)

    # Удалить клиентские папки удалённых/отключённых пользователей
    active_names = {user["name"] for user in enabled_users(state)}
    for child in CLIENTS_DIR.iterdir():
        if child.is_dir() and child.name not in active_names:
            shutil.rmtree(child, ignore_errors=True)

    (CLIENTS_DIR / "all-links.txt").write_text("\n".join(all_links), encoding="utf-8")
    CLIENT_LINKS_FILE.write_text(client_links_markdown(state, public_key), encoding="utf-8")


def mtg_config_text(state: dict) -> str:
    """Рендерит явный безопасный конфиг mtg 2.2.8."""
    secret = mtg_faketls_secret(state)
    if not secret:
        raise SystemExit("mtg секрет не задан — сначала выполните prepare_state")
    local_site = mtproto_camouflage_origin(state, "mtg") == "local-site"
    lines = [
        "# Конфиг mtg (MTProto FakeTLS). Генерируется из users.json — не править вручную.",
        "debug = false",
        f'secret = "{secret}"',
        'bind-to = "0.0.0.0:3128"',
        "concurrency = 8192",
        'prefer-ip = "only-ipv4"',
        'tolerate-time-skewness = "5s"',
        "auto-update = false",
        "allow-fallback-on-unknown-dc = false",
        "",
        "[domain-fronting]",
        f"port = {8443 if local_site else 443}",
        "proxy-protocol = false",
        "",
        "[network]",
        # Пустая строка включает системный resolver. В local-site Docker DNS
        # отдаёт внутренний alias nginx, а не публичный IP сервера.
        'dns = ""',
        "proxies = []",
        "",
        "[network.timeout]",
        'tcp = "5s"',
        'http = "10s"',
        'idle = "5m"',
        'handshake = "10s"',
        "",
        "[network.keep-alive]",
        "disabled = false",
        'idle = "15s"',
        'interval = "15s"',
        "count = 9",
        "",
        "[defense.doppelganger]",
        "urls = []",
        "repeats-per-raid = 10",
        'raid-each = "6h"',
        "drs = false",
        "",
        "[defense.anti-replay]",
        "enabled = true",
        'max-size = "1mib"',
        "error-rate = 0.001",
        "",
    ]
    return "\n".join(lines)


def render_compose_env(state: dict) -> None:
    """Обновляет только Docker alias MTG, не затрагивая остальные .env ключи."""
    path = ROOT / ".env"
    try:
        existing = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        existing = ""
    except OSError as exc:
        raise SystemExit(f"не удалось прочитать .env: {exc}") from exc
    key = "KVN_MTG_CAMOUFLAGE_HOST"
    replacement = f"{key}={mtg_compose_alias(state)}"
    lines = existing.splitlines()
    updated: list[str] = []
    replaced = False
    for line in lines:
        if line.startswith(f"{key}="):
            if not replaced:
                updated.append(replacement)
                replaced = True
            continue
        updated.append(line)
    if not replaced:
        updated.append(replacement)
    content = "\n".join(updated).rstrip("\n") + "\n"
    if content == existing:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".env.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def render_mtg(state: dict) -> None:
    """Пишет mtg/config.toml и согласованный Docker DNS alias decoy."""
    (ROOT / "mtg" / "config.toml").write_text(mtg_config_text(state), encoding="utf-8")
    render_compose_env(state)
    ok("mtg/config.toml обновлён")


def prepare_state(state: dict, server: str | None = None) -> tuple[str, str, bool]:
    """Нормализует источник правды до atomic commit, не пишет файлы и не запускает процессы."""
    before = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if server:
        state["server"] = validate_host(server, "server")
    validate_state_inputs(state)
    ensure_user_secrets(state)
    reapply_device_profiles(state)
    ensure_mtg_secret(state)
    ensure_amneziawg_state(state)
    ensure_wireguard_state(state)
    ocserv_config(state)
    xray_config_state(state)
    public_key, _ = ensure_reality_public_key(state, "reality")
    tcp_public_key, _ = ensure_reality_public_key(state, "reality_tcp")
    ensure_server_country(state)
    validate_sni_uniqueness(state)
    after = json.dumps(state, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return public_key, tcp_public_key, before != after


def render_all(state: dict, server: str | None = None) -> RenderResult:
    """Рендерит generated-файлы из подготовленного state без скрытого сохранения source."""
    before_fingerprint = generated_fingerprint()
    public_key, tcp_public_key, _ = prepare_state(state, server)
    render_decoy_site(state)
    render_nginx(state)
    render_xray(state)
    render_hysteria(state)
    render_telemt(state)
    render_mtg(state)
    render_amneziawg(state)
    render_wireguard(state)
    render_ocserv(state)
    write_client_files(state, public_key)
    write_sub_web(state, public_key)
    sync_portal_runtime_state(state)
    if public_key.startswith("<") or tcp_public_key.startswith("<"):
        warn("Reality public key не вычислен. Заполните users.json вручную.")
    fix_permissions()
    return build_change_set(before_fingerprint, generated_fingerprint())


def _run_compose(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", "docker-compose.yml", *command],
        cwd=ROOT,
        check=False,
        timeout=timeout,
    )


def _restart_docker_services(services: list[str]) -> bool:
    if not services:
        return True
    try:
        result = _run_compose(["restart", *services])
    except (OSError, subprocess.TimeoutExpired):
        warn(f"не удалось перезапустить сервисы: {', '.join(services)}")
        return False
    if result.returncode != 0:
        warn(f"restart завершился с ошибкой: {', '.join(services)}")
        return False
    ok(f"перезапущены сервисы: {', '.join(services)}")
    return True


def _docker_service_files_visible(service: str, paths: list[str]) -> bool:
    """Проверяет наличие bind-mounted файлов внутри работающего контейнера."""
    expression = " && ".join(f"test -r {path}" for path in paths)
    try:
        result = _run_compose(["exec", "-T", service, "sh", "-c", expression], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _recreate_docker_service(service: str) -> bool:
    """Точечно пересоздаёт сервис для обновления устаревшего bind mount."""
    try:
        result = _run_compose(
            ["up", "-d", "--no-deps", "--force-recreate", service], timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        result = None
    if result is not None and result.returncode == 0:
        ok(f"сервис {service} пересоздан для обновления bind mount")
        return True
    return False


def _docker_compose_service_running(service: str) -> bool:
    """Проверяет, запущен ли compose-сервис, без шума при недоступном Docker."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml", "ps", "-q", service],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    container_ids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    for container_id in container_ids:
        try:
            inspect = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", container_id],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if inspect.returncode == 0 and inspect.stdout.strip().lower() == "true":
            return True
    return False


def _stop_docker_service_best_effort(service: str) -> bool:
    """Останавливает Docker-сервис, если он запущен; ошибки только логируются."""
    if not _docker_compose_service_running(service):
        return False
    try:
        result = _run_compose(["stop", service], timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        warn(f"не удалось остановить сервис {service}")
        return False
    if result.returncode != 0:
        warn(f"stop завершился с ошибкой: {service}")
        return False
    return True


def _start_docker_service_best_effort(service: str) -> bool:
    """Поднимает Docker-сервис после временной остановки."""
    try:
        result = _run_compose(["up", "-d", service], timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        warn(f"не удалось запустить сервис {service}")
        return False
    if result.returncode != 0:
        warn(f"up завершился с ошибкой: {service}")
        return False
    return True


def _reload_docker_service(service: str) -> bool:
    commands = {
        "nginx": (["exec", "-T", "nginx", "nginx", "-t"], ["exec", "-T", "nginx", "nginx", "-s", "reload"]),
        "ocserv": (None, ["kill", "-s", "HUP", "ocserv"]),
    }
    check_command, reload_command = commands.get(service, (None, None))
    if reload_command is None:
        return False
    try:
        if check_command is not None and _run_compose(check_command, timeout=30).returncode != 0:
            warn(f"проверка конфигурации {service} не пройдена")
            return False
        result = _run_compose(reload_command, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode == 0:
        ok(f"сервис {service} перечитал конфигурацию")
        return True
    return False


def _hot_update_ocserv_users() -> bool:
    script = """
set -euo pipefail
tmp=/run/ocserv/ocpasswd.new
: > "$tmp"
while IFS=: read -r username password rest; do
  [[ -z "${username:-}" || "${username:0:1}" == "#" ]] && continue
  [[ -n "${rest:-}" || -z "${password:-}" ]] && exit 2
  printf '%s\n%s\n' "$password" "$password" | ocpasswd -c "$tmp" "$username" >/dev/null
done < /etc/ocserv/users.txt
chmod 600 "$tmp"
mv "$tmp" /run/ocserv/ocpasswd
""".strip()
    try:
        result = _run_compose(["exec", "-T", "ocserv", "/bin/bash", "-ceu", script], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode == 0:
        ok("пользователи ocserv обновлены без перезапуска")
        return True
    return False


def _xray_clients_by_tag(state: dict) -> dict[str, list[dict]]:
    users = enabled_users(state)
    return {
        TLS_INBOUND_TAG: xray_client_entries(users, "tls", flow=True),
        REALITY_XHTTP_INBOUND_TAG: xray_client_entries(users, "reality-xhttp", flow=False),
        REALITY_TCP_INBOUND_TAG: xray_client_entries(users, "reality-tcp", flow=True),
    }


def _hot_update_xray_users(before_state: dict, after_state: dict) -> bool:
    before = _xray_clients_by_tag(before_state)
    after = _xray_clients_by_tag(after_state)
    try:
        for tag in before:
            old_by_email = {item["email"]: item for item in before[tag]}
            new_by_email = {item["email"]: item for item in after[tag]}
            removed = [
                email for email, client in old_by_email.items()
                if email not in new_by_email or new_by_email[email] != client
            ]
            for email in removed:
                result = subprocess.run(
                    [
                        "docker", "exec", "xray", "xray", "api", "rmu",
                        "--server=127.0.0.1:10085", f"--tag={tag}", email,
                    ],
                    cwd=ROOT,
                    check=False,
                    timeout=20,
                )
                if result.returncode != 0:
                    return False
            added = [
                client for email, client in new_by_email.items()
                if email not in old_by_email or old_by_email[email] != client
            ]
            for client in added:
                payload = {
                    "inbounds": [{
                        "tag": tag,
                        "protocol": "vless",
                        "settings": {"clients": [client]},
                    }],
                }
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    suffix=".json",
                    delete=False,
                    dir=ROOT,
                ) as handle:
                    json.dump(payload, handle, ensure_ascii=False)
                    temp_path = Path(handle.name)
                try:
                    remote_path = "/tmp/kvn-xray-user.json"
                    copied = subprocess.run(
                        ["docker", "cp", str(temp_path), f"xray:{remote_path}"],
                        cwd=ROOT,
                        check=False,
                        timeout=20,
                    )
                    if copied.returncode != 0:
                        return False
                    result = subprocess.run(
                        [
                            "docker", "exec", "xray", "xray", "api", "adu",
                            "--server=127.0.0.1:10085", f"--tag={tag}", remote_path,
                        ],
                        cwd=ROOT,
                        check=False,
                        timeout=20,
                    )
                    if result.returncode != 0:
                        return False
                finally:
                    try:
                        temp_path.write_text("{}\n", encoding="utf-8")
                        subprocess.run(
                            ["docker", "cp", str(temp_path), "xray:/tmp/kvn-xray-user.json"],
                            cwd=ROOT,
                            check=False,
                            timeout=20,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                    temp_path.unlink(missing_ok=True)
    except (OSError, subprocess.TimeoutExpired):
        return False
    ok("пользователи Xray обновлены через HandlerService")
    return True


def expected_amneziawg_peers(state: dict) -> dict[str, str]:
    """Возвращает ожидаемые runtime peers без чувствительных данных."""
    return {
        user.get("amneziawg", {}).get("public_key", ""): user.get("amneziawg", {}).get("address", "")
        for user in enabled_users(state)
        if "amneziawg" in user_systems(user)
        and user.get("amneziawg", {}).get("public_key")
        and user.get("amneziawg", {}).get("address")
    }


def expected_wireguard_peers(state: dict) -> dict[str, str]:
    """Возвращает ожидаемые WireGuard runtime peers без чувствительных данных."""
    return {
        user.get("wireguard", {}).get("public_key", ""): user.get("wireguard", {}).get("address", "")
        for user in enabled_users(state)
        if "wireguard" in user_systems(user)
        and user.get("wireguard", {}).get("public_key")
        and user.get("wireguard", {}).get("address")
    }


def amneziawg_semantic_snapshot(state: dict | None) -> dict:
    """Снимок desired-состояния AmneziaWG без приватных ключей и PSK."""
    if not isinstance(state, dict):
        return {}
    cfg = awg_config(state)
    return {
        "interface": cfg.get("interface", "awg0"),
        "network": cfg.get("network", "10.66.66.0/24"),
        "server_address": cfg.get("server_address", "10.66.66.1/24"),
        "port": int(cfg.get("port", 51820)),
        "mtu": int(cfg.get("mtu", 1280)),
        "obfuscation": {
            key: cfg.get(key)
            for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4", "I1")
            if cfg.get(key) not in ("", None)
        },
        "peers": expected_amneziawg_peers(state),
    }


def wireguard_semantic_snapshot(state: dict | None) -> dict:
    """Снимок desired-состояния WireGuard без приватных ключей и PSK."""
    if not isinstance(state, dict):
        return {}
    if "wireguard" not in state and not any("wireguard" in user_systems(user) for user in state.get("users", [])):
        return {}
    cfg = wireguard_config(state)
    return {
        "interface": cfg.get("interface", "wg0"),
        "network": cfg.get("network", "10.88.88.0/24"),
        "server_address": cfg.get("server_address", "10.88.88.1/24"),
        "port": int(cfg.get("port", 51821)),
        "mtu": int(cfg.get("mtu", 1420)),
        "peers": expected_wireguard_peers(state),
    }


def amneziawg_semantic_changed(before_state: dict | None, after_state: dict | None) -> bool:
    return amneziawg_semantic_snapshot(before_state) != amneziawg_semantic_snapshot(after_state)


def wireguard_semantic_changed(before_state: dict | None, after_state: dict | None) -> bool:
    return wireguard_semantic_snapshot(before_state) != wireguard_semantic_snapshot(after_state)


def parse_amneziawg_dump(text: str) -> dict[str, str]:
    peers: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0]:
            peers[parts[0]] = parts[3]
    return peers


def parse_wireguard_dump(text: str) -> dict[str, str]:
    return parse_amneziawg_dump(text)


def verify_amneziawg_runtime(state: dict) -> dict:
    """Проверяет project/host config и точный набор peers активного интерфейса."""
    interface = awg_config(state).get("interface", "awg0")
    project_text, project_status = read_text_file(AMNEZIAWG_CONFIG)
    host_text, host_status = read_text_file(HOST_AMNEZIAWG_CONFIG)
    expected = expected_amneziawg_peers(state)
    result = {
        "ok": False,
        "reason": "",
        "config_match": False,
        "service_active": False,
        "interface_active": False,
        "expected_peers": len(expected),
        "runtime_peers": 0,
    }
    if project_status != "ok" or host_status != "ok":
        result["reason"] = "config_unavailable"
        return result
    result["config_match"] = amneziawg_configs_equivalent(project_text, host_text)
    if not result["config_match"]:
        result["reason"] = "host_config_mismatch"
        return result
    service_code, _stdout, _stderr = run_command_text(
        ["systemctl", "is-active", "kvn-amneziawg.service"], timeout=10
    )
    result["service_active"] = service_code == 0
    link_code, _stdout, _stderr = run_command_text(["ip", "link", "show", interface], timeout=10)
    result["interface_active"] = link_code == 0
    if not result["service_active"] or not result["interface_active"]:
        result["reason"] = "service_or_interface_inactive"
        return result
    tool = shutil.which("awg") or shutil.which("wg")
    if not tool:
        result["reason"] = "awg_tool_missing"
        return result
    dump_code, dump, _stderr = run_command_text([tool, "show", interface, "dump"], timeout=15)
    if dump_code != 0:
        result["reason"] = "runtime_dump_failed"
        return result
    runtime = parse_amneziawg_dump(dump)
    result["runtime_peers"] = len(runtime)
    if runtime != expected:
        result["reason"] = "runtime_peer_mismatch"
        return result
    result["ok"] = True
    result["reason"] = "ok"
    return result


def verify_wireguard_runtime(state: dict) -> dict:
    """Проверяет project/host config и точный набор peers WireGuard-интерфейса."""
    cfg = wireguard_config(state)
    interface = cfg.get("interface", "wg0")
    project_text, project_status = read_text_file(WIREGUARD_CONFIG)
    host_text, host_status = read_text_file(HOST_WIREGUARD_CONFIG)
    expected = expected_wireguard_peers(state)
    result = {
        "ok": False,
        "reason": "",
        "config_match": False,
        "service_active": False,
        "interface_active": False,
        "expected_peers": len(expected),
        "runtime_peers": 0,
    }
    if project_status != "ok" or host_status != "ok":
        result["reason"] = "config_unavailable"
        return result
    result["config_match"] = amneziawg_configs_equivalent(project_text, host_text)
    if not result["config_match"]:
        result["reason"] = "host_config_mismatch"
        return result
    service_code, _stdout, _stderr = run_command_text(
        ["systemctl", "is-active", "kvn-wireguard.service"], timeout=10
    )
    result["service_active"] = service_code == 0
    link_code, _stdout, _stderr = run_command_text(["ip", "link", "show", interface], timeout=10)
    result["interface_active"] = link_code == 0
    if not result["service_active"] or not result["interface_active"]:
        result["reason"] = "service_or_interface_inactive"
        return result
    if not shutil.which("wg"):
        result["reason"] = "wg_tool_missing"
        return result
    dump_code, dump, _stderr = run_command_text(["wg", "show", interface, "dump"], timeout=15)
    if dump_code != 0:
        result["reason"] = "runtime_dump_failed"
        return result
    runtime = parse_wireguard_dump(dump)
    result["runtime_peers"] = len(runtime)
    if runtime != expected:
        result["reason"] = "runtime_peer_mismatch"
        return result
    result["ok"] = True
    result["reason"] = "ok"
    return result


def _sync_amneziawg(state: dict | None = None) -> dict:
    state = state or load_state()
    sync = {
        "ok": False,
        "mode": "failed",
        "reason": "",
        "fallback": "",
        "verified": False,
        "verification": {},
    }
    script = ROOT / "amneziawg" / "sync-host-service.sh"
    if not script.exists():
        warn("sync-host-service.sh не найден")
        sync["reason"] = "sync_script_missing"
        return sync
    if not shutil.which("awg-quick"):
        warn("awg-quick не найден — AmneziaWG не синхронизирован")
        sync["reason"] = "awg_quick_missing"
        return sync
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        warn("Синхронизация AmneziaWG требует root")
        sync["reason"] = "root_required"
        return sync
    try:
        completed = subprocess.run(
            [str(script)], cwd=ROOT, check=False, timeout=60,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        sync["reason"] = "sync_execution_failed"
        return sync
    if completed.returncode != 0:
        error_match = re.search(r"^KVN_AWG_ERROR=([a-z0-9_]+)$", completed.stderr, re.M)
        sync["reason"] = error_match.group(1) if error_match else "sync_script_failed"
        return sync
    mode_match = re.search(r"^KVN_AWG_APPLY_MODE=(syncconf|restart)$", completed.stdout, re.M)
    sync["mode"] = mode_match.group(1) if mode_match else "restart"
    if "KVN_AWG_FALLBACK=syncconf_failed" in completed.stdout:
        sync["fallback"] = "syncconf_failed"
    verification = verify_amneziawg_runtime(state)
    sync["verification"] = verification
    sync["verified"] = bool(verification.get("ok"))
    sync["ok"] = sync["verified"]
    sync["reason"] = verification.get("reason", "verification_failed")
    if sync["ok"]:
        ok("AmneziaWG host-служба синхронизирована и проверена")
    return sync


def _sync_wireguard(state: dict | None = None) -> dict:
    state = state or load_state()
    sync = {
        "ok": False,
        "mode": "failed",
        "reason": "",
        "fallback": "",
        "verified": False,
        "verification": {},
    }
    script = ROOT / "wireguard" / "sync-host-service.sh"
    if not script.exists():
        warn("wireguard/sync-host-service.sh не найден")
        sync["reason"] = "sync_script_missing"
        return sync
    if not shutil.which("wg-quick") or not shutil.which("wg"):
        warn("wg/wg-quick не найден — WireGuard не синхронизирован")
        sync["reason"] = "wg_tools_missing"
        return sync
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        warn("Синхронизация WireGuard требует root")
        sync["reason"] = "root_required"
        return sync
    try:
        completed = subprocess.run(
            [str(script)], cwd=ROOT, check=False, timeout=60,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        sync["reason"] = "sync_execution_failed"
        return sync
    if completed.returncode != 0:
        error_match = re.search(r"^KVN_WG_ERROR=([a-z0-9_]+)$", completed.stderr, re.M)
        sync["reason"] = error_match.group(1) if error_match else "sync_script_failed"
        return sync
    mode_match = re.search(r"^KVN_WG_APPLY_MODE=(syncconf|restart)$", completed.stdout, re.M)
    sync["mode"] = mode_match.group(1) if mode_match else "restart"
    if "KVN_WG_FALLBACK=syncconf_failed" in completed.stdout:
        sync["fallback"] = "syncconf_failed"
    verification = verify_wireguard_runtime(state)
    sync["verification"] = verification
    sync["verified"] = bool(verification.get("ok"))
    sync["ok"] = sync["verified"]
    sync["reason"] = verification.get("reason", "verification_failed")
    if sync["ok"]:
        ok("WireGuard host-служба синхронизирована и проверена")
    return sync


def _record_amneziawg_apply(report: dict, state: dict | None) -> None:
    sync = _sync_amneziawg(state)
    verification = sync.get("verification") if isinstance(sync.get("verification"), dict) else {}
    report.setdefault("details", {})["amneziawg"] = {
        "mode": sync.get("mode", "failed"),
        "reason": sync.get("reason", ""),
        "fallback": sync.get("fallback", ""),
        "verified": bool(sync.get("verified")),
        "expected_peers": int(verification.get("expected_peers", 0) or 0),
        "runtime_peers": int(verification.get("runtime_peers", 0) or 0),
    }
    if sync["ok"]:
        target = "restarted" if sync["mode"] == "restart" else "hot_updated"
        report[target].append("amneziawg")
        if sync["fallback"]:
            report["fallbacks"].append("amneziawg: syncconf не удался, выполнен restart")
        return
    warn("изменение AmneziaWG сохранено, но runtime verification не пройдена")
    report["warnings"].append(f"AmneziaWG не применён: {sync['reason']}")
    report["failed"].append("amneziawg")


def _record_wireguard_apply(report: dict, state: dict | None) -> None:
    sync = _sync_wireguard(state)
    verification = sync.get("verification") if isinstance(sync.get("verification"), dict) else {}
    report.setdefault("details", {})["wireguard"] = {
        "mode": sync.get("mode", "failed"),
        "reason": sync.get("reason", ""),
        "fallback": sync.get("fallback", ""),
        "verified": bool(sync.get("verified")),
        "expected_peers": int(verification.get("expected_peers", 0) or 0),
        "runtime_peers": int(verification.get("runtime_peers", 0) or 0),
    }
    if sync["ok"]:
        target = "restarted" if sync["mode"] == "restart" else "hot_updated"
        report[target].append("wireguard")
        if sync["fallback"]:
            report["fallbacks"].append("wireguard: syncconf не удался, выполнен restart")
        return
    warn("изменение WireGuard сохранено, но runtime verification не пройдена")
    report["warnings"].append(f"WireGuard не применён: {sync['reason']}")
    report["failed"].append("wireguard")


def restart_services(
    changed: bool | ChangeSet = True,
    *,
    before_state: dict | None = None,
    after_state: dict | None = None,
    force_host_sync_services: set[str] | list[str] | tuple[str, ...] | None = None,
) -> dict:
    report = {
        "outcome": "applied",
        "hot_updated": [],
        "reloaded": [],
        "restarted": [],
        "fallbacks": [],
        "failed": [],
        "warnings": [],
        "skipped_disabled": [],
        "reconcile_required": False,
        "details": {},
    }

    def finish() -> dict:
        if report["failed"] or report["warnings"]:
            report["outcome"] = "failed"
            report["reconcile_required"] = True
        elif report["fallbacks"]:
            report["outcome"] = "fallback"
        return report

    try:
        lifecycle_state = after_state if after_state is not None else STATE_STORE.load()
    except (OSError, ValueError, TypeError):
        lifecycle_state = {}
    service_plan = effective_service_plan(lifecycle_state)
    enabled_services = {
        service for service, enabled in service_plan.effective_preferences if enabled
    }

    forced_host_sync = {
        service
        for service in (force_host_sync_services or ())
        if service in {"amneziawg", "wireguard"} and service in enabled_services
    }
    semantic_awg_changed = (
        "amneziawg" in enabled_services and amneziawg_semantic_changed(before_state, after_state)
    )
    semantic_wg_changed = (
        "wireguard" in enabled_services and wireguard_semantic_changed(before_state, after_state)
    )
    force_awg_sync = "amneziawg" in forced_host_sync
    force_wg_sync = "wireguard" in forced_host_sync

    if not changed and not semantic_awg_changed and not semantic_wg_changed and not forced_host_sync:
        ok("изменений нет — сервисы не перезапускались")
        report["outcome"] = "no-op"
        return finish()
    if isinstance(changed, ChangeSet) and not changed.has_service_actions:
        if semantic_awg_changed or force_awg_sync:
            _record_amneziawg_apply(report, after_state)
        if semantic_wg_changed or force_wg_sync:
            _record_wireguard_apply(report, after_state)
        if not semantic_awg_changed and not semantic_wg_changed and not forced_host_sync:
            ok("изменены только клиентские/runtime-файлы — сервисы не трогались")
        return finish()
    if not shutil.which("docker"):
        if "amneziawg" in enabled_services and (
            force_awg_sync or semantic_awg_changed
            or isinstance(changed, ChangeSet) and "amneziawg" in changed.services
        ):
            _record_amneziawg_apply(report, after_state)
        if "wireguard" in enabled_services and (
            force_wg_sync or semantic_wg_changed
            or isinstance(changed, ChangeSet) and "wireguard" in changed.services
        ):
            _record_wireguard_apply(report, after_state)
        if isinstance(changed, ChangeSet) and set(changed.services) <= {"amneziawg", "wireguard"}:
            return finish()
        warn("docker не найден, изменения сервисов не применены")
        report["warnings"].append("Docker недоступен, изменения не применены")
        return finish()

    if not isinstance(changed, ChangeSet):
        if not changed and (semantic_awg_changed or semantic_wg_changed or forced_host_sync):
            if semantic_awg_changed or force_awg_sync:
                _record_amneziawg_apply(report, after_state)
            if semantic_wg_changed or force_wg_sync:
                _record_wireguard_apply(report, after_state)
            return finish()
        docker_services = [
            service for service in ["xray", "hysteria", "telemt", "nginx", "mtg", "ocserv"]
            if service in enabled_services
        ]
        if _restart_docker_services(docker_services):
            report["restarted"].extend(docker_services)
        if "amneziawg" in enabled_services:
            _record_amneziawg_apply(report, after_state)
        if "wireguard" in enabled_services:
            _record_wireguard_apply(report, after_state)
        return finish()

    restart_queue: list[str] = []
    recreate_queue: list[str] = []
    amneziawg_applied = False
    wireguard_applied = False
    for service, service_change in sorted(changed.services.items()):
        if service not in enabled_services:
            report["skipped_disabled"].append(service)
            continue
        action = service_change.action
        if service == "amneziawg":
            _record_amneziawg_apply(report, after_state)
            amneziawg_applied = True
            continue
        if service == "wireguard":
            _record_wireguard_apply(report, after_state)
            wireguard_applied = True
            continue
        if (
            service == "xray"
            and before_state is not None
            and after_state is not None
            and _hot_update_xray_users(before_state, after_state)
        ):
            report["hot_updated"].append(service)
            continue
        if action is ApplyAction.HOT_UPDATE:
            if service == "telemt":
                structural = bool(
                    before_state is not None
                    and after_state is not None
                    and (
                        system_sni(before_state, "telemt") != system_sni(after_state, "telemt")
                        or mtproto_camouflage_origin(before_state, "telemt")
                        != mtproto_camouflage_origin(after_state, "telemt")
                    )
                )
                if structural:
                    restart_queue.append(service)
                    report["fallbacks"].append(
                        "telemt: SNI/camouflage требует controlled restart по схеме 3.4.24"
                    )
                else:
                    ok("Telemt получил пользователей через штатный file watcher")
                    report["hot_updated"].append(service)
                continue
            if service == "ocserv" and _hot_update_ocserv_users():
                report["hot_updated"].append(service)
                continue
            restart_queue.append(service)
            report["fallbacks"].append(f"{service}: hot-update не удался, выполнен restart")
            continue
        if action is ApplyAction.RELOAD:
            if _reload_docker_service(service):
                report["reloaded"].append(service)
            else:
                restart_queue.append(service)
                report["fallbacks"].append(f"{service}: reload не удался, выполнен restart")
            continue
        if action is ApplyAction.RESTART:
            if service_change.reason == "compose-network-alias":
                recreate_queue.append(service)
            else:
                restart_queue.append(service)
            if service == "xray" and before_state is not None:
                report["fallbacks"].append("xray: hot-update не удался, выполнен restart")
    if (semantic_awg_changed or force_awg_sync) and not amneziawg_applied:
        _record_amneziawg_apply(report, after_state)
    if (semantic_wg_changed or force_wg_sync) and not wireguard_applied:
        _record_wireguard_apply(report, after_state)
    restart_queue = sorted(set(restart_queue))
    for service in sorted(set(recreate_queue)):
        if _recreate_docker_service(service):
            report["restarted"].append(service)
            report["details"][service] = {"mode": "force-recreate", "reason": "compose-network-alias"}
        else:
            report["warnings"].append(f"{service}: пересоздание для Docker DNS alias не выполнено")
            report["failed"].append(service)
    if _restart_docker_services(restart_queue):
        report["restarted"].extend(restart_queue)
    elif restart_queue:
        report["warnings"].append("Перезапуск сервисов завершился с ошибкой")
        report["failed"].extend(restart_queue)
    return finish()


def read_text_file(path: Path) -> tuple[str, str]:
    try:
        return path.read_text(encoding="utf-8"), "ok"
    except FileNotFoundError:
        return "", "missing"
    except PermissionError:
        return "", "permission"
    except OSError as exc:
        return "", str(exc)


def resolve_host_ips(host: str) -> list[str]:
    host = (host or "").strip()
    if not host or host == "YOUR_SERVER_IP":
        return []
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []
    result: list[str] = []
    for info_item in infos:
        ip = info_item[4][0]
        if ip not in result:
            result.append(ip)
    return result


def host_global_ipv4s() -> list[str]:
    if not shutil.which("ip"):
        return []
    code, stdout, _stderr = run_command_text(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=10)
    if code != 0:
        return []
    result: list[str] = []
    for address in re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+", stdout):
        if address not in result:
            result.append(address)
    return result


def default_wan_iface() -> str:
    if not shutil.which("ip"):
        return ""
    code, stdout, _stderr = run_command_text(["ip", "-4", "route", "show", "default"], timeout=10)
    if code != 0:
        return ""
    match = re.search(r"\bdev\s+([A-Za-z0-9_.-]{1,15})\b", stdout)
    return match.group(1) if match else ""


def normalize_amneziawg_host_config(config_text: str) -> str:
    """Убирает штатную замену eth0 на реальный WAN-интерфейс при сравнении."""
    normalized = config_text.replace("\r\n", "\n")
    normalized = re.sub(
        r"(-o\s+)[A-Za-z0-9_.-]+(\s+-j\s+MASQUERADE)",
        r"\1eth0\2",
        normalized,
    )
    return "\n".join(line.rstrip() for line in normalized.strip().splitlines())


def amneziawg_configs_equivalent(project_text: str, host_text: str) -> bool:
    if not project_text or not host_text:
        return False
    return normalize_amneziawg_host_config(project_text) == normalize_amneziawg_host_config(host_text)


def amneziawg_key_pair_matches(private_key: str, public_key: str) -> bool:
    derived = wg_public_key(private_key)
    return bool(derived and public_key and secrets.compare_digest(derived, public_key))


def ufw_udp_status(port: int) -> str:
    if not shutil.which("ufw"):
        return "не установлен"
    code, stdout, stderr = run_command_text(["ufw", "status"], timeout=15)
    if code != 0:
        return stderr or stdout or "ошибка проверки"
    if re.search(r"^Status:\s+inactive", stdout, re.M | re.I):
        return "inactive"
    if any(
        re.search(rf"\b{port}/udp\b.*\bALLOW\b", line, re.I)
        for line in stdout.splitlines()
    ):
        return f"ALLOW {port}/udp"
    return f"active, правило ALLOW {port}/udp не найдено"


def iptables_udp_input_status(port: int) -> str:
    if not shutil.which("iptables"):
        return "iptables не найден"
    code, _stdout, _stderr = run_command_text(
        ["iptables", "-C", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"],
        timeout=15,
    )
    return f"ACCEPT {port}/udp" if code == 0 else f"явное правило ACCEPT {port}/udp не найдено"


def iptables_wireguard_forward_status(interface: str) -> str:
    if not shutil.which("iptables"):
        return "iptables не найден"
    checks = [
        (["iptables", "-C", "FORWARD", "-i", interface, "-j", "ACCEPT"], f"-i {interface} ACCEPT"),
        (["iptables", "-C", "FORWARD", "-o", interface, "-j", "ACCEPT"], f"-o {interface} ACCEPT"),
    ]
    missing: list[str] = []
    for argv, label in checks:
        code, _stdout, _stderr = run_command_text(argv, timeout=15)
        if code != 0:
            missing.append(label)
    return "ACCEPT inbound/outbound" if not missing else "не найдены: " + ", ".join(missing)


def iptables_masquerade_status(network: str, wan_iface: str) -> str:
    if not shutil.which("iptables"):
        return "iptables не найден"
    if not wan_iface:
        return "WAN-интерфейс не определён"
    code, _stdout, _stderr = run_command_text(
        ["iptables", "-t", "nat", "-C", "POSTROUTING", "-s", network, "-o", wan_iface, "-j", "MASQUERADE"],
        timeout=15,
    )
    return f"MASQUERADE {network} -> {wan_iface}" if code == 0 else f"MASQUERADE {network} -> {wan_iface} не найден"


def ipv4_forward_status() -> str:
    path = Path("/proc/sys/net/ipv4/ip_forward")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return "неизвестно"
    return "включён" if value == "1" else "выключен"


def amneziawg_peer_present(config_text: str, user: dict) -> bool:
    awg_user = user.get("amneziawg", {})
    public_key = awg_user.get("public_key", "")
    address = awg_user.get("address", "")
    if not config_text or not public_key or not address:
        return False
    return f"PublicKey = {public_key}" in config_text and f"AllowedIPs = {address}" in config_text


def wireguard_peer_present(config_text: str, user: dict) -> bool:
    wg_user = user.get("wireguard", {})
    public_key = wg_user.get("public_key", "")
    address = wg_user.get("address", "")
    if not config_text or not public_key or not address:
        return False
    return f"PublicKey = {public_key}" in config_text and f"AllowedIPs = {address}" in config_text


def amneziawg_latest_handshakes(interface: str) -> tuple[dict[str, int], str]:
    tool = shutil.which("awg") or shutil.which("wg")
    if not tool:
        return {}, "awg/wg не найден"
    code, stdout, stderr = run_command_text([tool, "show", interface, "latest-handshakes"], timeout=15)
    if code != 0:
        return {}, stderr or stdout or f"{Path(tool).name} show завершился с ошибкой"
    result: dict[str, int] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            result[parts[0]] = int(parts[1])
        except ValueError:
            result[parts[0]] = 0
    return result, ""


def wireguard_latest_handshakes(interface: str) -> tuple[dict[str, int], str]:
    if not shutil.which("wg"):
        return {}, "wg не найден"
    code, stdout, stderr = run_command_text(["wg", "show", interface, "latest-handshakes"], timeout=15)
    if code != 0:
        return {}, stderr or stdout or "wg show завершился с ошибкой"
    result: dict[str, int] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            result[parts[0]] = int(parts[1])
        except ValueError:
            result[parts[0]] = 0
    return result, ""


def wireguard_transfer_stats(interface: str) -> tuple[dict[str, tuple[int, int]], str]:
    if not shutil.which("wg"):
        return {}, "wg не найден"
    code, stdout, stderr = run_command_text(["wg", "show", interface, "transfer"], timeout=15)
    if code != 0:
        return {}, stderr or stdout or "wg show transfer завершился с ошибкой"
    result: dict[str, tuple[int, int]] = {}
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            result[parts[0]] = (int(parts[1]), int(parts[2]))
        except ValueError:
            result[parts[0]] = (0, 0)
    return result, ""


def format_handshake(timestamp: int | None) -> str:
    if not timestamp:
        return "never"
    now = int(datetime.datetime.now(datetime.UTC).timestamp())
    delta = max(0, now - int(timestamp))
    if delta < 60:
        ago = f"{delta} сек назад"
    elif delta < 3600:
        ago = f"{delta // 60} мин назад"
    else:
        ago = f"{delta // 3600} ч назад"
    moment = datetime.datetime.fromtimestamp(timestamp, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"{ago} ({moment})"


def cmd_amneziawg(args: argparse.Namespace) -> None:
    state = load_state()
    changed = ensure_amneziawg_state(state)
    if changed:
        save_state(state)
        warn("в users.json дозаполнены недостающие AmneziaWG ключи; выполните render/sync при необходимости")

    if args.action == "verify":
        verification = verify_amneziawg_runtime(state)
        if not verification["ok"]:
            err(
                "AmneziaWG verification: "
                f"{verification['reason']}; expected={verification['expected_peers']}, "
                f"runtime={verification['runtime_peers']}"
            )
            raise SystemExit(1)
        ok(
            "AmneziaWG project/host/runtime совпадают: "
            f"peers={verification['runtime_peers']}"
        )
        return

    cfg = awg_config(state)
    interface = cfg.get("interface", "awg0")
    port = int(cfg.get("port", 51820))
    server = state.get("server", "YOUR_SERVER_IP")
    endpoint = f"{server}:{port}"
    users = [user for user in state.get("users", []) if "amneziawg" in user_systems(user)]
    if getattr(args, "name", None):
        user = find_user_or_exit(state, args.name)
        users = [user]

    header("AmneziaWG")
    print(f"endpoint клиента: {endpoint}")
    resolved = resolve_host_ips(server)
    print(f"DNS/IP endpoint: {', '.join(resolved) if resolved else 'не удалось определить'}")
    host_ips = host_global_ipv4s()
    print(f"IPv4 хоста: {', '.join(host_ips) if host_ips else 'не удалось определить'}")
    public_host_ips = []
    for host_ip in host_ips:
        try:
            if not ipaddress.ip_address(host_ip).is_private:
                public_host_ips.append(host_ip)
        except ValueError:
            continue
    if resolved and public_host_ips and not set(resolved).intersection(public_host_ips):
        warn(f"DNS {server} не совпадает с публичным IPv4 интерфейса: {', '.join(public_host_ips)}")
    print(f"interface/port: {interface} / {port}/udp")
    print(f"project config: {AMNEZIAWG_CONFIG.relative_to(ROOT).as_posix()} ({'есть' if AMNEZIAWG_CONFIG.exists() else 'нет'})")

    project_text, project_status = read_text_file(AMNEZIAWG_CONFIG)
    host_text, host_status = read_text_file(HOST_AMNEZIAWG_CONFIG)
    if host_status == "ok":
        same = "да" if amneziawg_configs_equivalent(project_text, host_text) else "нет"
        print(f"host config: {HOST_AMNEZIAWG_CONFIG} (есть, семантически совпадает с project: {same})")
    elif host_status == "permission":
        print(f"host config: {HOST_AMNEZIAWG_CONFIG} (нет прав на чтение)")
    else:
        print(f"host config: {HOST_AMNEZIAWG_CONFIG} ({host_status})")

    if shutil.which("systemctl"):
        active = run_capture(["systemctl", "is-active", "kvn-amneziawg.service"]) or "unknown"
        enabled = run_capture(["systemctl", "is-enabled", "kvn-amneziawg.service"]) or "unknown"
        print(f"systemd: active={active}, enabled={enabled}")
    else:
        print("systemd: недоступен")

    print(f"awg-quick: {'найден' if shutil.which('awg-quick') else 'не найден'}")
    if shutil.which("ip"):
        code, _stdout, _stderr = run_command_text(["ip", "link", "show", interface], timeout=10)
        print(f"interface {interface}: {'есть' if code == 0 else 'нет'}")
    if shutil.which("ss"):
        code, stdout, _stderr = run_command_text(["ss", "-H", "-lunp"], timeout=10)
        listening = code == 0 and any(re.search(rf"[:.]?{port}\b", line) for line in stdout.splitlines())
        print(f"UDP listen {port}: {'есть' if listening else 'не найден'}")
    print(f"ufw: {ufw_udp_status(port)}")
    print(f"iptables INPUT: {iptables_udp_input_status(port)}")
    print(f"IPv4 forwarding: {ipv4_forward_status()}")

    server_key_ok = amneziawg_key_pair_matches(cfg.get("private_key", ""), cfg.get("public_key", ""))
    print(f"server private/public key: {'совпадают' if server_key_ok else 'НЕ СОВПАДАЮТ'}")

    handshakes, handshake_error = amneziawg_latest_handshakes(interface)
    if handshake_error:
        print(f"handshakes: {handshake_error}")

    print()
    print(f"{C.bold}Peers{C.reset}")
    if not users:
        warn("пользователей с системой amneziawg нет")
    for user in users:
        awg_user = user.get("amneziawg", {})
        public_key = awg_user.get("public_key", "")
        address = awg_user.get("address", "")
        project_peer = amneziawg_peer_present(project_text, user)
        host_peer = amneziawg_peer_present(host_text, user) if host_status == "ok" else False
        enabled = user.get("enabled", True)
        systems = user_systems(user)
        print(f"- {user.get('name', '-')}: enabled={enabled}, system={'да' if 'amneziawg' in systems else 'нет'}")
        print(f"  address={address or '-'}, public_key={public_key[:12] + '...' if public_key else '-'}")
        client_key_ok = amneziawg_key_pair_matches(awg_user.get("private_key", ""), public_key)
        print(f"  client private/public key: {'совпадают' if client_key_ok else 'НЕ СОВПАДАЮТ'}")
        print(f"  peer в project/host: {'да' if project_peer else 'нет'} / {'да' if host_peer else 'нет' if host_status == 'ok' else 'неизвестно'}")
        if handshakes:
            print(f"  latest handshake: {format_handshake(handshakes.get(public_key))}")
        client_conf = CLIENTS_DIR / user.get("name", "") / "amneziawg.conf"
        print(f"  client config: {client_conf.relative_to(ROOT).as_posix()} ({'есть' if client_conf.exists() else 'нет'})")

    print()
    print("Если клиент висит на «ожидание рукопожатия»:")
    print(f"  1. проверьте, что UDP {port} открыт в ufw и cloud firewall")
    print(f"  2. проверьте, что endpoint {endpoint} указывает на этот сервер")
    print("  3. выполните: python3 tools/kvnctl.py render && sudo ./amneziawg/sync-host-service.sh")
    print("  4. на сервере проверьте: sudo awg show awg0 и sudo journalctl -u kvn-amneziawg.service -n 100 --no-pager")
    if shutil.which("tcpdump"):
        print(f"  5. во время подключения запустите: sudo tcpdump -ni any 'udp port {port}'")
    else:
        print("  5. tcpdump не найден: sudo apt-get update && sudo apt-get install -y tcpdump")
        print(f"     затем во время подключения: sudo tcpdump -ni any 'udp port {port}'")
    print("     нет пакетов — DNS/firewall/cloud firewall; пакеты есть — удалите старый профиль клиента и импортируйте свежий")


def cmd_wireguard(args: argparse.Namespace) -> None:
    state = load_state()
    changed = ensure_wireguard_state(state)
    if changed:
        save_state(state)
        warn("в users.json дозаполнены недостающие WireGuard ключи; выполните render/sync при необходимости")

    if args.action == "verify":
        verification = verify_wireguard_runtime(state)
        if not verification["ok"]:
            err(
                "WireGuard verification: "
                f"{verification['reason']}; expected={verification['expected_peers']}, "
                f"runtime={verification['runtime_peers']}"
            )
            raise SystemExit(1)
        ok(
            "WireGuard project/host/runtime совпадают: "
            f"peers={verification['runtime_peers']}"
        )
        return

    cfg = wireguard_config(state)
    interface = cfg.get("interface", "wg0")
    port = int(cfg.get("port", 51821))
    server = state.get("server", "YOUR_SERVER_IP")
    endpoint = f"{server}:{port}"
    users = [user for user in state.get("users", []) if "wireguard" in user_systems(user)]
    if getattr(args, "name", None):
        user = find_user_or_exit(state, args.name)
        users = [user]

    header("WireGuard")
    print(f"endpoint клиента: {endpoint}")
    resolved = resolve_host_ips(server)
    print(f"DNS/IP endpoint: {', '.join(resolved) if resolved else 'не удалось определить'}")
    host_ips = host_global_ipv4s()
    print(f"IPv4 хоста: {', '.join(host_ips) if host_ips else 'не удалось определить'}")
    public_host_ips = []
    for host_ip in host_ips:
        try:
            if not ipaddress.ip_address(host_ip).is_private:
                public_host_ips.append(host_ip)
        except ValueError:
            continue
    if resolved and public_host_ips and not set(resolved).intersection(public_host_ips):
        warn(f"DNS {server} не совпадает с публичным IPv4 интерфейса: {', '.join(public_host_ips)}")
    wan_iface = default_wan_iface()
    print(f"WAN interface: {wan_iface or 'не удалось определить'}")
    print(f"interface/port: {interface} / {port}/udp")
    print(f"project config: {WIREGUARD_CONFIG.relative_to(ROOT).as_posix()} ({'есть' if WIREGUARD_CONFIG.exists() else 'нет'})")

    project_text, project_status = read_text_file(WIREGUARD_CONFIG)
    host_text, host_status = read_text_file(HOST_WIREGUARD_CONFIG)
    if host_status == "ok":
        same = "да" if amneziawg_configs_equivalent(project_text, host_text) else "нет"
        print(f"host config: {HOST_WIREGUARD_CONFIG} (есть, семантически совпадает с project: {same})")
    elif host_status == "permission":
        print(f"host config: {HOST_WIREGUARD_CONFIG} (нет прав на чтение)")
    else:
        print(f"host config: {HOST_WIREGUARD_CONFIG} ({host_status})")

    if shutil.which("systemctl"):
        active = run_capture(["systemctl", "is-active", "kvn-wireguard.service"]) or "unknown"
        enabled = run_capture(["systemctl", "is-enabled", "kvn-wireguard.service"]) or "unknown"
        print(f"systemd: active={active}, enabled={enabled}")
    else:
        print("systemd: недоступен")

    print(f"wg-quick: {'найден' if shutil.which('wg-quick') else 'не найден'}")
    if shutil.which("ip"):
        code, _stdout, _stderr = run_command_text(["ip", "link", "show", interface], timeout=10)
        print(f"interface {interface}: {'есть' if code == 0 else 'нет'}")
    if shutil.which("ss"):
        code, stdout, _stderr = run_command_text(["ss", "-H", "-lunp"], timeout=10)
        listening = code == 0 and any(re.search(rf"[:.]?{port}\b", line) for line in stdout.splitlines())
        print(f"UDP listen {port}: {'есть' if listening else 'не найден'}")
    print(f"ufw: {ufw_udp_status(port)}")
    print(f"iptables INPUT: {iptables_udp_input_status(port)}")
    print(f"iptables FORWARD: {iptables_wireguard_forward_status(interface)}")
    print(f"iptables NAT: {iptables_masquerade_status(cfg.get('network', '10.88.88.0/24'), wan_iface)}")
    print(f"IPv4 forwarding: {ipv4_forward_status()}")

    server_key_ok = amneziawg_key_pair_matches(cfg.get("private_key", ""), cfg.get("public_key", ""))
    print(f"server private/public key: {'совпадают' if server_key_ok else 'НЕ СОВПАДАЮТ'}")

    handshakes, handshake_error = wireguard_latest_handshakes(interface)
    if handshake_error:
        print(f"handshakes: {handshake_error}")
    transfers, transfer_error = wireguard_transfer_stats(interface)
    if transfer_error:
        print(f"transfers: {transfer_error}")

    print()
    print(f"{C.bold}Peers{C.reset}")
    if not users:
        warn("пользователей с системой wireguard нет")
    for user in users:
        wg_user = user.get("wireguard", {})
        public_key = wg_user.get("public_key", "")
        address = wg_user.get("address", "")
        project_peer = wireguard_peer_present(project_text, user)
        host_peer = wireguard_peer_present(host_text, user) if host_status == "ok" else False
        enabled = user.get("enabled", True)
        systems = user_systems(user)
        print(f"- {user.get('name', '-')}: enabled={enabled}, system={'да' if 'wireguard' in systems else 'нет'}")
        print(f"  address={address or '-'}, public_key={public_key[:12] + '...' if public_key else '-'}")
        client_key_ok = amneziawg_key_pair_matches(wg_user.get("private_key", ""), public_key)
        print(f"  client private/public key: {'совпадают' if client_key_ok else 'НЕ СОВПАДАЮТ'}")
        print(f"  peer в project/host: {'да' if project_peer else 'нет'} / {'да' if host_peer else 'нет' if host_status == 'ok' else 'неизвестно'}")
        if handshakes:
            print(f"  latest handshake: {format_handshake(handshakes.get(public_key))}")
        if transfers:
            rx, tx = transfers.get(public_key, (0, 0))
            print(f"  transfer server rx/tx: {rx} / {tx} bytes")
        client_conf = CLIENTS_DIR / user.get("name", "") / "wireguard.conf"
        print(f"  client config: {client_conf.relative_to(ROOT).as_posix()} ({'есть' if client_conf.exists() else 'нет'})")

    print()
    user_public_keys = [user.get("wireguard", {}).get("public_key", "") for user in users]
    user_handshakes = [handshakes.get(public_key, 0) for public_key in user_public_keys if public_key]
    if user_public_keys and handshakes and not any(user_handshakes):
        warn("После попытки подключения handshake отсутствует: UDP 51821 не доходит до сервера или клиент использует старый профиль.")
    elif any(user_handshakes):
        print("Handshake есть. Если интернет не работает, проверяйте FORWARD/NAT, MTU и DNS на клиенте.")
    print("Если клиент подключается, но трафик не идёт:")
    print(f"  1. проверьте, что UDP {port} открыт в ufw и cloud firewall")
    print("  2. проверьте, что net.ipv4.ip_forward = 1")
    print(f"  3. проверьте endpoint {endpoint} и AllowedIPs = 0.0.0.0/0 в свежем wireguard.conf")
    print("  4. выполните: python3 tools/kvnctl.py render && sudo ./wireguard/sync-host-service.sh")
    print("  5. на сервере проверьте: sudo wg show wg0 и sudo journalctl -u kvn-wireguard.service -n 100 --no-pager")
    print(f"  6. во время подключения запустите: sudo tcpdump -ni any 'udp port {port}'")


# ── Команды CLI ──────────────────────────────────────────────────────────


def cmd_add_user(args: argparse.Namespace) -> None:
    state = load_state()
    validate_name(args.name)
    unique_name(state, args.name)

    systems = parse_systems(args.systems) if args.systems else list(DEFAULT_USER_SYSTEMS)

    user_uuid = validate_uuid(args.uuid) if args.uuid else str(uuid.uuid4())
    telemt_secret = validate_telemt_secret(args.telemt_secret) if args.telemt_secret else random_hex32()
    ocserv_password = getattr(args, "ocserv_password", None)
    user = {
        "name": args.name,
        "uuid": user_uuid,
        "hysteria_password": args.hysteria_password or random_password(),
        "telemt_secret": telemt_secret,
        "enabled": True,
        "description": args.description or "",
        "device": "",
        "systems": systems,
        "sni_overrides": {},
    }
    if ocserv_password:
        user["ocserv_password"] = validate_ocserv_password(ocserv_password)
    device = getattr(args, "device", None)
    applied = apply_device_profile(user, device, overwrite=True) if device else []

    state["users"].append(user)
    render_changed = render_all(state, args.server)
    save_state(state)
    if args.restart:
        restart_services(render_changed)
    ok(f"пользователь добавлен: {C.bold}{args.name}{C.reset}")
    print(f"  Системы: {', '.join(C.cyan + SYSTEM_LABELS[s] + C.reset for s in systems)}")
    if applied:
        print(f"  Устройство: {C.cyan}{user['device']}{C.reset} → SNI: {', '.join(user['sni_overrides'][s] for s in applied)}")
    try:
        print((CLIENTS_DIR / args.name / "links.txt").read_text(encoding="utf-8"))
    except FileNotFoundError:
        pass


def cmd_edit_user(args: argparse.Namespace) -> None:
    state = load_state()
    user = find_user_or_exit(state, args.name)
    changed = []

    # Переименование
    if args.new_name:
        validate_name(args.new_name)
        unique_name(state, args.new_name, exclude=args.name)
        old_name = user["name"]
        old_dir = CLIENTS_DIR / old_name
        user["name"] = args.new_name
        if old_dir.exists():
            old_dir.rename(CLIENTS_DIR / args.new_name)
        changed.append(f"name: {old_name} -> {args.new_name}")

    # Описание
    if args.description is not None:
        user["description"] = args.description
        changed.append(f"description: {args.description}")

    # Смена систем
    if args.systems:
        systems = parse_systems(args.systems)
        user["systems"] = systems
        sni_overrides = user.get("sni_overrides", {})
        stale = [k for k in sni_overrides if k not in systems]
        for k in stale:
            del sni_overrides[k]
            changed.append(f"sni {k}: удалён (система убрана)")
        changed.append(f"systems: {', '.join(systems)}")

    # Смена устройства (проставляет SNI-профиль экосистемы)
    if getattr(args, "device", None):
        applied = apply_device_profile(user, args.device, overwrite=True)
        if applied:
            changed.append(f"device: {user['device']} → SNI {', '.join(applied)}")
        else:
            changed.append("device: сброшен")

    # Смена SNI
    if args.sni:
        sni_overrides = user.setdefault("sni_overrides", {})
        for pair in args.sni:
            if "=" not in pair:
                raise SystemExit(f"Формат SNI: система=домен (например: tls=google.com). Получено: {pair}")
            sys_name, domain = pair.split("=", 1)
            if sys_name not in ALL_SYSTEMS:
                raise SystemExit(f"Неизвестная система: {sys_name}. Доступные: {', '.join(ALL_SYSTEMS)}")
            if sys_name not in USER_SNI_OVERRIDE_SYSTEMS:
                raise SystemExit(
                    f"SNI для {sys_name} не является пользовательским. "
                    f"Доступные per-user SNI: {', '.join(USER_SNI_OVERRIDE_SYSTEMS)}. "
                    f"Для Telemt/mtg используйте sni-routes."
                )
            if domain.strip().lower() in {"", "-", "none", "default", "reset", "стандарт"}:
                if sys_name in sni_overrides:
                    del sni_overrides[sys_name]
                    changed.append(f"sni {sys_name}: сброшен на default")
                continue
            domain = validate_sni_domain(domain)
            sni_overrides[sys_name] = domain
            changed.append(f"sni {sys_name}: {domain}")

    # Смена ключей
    if args.uuid:
        user["uuid"] = validate_uuid(args.uuid)
        changed.append(f"uuid: {user['uuid']}")
    if args.hysteria_password:
        user["hysteria_password"] = args.hysteria_password
        changed.append("hysteria_password: обновлён")
    if args.telemt_secret:
        user["telemt_secret"] = validate_telemt_secret(args.telemt_secret)
        changed.append("telemt_secret: обновлён")
    if getattr(args, "ocserv_password", None) is not None:
        user["ocserv_password"] = validate_ocserv_password(args.ocserv_password)
        changed.append("ocserv_password: обновлён")
    if args.regenerate_keys:
        user["uuid"] = str(uuid.uuid4())
        user["hysteria_password"] = random_password()
        user["telemt_secret"] = random_hex32()
        if "amneziawg" in user_systems(user):
            old_awg_address = user.get("amneziawg", {}).get("address", "")
            user["amneziawg"] = {
                "private_key": random_wg_private_key(),
                "preshared_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            }
            if old_awg_address:
                user["amneziawg"]["address"] = old_awg_address
        if "wireguard" in user_systems(user):
            old_wg_address = user.get("wireguard", {}).get("address", "")
            user["wireguard"] = {
                "private_key": random_wg_private_key(),
                "preshared_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            }
            if old_wg_address:
                user["wireguard"]["address"] = old_wg_address
        changed.append("Все ключи регенерированы")

    # Включить/выключить
    if args.enable is not None:
        user["enabled"] = args.enable
        changed.append(f"enabled: {args.enable}")

    if not changed:
        print(f"{C.yellow}Нечего менять. Укажите хотя бы один параметр.{C.reset}")
        return

    render_changed = render_all(state, args.server)
    save_state(state)
    if args.restart:
        restart_services(render_changed)

    ok(f"пользователь {C.bold}{user['name']}{C.reset} обновлён")
    for c in changed:
        print(f"  {C.dim}→{C.reset} {c}")


def cmd_remove_user(args: argparse.Namespace) -> None:
    state = load_state()
    user = find_user_or_exit(state, args.name)
    name = user["name"]

    state["users"] = [u for u in state["users"] if u["name"] != name]

    client_dir = CLIENTS_DIR / name
    if client_dir.exists():
        shutil.rmtree(client_dir)

    render_changed = render_all(state, args.server)
    save_state(state)
    if args.restart:
        restart_services(render_changed)
    ok(f"пользователь {C.bold}{name}{C.reset} удалён")


def cmd_reconcile(_args: argparse.Namespace) -> None:
    """Повторно рендерит и применяет текущий desired state."""
    def prepare(state: dict) -> None:
        prepare_state(state)

    transaction = STATE_STORE.update(prepare)
    render_result = render_all(transaction.state)
    plan = effective_service_plan(transaction.state)
    report = restart_services(
        render_result,
        before_state=transaction.before_state,
        after_state=transaction.state,
        force_host_sync_services=set(plan.enabled_host),
    )
    if report["outcome"] == "failed":
        raise SystemExit("Reconcile не завершён: " + "; ".join(report["warnings"]))
    ok(f"reconcile завершён: {report['outcome']}")


def cmd_service_plan(args: argparse.Namespace) -> None:
    """Печатает единый эффективный lifecycle-план без изменения state."""
    plan = effective_service_plan(load_state())
    data = plan.to_dict()
    if args.format == "json":
        print(json.dumps(data, ensure_ascii=False, sort_keys=True))
        return
    rows = (
        ("docker-enabled", ",".join(plan.enabled_docker)),
        ("docker-disabled", ",".join(plan.disabled_docker)),
        ("host-enabled", ",".join(plan.enabled_host)),
        ("host-disabled", ",".join(plan.disabled_host)),
        ("compose-profiles", ",".join(plan.compose_profiles)),
        ("portal-agent", "1" if plan.enabled("agent") else "0"),
    )
    for key, value in rows:
        print(f"{key}\t{value}")


def cmd_render(args: argparse.Namespace) -> None:
    state = load_state()
    if args.server:
        state["server"] = validate_host(args.server, "server")
    if args.certs:
        generate_all_certs(state)
    # Передаём server в render_all, чтобы новый IP сохранился в users.json.
    render_changed = render_all(state, args.server)
    save_state(state)
    if args.restart:
        restart_services(render_changed or args.certs)


def cmd_letsencrypt(args: argparse.Namespace) -> None:
    state = load_state()
    target = getattr(args, "target", "site")

    if args.action == "status":
        print_certificate_status(state, target)
        return
    if args.action == "issue-configured":
        issue_configured_letsencrypt(
            state,
            target,
            email=args.email,
            staging=args.staging,
            restart=args.restart,
            force_renewal=args.force_renewal,
        )
        return

    if args.action == "reissue":
        issue_configured_letsencrypt(
            state,
            target,
            email=args.email,
            staging=args.staging,
            restart=args.restart,
            force_renewal=True,
        )
        return

    if args.action == "issue":
        domains = [validate_sni_domain(domain) for domain in args.domain]
        domain = domains[0]
        email = args.email or letsencrypt_config(state).get("email", "")
        if target == "site":
            domains = site_issue_domains(state, domains)
        run_certbot_issue(domains, email=email or None, staging=args.staging, force_renewal=args.force_renewal)
        if target == "site":
            configure_letsencrypt_state(state, domains, email or None)
        elif target == "ocserv":
            cfg = ocserv_config(state)
            cfg["enabled"] = True
            cfg["sni_enabled"] = True
            cfg["sni"] = domain
            cfg["front_snis"] = [item for item in domains[1:] if item != domain]
            if email is not None:
                letsencrypt_config(state)["email"] = email
        else:
            raise SystemExit(f"Неизвестный target Let's Encrypt: {target}")
        save_state(state)
        deploy_letsencrypt_certificate(state, domains, restart=args.restart, target=target)
        install_letsencrypt_renewal_best_effort()
        if target == "site":
            ok(f"Let's Encrypt включён. Основной адрес подключений: {domain}")
        else:
            ok(f"Let's Encrypt для ocserv включён. OpenConnect SNI: {domain}")
        return

    if args.action == "deploy":
        domain = validate_sni_domain(args.domain) if args.domain else None
        domains: str | list[str] | None = domain
        if target == "ocserv":
            domains = domain or ocserv_cert_domains(state)
            cfg = ocserv_config(state)
            if domain and (not cfg.get("sni_enabled") or cfg.get("sni") != domain):
                cfg["enabled"] = True
                cfg["sni_enabled"] = True
                cfg["sni"] = domain
                save_state(state)
        elif args.domain and configure_letsencrypt_state(state, domain, None):
            save_state(state)
        else:
            domains = domain or letsencrypt_domains(state)
        deploy_letsencrypt_certificate(state, domains, restart=args.restart, target=target)
        return

    if args.action == "renew":
        if not shutil.which("certbot"):
            raise SystemExit("certbot не найден. Установите: apt-get install -y certbot")
        site_domains_for_cert = letsencrypt_domains(state)
        oc_domains_for_cert = ocserv_cert_domains(state)
        domains = list(site_domains_for_cert)
        for oc_domain in oc_domains_for_cert:
            if oc_domain and oc_domain not in domains:
                domains.append(oc_domain)
        domains = [domain for domain in domains if domain]
        portal = state.get("portal", {})
        portal_ip = ""
        if isinstance(portal, dict) and portal.get("enabled") and portal.get("domain"):
            candidate = validate_portal_host(str(portal["domain"]))
            if portal_host_kind(candidate) == "ipv4":
                portal_ip = candidate
        if not domains and not portal_ip:
            warn("Let's Encrypt домены не настроены — renew пропущен")
            return
        nginx_stopped = _stop_docker_service_best_effort("nginx")
        try:
            result = subprocess.run(["certbot", "renew", "--non-interactive"], cwd=ROOT, check=False, timeout=300)
        finally:
            if nginx_stopped:
                _start_docker_service_best_effort("nginx")
        if result.returncode != 0:
            raise SystemExit("certbot renew завершился с ошибкой")
        deployed_targets: list[str] = []
        if site_domains_for_cert:
            if existing_letsencrypt_live_domain(site_domains_for_cert):
                deploy_letsencrypt_certificate(state, site_domains_for_cert, restart=False, target="site")
                deployed_targets.append("site")
            else:
                warn(f"live-сертификат сайта не найден для {', '.join(site_domains_for_cert)} — deploy пропущен")
        if oc_domains_for_cert:
            if existing_letsencrypt_live_domain(oc_domains_for_cert):
                deploy_letsencrypt_certificate(state, oc_domains_for_cert, restart=False, target="ocserv")
                deployed_targets.append("ocserv")
            else:
                warn(f"live-сертификат ocserv не найден для {', '.join(oc_domains_for_cert)} — deploy пропущен")
        if portal_ip:
            if (LE_LIVE_DIR / portal_ip / "fullchain.pem").exists():
                deploy_letsencrypt_ip_certificate(state, portal_ip, restart=False)
                if "site" not in deployed_targets:
                    deployed_targets.append("site")
            else:
                warn(f"live IP-сертификат портала не найден для {portal_ip} — deploy пропущен")
        if args.restart:
            for deployed_target in deployed_targets:
                reload_certificate_consumers(state, deployed_target)
        ok("Let's Encrypt renew выполнен")
        return

    if args.action == "install-renewal":
        install_letsencrypt_renewal_best_effort()
        return

    raise SystemExit(f"Неизвестное действие letsencrypt: {args.action}")


def invalidate_portal_sessions() -> None:
    database = ROOT / "portal-data" / "portal.db"
    if not database.exists():
        return
    with closing(sqlite3.connect(database, timeout=10)) as db:
        db.execute("DELETE FROM sessions")
        db.commit()


def _prompt_yes_no(prompt: str, default: bool) -> bool:
    while True:
        answer = input(prompt).strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes", "д", "да"}:
            return True
        if answer in {"n", "no", "н", "нет"}:
            return False
        err("Введите y/да или n/нет")


def _prompt_validated(
    argument,
    prompt: str,
    default: str,
    validator,
    *,
    interactive: bool,
):
    if argument is not None:
        return validator(str(argument))
    if not interactive:
        return validator(default)
    while True:
        candidate = input(f"{prompt} [{default}]: ").strip() or default
        try:
            return validator(candidate)
        except SystemExit as exc:
            err(str(exc))


def _portal_password_twice() -> str:
    while True:
        first = getpass.getpass("Пароль портала: ")
        second = getpass.getpass("Повторите пароль портала: ")
        if not secrets.compare_digest(first, second):
            err("Пароли не совпадают")
            continue
        try:
            return validate_portal_password(first)
        except SystemExit as exc:
            err(str(exc))


def restart_portal_container_best_effort() -> None:
    if not shutil.which("docker"):
        return
    result = _run_compose(["restart", "portal"], timeout=60)
    if result.returncode != 0:
        warn("учётные данные сохранены, но контейнер portal нужно перезапустить вручную")


def cmd_updates(args: argparse.Namespace) -> None:
    """Настраивает фиксированный GitHub Release источник без вывода token."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from portal.github_updates import (
        GITHUB_TOKEN_FILE,
        GitHubUpdateError,
        github_token_status,
        normalize_github_settings,
    )

    state = load_state()
    try:
        current = normalize_github_settings(state)
    except GitHubUpdateError as exc:
        raise SystemExit(str(exc)) from exc
    if args.action == "status":
        credential = github_token_status(GITHUB_TOKEN_FILE)
        print(f"enabled: {'да' if current['enabled'] else 'нет'}")
        print(f"repository: {current['owner']}/{current['repo']}")
        print(f"channel: {current['channel']}")
        if current["tag"]:
            print(f"tag: {current['tag']}")
        print(f"asset: {current['asset_preference']}")
        print(f"credential: {'настроен' if credential['configured'] else 'не настроен'}")
        print(f"credential-secure: {'да' if credential['secure'] else 'нет'}")
        return

    enabled = current["enabled"] if args.enable is None else bool(args.enable)
    channel = args.channel or current["channel"]
    tag = current["tag"] if args.tag is None else args.tag.strip()
    if channel == "stable":
        tag = ""
    preference = args.asset_preference or current["asset_preference"]
    state["updates"] = state.get("updates", {})
    state["updates"]["github"] = {
        "enabled": enabled,
        "owner": current["owner"],
        "repo": current["repo"],
        "channel": channel,
        "tag": tag,
        "asset_preference": preference,
    }
    try:
        normalize_github_settings(state, mutate=True)
    except GitHubUpdateError as exc:
        raise SystemExit(str(exc)) from exc

    token_value = ""
    if args.set_token:
        token_value = getpass.getpass("GitHub token (Contents: read): ").strip()
        if not token_value or len(token_value) > 512 or any(
            char.isspace() or ord(char) < 33 for char in token_value
        ):
            raise SystemExit("GitHub token имеет недопустимый формат")
    elif args.token_file:
        try:
            supplied_token_file = Path(args.token_file).expanduser()
            supplied_status = supplied_token_file.stat()
            if (
                not supplied_token_file.is_file()
                or supplied_token_file.is_symlink()
                or (os.name == "posix" and supplied_status.st_mode & 0o077)
            ):
                raise OSError("token-файл должен быть обычным root-only файлом")
            token_value = supplied_token_file.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise SystemExit("Не удалось безопасно прочитать указанный root-only token-файл") from exc
        if not token_value or len(token_value) > 512 or any(
            char.isspace() or ord(char) < 33 for char in token_value
        ):
            raise SystemExit("GitHub token имеет недопустимый формат")

    save_state(state)
    if args.clear_token:
        GITHUB_TOKEN_FILE.unlink(missing_ok=True)
    elif token_value:
        try:
            atomic_write_private(GITHUB_TOKEN_FILE, token_value + "\n")
            if os.name == "posix":
                os.chown(GITHUB_TOKEN_FILE, 0, 0)
        except OSError as exc:
            raise SystemExit("Не удалось записать /etc/kvn-portal/github.token; запустите через sudo") from exc
    ok("настройки GitHub Releases сохранены; значение token не выводится")


def cmd_portal(args: argparse.Namespace) -> None:
    state = load_state()
    current = state.get("portal", {}) if isinstance(state.get("portal", {}), dict) else {}
    if args.action == "status":
        cfg = portal_config(state)
        print(f"enabled: {'да' if cfg.get('enabled') else 'нет'}")
        if cfg.get("enabled"):
            suffix = ":" + str(cfg["port"]) if cfg["port"] != 443 else ""
            print(f"name: {cfg['name']}")
            print(f"url: https://{cfg['domain']}{suffix}{cfg['path']}/")
            print(f"host-kind: {portal_host_kind(cfg['domain'])}")
            print(f"public-ready: {'да' if portal_public_ready(state) else 'нет'}")
            if portal_host_kind(cfg["domain"]) == "ipv4":
                print(f"self-signed-ip: {'разрешён' if cfg['allow_self_signed_ip'] else 'запрещён'}")
            print(f"login: {cfg['login']}")
            print(f"certificate: {certificate_source(SITE_CERTS_DIR / 'server.crt')}")
        return
    if args.action == "unlock-ip":
        address = str(ipaddress.ip_address(args.ip))
        database = ROOT / "portal-data" / "portal.db"
        if database.exists():
            with closing(sqlite3.connect(database, timeout=10)) as db:
                db.execute("DELETE FROM login_failures WHERE ip=?", (address,))
                db.commit()
        ok(f"блокировка IP снята: {address}")
        return
    if args.action == "reset-credentials":
        cfg = portal_config(state)
        if not cfg.get("enabled"):
            raise SystemExit("Портал отключён")
        login = _prompt_validated(
            args.login,
            "Логин",
            cfg["login"],
            validate_portal_login,
            interactive=args.login is None,
        )
        cfg["login"] = login
        cfg["password_hash"] = hash_portal_password(_portal_password_twice())
        save_state(state)
        invalidate_portal_sessions()
        restart_portal_container_best_effort()
        ok("учётные данные портала изменены; активные сессии закрыты")
        return

    interactive = args.enable is None
    if interactive:
        default_enabled = bool(current.get("enabled", False))
        prompt = "Включить web-портал? [Y/n]: " if default_enabled else "Включить web-портал? [y/N]: "
        enabled = _prompt_yes_no(prompt, default_enabled)
    else:
        enabled = bool(args.enable)
    if not enabled:
        if interactive:
            if input("Для отключения введите ОТКЛЮЧИТЬ: ").strip() != "ОТКЛЮЧИТЬ":
                raise SystemExit("Отключение портала отменено")
        elif not args.confirm_disable:
            raise SystemExit("Для отключения добавьте --confirm-disable")
        state.setdefault("portal", {})["enabled"] = False
        save_state(state)
        ok("web-портал отключён; VPN-сервисы не изменены")
        return

    cfg = state.setdefault("portal", {})
    old_login = str(current.get("login", ""))
    old_hash = str(current.get("password_hash", ""))
    cfg.update({
        "enabled": True,
        "name": _prompt_validated(
            args.name, "Название портала", str(current.get("name", "KVN VPN")),
            validate_site_title, interactive=interactive,
        ),
        "domain": _prompt_validated(
            args.domain, "Домен или публичный IPv4 портала", str(current.get("domain", "")),
            validate_portal_host, interactive=interactive,
        ),
        "port": _prompt_validated(
            args.port, "Публичный HTTPS-порт", str(current.get("port", 8443)),
            lambda value: validate_portal_port(value, state), interactive=interactive,
        ),
        "path": _prompt_validated(
            args.path, "Путь портала", str(current.get("path", "/admin")),
            validate_portal_path, interactive=interactive,
        ),
        "login": _prompt_validated(
            args.login, "Логин", old_login or "admin",
            validate_portal_login, interactive=interactive,
        ),
    })
    cfg.setdefault("proxy_secret", secrets.token_hex(32))
    cfg.setdefault("hysteria_secret", secrets.token_hex(32))
    host_kind = portal_host_kind(cfg["domain"])
    if host_kind == "ipv4":
        if cfg["port"] == 443:
            raise SystemExit("Для портала по IP укажите отдельный HTTPS-порт, например --port 8443")
        if args.allow_self_signed_ip is not None:
            cfg["allow_self_signed_ip"] = bool(args.allow_self_signed_ip)
        elif interactive:
            cfg["allow_self_signed_ip"] = _prompt_yes_no(
                "Разрешить self-signed IP SAN как безопасный fallback? [y/N]: ", False,
            )
        else:
            cfg.setdefault("allow_self_signed_ip", False)
    else:
        cfg["allow_self_signed_ip"] = False
    change_credentials = bool(args.reset_credentials or not old_hash or cfg["login"] != old_login)
    if interactive and old_hash and cfg["login"] == old_login:
        change_credentials = _prompt_yes_no("Изменить логин/пароль? [y/N]: ", False)
    cfg["password_hash"] = hash_portal_password(_portal_password_twice()) if change_credentials else old_hash
    if host_kind == "domain":
        le = letsencrypt_config(state)
        domains = letsencrypt_domains(state)
        if cfg["domain"] not in domains:
            domains.append(cfg["domain"])
        le["enabled"] = True
        le["domain"] = le.get("domain") or cfg["domain"]
        le["domains"] = domains
    portal_config(state)
    save_state(state)
    render_result = render_all(state)
    save_state(state)
    if change_credentials:
        invalidate_portal_sessions()
    if args.restart:
        restart_services(render_result)
        restart_portal_container_best_effort()
    if host_kind == "ipv4":
        ok("web-портал настроен; route откроется после установки сертификата с совпадающим IP SAN")
    else:
        ok("web-портал настроен; публичный route откроется только после выпуска Let's Encrypt")
    suffix = ":" + str(cfg["port"]) if cfg["port"] != 443 else ""
    print(f"URL: https://{cfg['domain']}{suffix}{cfg['path']}/")


def cmd_list(args: argparse.Namespace) -> None:
    state = load_state()
    header("Список пользователей")
    # Флаг и страна сервера (best-effort, из кэша или по IP).
    server = state.get("server", "")
    if server:
        ensure_server_country(state)
        geo = state.get("server_geo", {})
        if geo.get("ip") == server:
            flag = flag_emoji(geo.get("country_code", ""))
            country = geo.get("country", "")
        else:
            flag = ""
            country = ""
        srv_line = f"  {C.dim}Сервер:{C.reset} {C.bold}{server}{C.reset}"
        if flag:
            srv_line += f"  {flag} {C.dim}{country}{C.reset}"
        print(srv_line)
        print()
    for user in state["users"]:
        enabled = user.get("enabled", True)
        status_color = C.green if enabled else C.red
        status = f"{status_color}●{C.reset}" if enabled else f"{status_color}○{C.reset}"
        systems = user_systems(user)
        desc = user.get("description", "")
        dev = user.get("device", "")
        line = f"  {status} {C.bold}{user['name']}{C.reset}\t{C.dim}{user['uuid']}{C.reset}\t{C.cyan}[{','.join(systems)}]{C.reset}"
        if dev:
            line += f"\t{C.magenta}{dev}{C.reset}"
        if desc:
            line += f"\t{C.dim}{desc}{C.reset}"
        print(line)


def client_export_command_state(
    *,
    server: str = "",
    render_changed_clients: bool = False,
) -> tuple[dict, str]:
    """Готовит state для CLI-экспорта без изменения временного endpoint."""
    state = load_state()
    public_key, changed = ensure_reality_public_key(state, "reality")
    _, tcp_changed = ensure_reality_public_key(state, "reality_tcp")
    awg_changed = ensure_amneziawg_state(state)
    wg_changed = ensure_wireguard_state(state)
    if changed or tcp_changed or awg_changed or wg_changed:
        save_state(state)
    if render_changed_clients and (awg_changed or wg_changed):
        render_amneziawg(state)
        render_wireguard(state)
        write_client_files(state, public_key)
    if server:
        state = copy.deepcopy(state)
        state["server"] = validate_host(server, "server")
    return state, public_key


def enabled_user_by_name(state: dict, name: str) -> dict:
    """Возвращает включённого пользователя или единообразную CLI-ошибку."""
    user = next(
        (
            candidate
            for candidate in enabled_users(state)
            if candidate["name"].lower() == name.lower()
        ),
        None,
    )
    if user is None:
        raise SystemExit(f"Пользователь не найден: {name}")
    return user


def cmd_links(args: argparse.Namespace) -> None:
    state, public_key = client_export_command_state(
        server=args.server or "",
        render_changed_clients=True,
    )

    users = enabled_users(state)
    if args.all:
        for user in users:
            print(user_links_text(state, user, public_key))
        return

    if not args.name:
        raise SystemExit("Укажите имя пользователя или --all")
    user = enabled_user_by_name(state, args.name)
    print(user_links_text(state, user, public_key))


def cmd_export_links(args: argparse.Namespace) -> None:
    """Выводит ссылки в формате готовом для отправки (без markdown)."""
    state, public_key = client_export_command_state(
        server=args.server or "",
        render_changed_clients=True,
    )

    users = enabled_users(state)
    if args.all:
        for user in users:
            print(user_send_text(state, user, public_key))
            print("")
        return

    if not args.name:
        raise SystemExit("Укажите имя пользователя или --all")
    user = enabled_user_by_name(state, args.name)
    print(user_send_text(state, user, public_key))
    send_path = CLIENTS_DIR / user["name"] / "send.txt"
    print(f"\n[Сохранено: {send_path}]")


def cmd_export_user(args: argparse.Namespace) -> None:
    """Экспортирует одного пользователя без сохранения временного endpoint."""
    state, public_key = client_export_command_state()

    if args.public_ip and args.address_mode != "public-ip":
        raise SystemExit("--public-ip используется только с --address-mode public-ip")
    if args.address_mode:
        try:
            state = with_client_export_policy(
                state,
                address_mode=args.address_mode,
                public_ip=args.public_ip or "",
            )
        except ClientExportValidationError as exc:
            raise SystemExit(str(exc)) from exc

    user = enabled_user_by_name(state, args.name)

    sections = user_export_sections(state, user, public_key)
    payload = serialize_user_export(
        username=user["name"],
        connection_host=client_connection_host(state),
        sections=sections,
        output_format=args.format,
    )
    if args.output:
        atomic_write_private(args.output, payload)
        print(f"[OK] Экспорт записан: {args.output.expanduser().resolve()}")
        return
    sys.stdout.write(payload)


def cmd_interactive(args: argparse.Namespace) -> None:
    """Интерактивный мастер управления пользователями."""
    if not sys.stdin.isatty():
        raise SystemExit("Интерактивный режим требует терминал (TTY). Запустите без аргументов или используйте команды CLI.")

    state = load_state()
    if args.server:
        state["server"] = args.server
        save_state(state)

    header("KVN VPN v3 — Интерактивное управление")
    print()

    system_labels = SYSTEM_LABELS
    session_changed = False

    def _ask_systems(user: dict | None = None) -> list[str]:
        enabled = []
        print(f"  {C.dim}Enter = оставить значение по умолчанию, y = включить, n = выключить{C.reset}")
        print()
        for sys_name, label in system_labels.items():
            default = "Y" if sys_name in DEFAULT_USER_SYSTEMS else "N"
            if user is not None:
                default = "Y" if sys_name in user_systems(user) else "N"
            color = C.green if default == "Y" else C.dim
            yn = input(f"  {color}[{default}]{C.reset} {label} ({C.cyan}{sys_name}{C.reset}): ").strip()
            if yn == "":
                if default == "Y":
                    enabled.append(sys_name)
                continue
            if yn.lower().startswith("n"):
                continue
            enabled.append(sys_name)
        if not enabled:
            raise SystemExit("Нужно включить хотя бы одну систему")
        return enabled

    def _set_amneziawg(name: str, enable: bool) -> None:
        state = load_state()
        user = find_user(state, name)
        if not user:
            err(f"пользователь не найден: {name}")
            return
        systems = list(user_systems(user))
        if enable and "amneziawg" not in systems:
            systems.append("amneziawg")
        if not enable:
            systems = [s for s in systems if s != "amneziawg"]
        _run(
            cmd_edit_user,
            name=name,
            new_name=None,
            description=None,
            systems=",".join(systems),
            sni=None,
            uuid=None,
            hysteria_password=None,
            telemt_secret=None,
            regenerate_keys=False,
            enable=None,
            server=args.server,
            restart=False,
        )

    def _run(func, **kwargs) -> None:
        nonlocal session_changed
        before_fingerprint = generated_fingerprint()
        try:
            tmp = argparse.Namespace(**kwargs)
            func(tmp)
        except SystemExit as e:
            code = getattr(e, "code", None)
            if code and str(code) != "0":
                err(str(code))
        finally:
            if generated_fingerprint() != before_fingerprint:
                session_changed = True

    while True:
        print()
        print(f"  {C.bold}Доступные действия:{C.reset}")
        print(f"  {C.green}[1]{C.reset} Добавить пользователя")
        print(f"  {C.green}[2]{C.reset} Показать ссылки для отправки")
        print(f"  {C.green}[3]{C.reset} Список пользователей")
        print(f"  {C.yellow}[4]{C.reset} Удалить пользователя")
        print(f"  {C.yellow}[5]{C.reset} Переименовать пользователя")
        print(f"  {C.yellow}[6]{C.reset} Изменить системы пользователя")
        print(f"  {C.yellow}[7]{C.reset} Включить AmneziaWG пользователю")
        print(f"  {C.yellow}[8]{C.reset} Выключить AmneziaWG пользователю")
        print(f"  {C.green}[9]{C.reset} Показать AmneziaWG QR/конфиг")
        print(f"  {C.yellow}[10]{C.reset} Изменить SNI пользователя")
        print(f"  {C.yellow}[11]{C.reset} Изменить SNI сервиса")
        print(f"  {C.yellow}[12]{C.reset} Изменить пароль OpenConnect/ocserv")
        if getattr(args, "no_restart_on_exit", False):
            print(f"  {C.red}[0]{C.reset} Выход без перезапуска сервисов")
        else:
            print(f"  {C.red}[0]{C.reset} Выход и перезапуск сервисов")
        print()
        choice = input(f"  {C.bold}→{C.reset} Выберите действие: ").strip()
        print()

        if choice == "1":
            name = input("  Имя пользователя: ").strip()
            if not name:
                err("Имя не может быть пустым.")
                continue
            try:
                validate_name(name)
                unique_name(load_state(), name)
            except SystemExit as e:
                err(str(e))
                continue
            print()
            print(f"  {C.bold}Тип устройства{C.reset} {C.dim}(подберёт SNI под экосистему){C.reset}:")
            print(f"    {C.green}[1]{C.reset} iOS {C.dim}(apple){C.reset}   {C.green}[2]{C.reset} Android {C.dim}(google){C.reset}   {C.green}[3]{C.reset} Windows {C.dim}(microsoft){C.reset}   {C.dim}[Enter] пропустить{C.reset}")
            dev_choice = input(f"  {C.bold}→{C.reset} Устройство: ").strip()
            device = {"1": "ios", "2": "android", "3": "windows"}.get(dev_choice)
            print()
            print(f"  {C.bold}Выберите системы для {C.cyan}{name}{C.reset}{C.bold}:{C.reset}")
            try:
                systems = _ask_systems()
            except SystemExit as e:
                err(str(e))
                continue
            if "amneziawg" in systems:
                warn("AmneziaWG использует отдельный порт 51820/udp. Его нужно открыть в firewall.")
            if "wireguard" in systems:
                warn("WireGuard использует отдельный порт 51821/udp. Его нужно открыть в firewall.")
            ocserv_password = None
            if "ocserv" in systems:
                while True:
                    entered_password = getpass.getpass("  Пароль OpenConnect/ocserv (Enter — сгенерировать): ").strip()
                    if not entered_password:
                        break
                    confirm_password = getpass.getpass("  Повторите пароль: ").strip()
                    if entered_password != confirm_password:
                        err("пароли не совпадают")
                        continue
                    try:
                        ocserv_password = validate_ocserv_password(entered_password)
                    except SystemExit as exc:
                        err(str(exc))
                        continue
                    break
            print()
            dev_note = f", устройство: {device}" if device else ""
            print(f"  {C.dim}→ Создаю {name} (системы: {', '.join(systems)}{dev_note}) ...{C.reset}")
            _run(
                cmd_add_user,
                name=name,
                systems=",".join(systems),
                uuid=None,
                hysteria_password=None,
                telemt_secret=None,
                ocserv_password=ocserv_password,
                description="",
                device=device,
                server=args.server,
                restart=False,
            )

        elif choice == "2":
            name = input(f"  Имя пользователя (или {C.bold}all{C.reset} для всех): ").strip()
            if not name:
                continue
            _run(
                cmd_export_links,
                name=name if name != "all" else None,
                all=(name == "all"),
                server=args.server,
            )

        elif choice == "3":
            separator()
            try:
                cmd_list(argparse.Namespace())
            except SystemExit:
                pass
            separator()

        elif choice == "4":
            name = input("  Имя пользователя для удаления: ").strip()
            if not name:
                continue
            confirm = input(f"  {C.red}Удалить {name}? (y/N):{C.reset} ").strip()
            if not confirm.lower().startswith("y"):
                continue
            _run(cmd_remove_user, name=name, server=args.server, restart=False)

        elif choice == "5":
            old_name = input("  Текущее имя: ").strip()
            new_name = input("  Новое имя: ").strip()
            if not old_name or not new_name:
                continue
            _run(
                cmd_edit_user,
                name=old_name,
                new_name=new_name,
                description=None,
                systems=None,
                sni=None,
                uuid=None,
                hysteria_password=None,
                telemt_secret=None,
                regenerate_keys=False,
                enable=None,
                server=args.server,
                restart=False,
            )

        elif choice == "6":
            name = input("  Имя пользователя: ").strip()
            if not name:
                continue
            state = load_state()
            user = find_user(state, name)
            if not user:
                err(f"пользователь не найден: {name}")
                continue
            print()
            print(f"  {C.bold}Системы для {C.cyan}{name}{C.reset}{C.bold}:{C.reset}")
            try:
                systems = _ask_systems(user)
            except SystemExit as e:
                err(str(e))
                continue
            if "amneziawg" in systems and "amneziawg" not in user_systems(user):
                warn("AmneziaWG использует отдельный порт 51820/udp. Его нужно открыть в firewall.")
            if "wireguard" in systems and "wireguard" not in user_systems(user):
                warn("WireGuard использует отдельный порт 51821/udp. Его нужно открыть в firewall.")
            _run(
                cmd_edit_user,
                name=name,
                new_name=None,
                description=None,
                systems=",".join(systems),
                sni=None,
                uuid=None,
                hysteria_password=None,
                telemt_secret=None,
                regenerate_keys=False,
                enable=None,
                server=args.server,
                restart=False,
            )

        elif choice == "7":
            name = input("  Имя пользователя: ").strip()
            if name:
                warn("Не забудьте открыть 51820/udp в firewall/cloud-firewall.")
                _set_amneziawg(name, True)

        elif choice == "8":
            name = input("  Имя пользователя: ").strip()
            if name:
                _set_amneziawg(name, False)

        elif choice == "9":
            name = input("  Имя пользователя: ").strip()
            if not name:
                continue
            before_fingerprint = generated_fingerprint()
            state = load_state()
            user = find_user(state, name)
            if not user:
                err(f"пользователь не найден: {name}")
                continue
            if "amneziawg" not in user_systems(user):
                err("у пользователя не включён amneziawg")
                continue
            if ensure_amneziawg_state(state):
                save_state(state)
                render_amneziawg(state)
                public_key, _ = ensure_reality_public_key(state, "reality")
                write_client_files(state, public_key)
            awg_text = amneziawg_client_conf(state, user)
            qr_path = CLIENTS_DIR / user["name"] / "amneziawg.png"
            qr_created = write_qr_png(awg_text, qr_path)
            qr_text = terminal_qr(awg_text)
            print()
            if qr_text:
                print(qr_text)
            else:
                warn("qrencode не найден или завершился с ошибкой — QR в терминале не показан.")
            conf_path = CLIENTS_DIR / user["name"] / "amneziawg.conf"
            print(f"  Файл конфига: {conf_path}")
            if qr_created or qr_path.exists():
                print(f"  QR PNG:       {qr_path}")
            else:
                print("  QR PNG:       не создан (qrencode не найден или завершился с ошибкой)")
            print()
            print(awg_text)
            if generated_fingerprint() != before_fingerprint:
                session_changed = True

        elif choice == "10":
            name = input("  Имя пользователя: ").strip()
            system = input(f"  Система ({', '.join(USER_SNI_OVERRIDE_SYSTEMS)}): ").strip()
            domain = input("  Новый SNI или 'default' для сброса: ").strip()
            if not name or not system or not domain:
                continue
            _run(
                cmd_edit_user,
                name=name,
                new_name=None,
                description=None,
                systems=None,
                sni=[f"{system}={domain}"],
                uuid=None,
                hysteria_password=None,
                telemt_secret=None,
                regenerate_keys=False,
                enable=None,
                server=args.server,
                restart=False,
            )

        elif choice == "11":
            print(f"  Системы: {', '.join(SNI_ROUTE_SYSTEMS)}")
            system = input("  Система: ").strip()
            if system not in SNI_ROUTE_SYSTEMS:
                err(f"неизвестная система: {system}")
                continue
            state = load_state()
            route = ensure_sni_route(state, system)
            print(f"  Текущий default: {route.get('default', '-')}")
            print(f"  Текущие aliases: {', '.join(route.get('aliases', []))}")
            default_sni = input("  Новый default SNI (Enter — оставить): ").strip()
            aliases = input("  Новый полный список aliases через запятую (Enter — оставить): ").strip()
            if default_sni:
                _run(cmd_sni_routes, action="set-default", system=system, sni=default_sni, restart=False)
            if aliases:
                _run(cmd_sni_routes, action="set-aliases", system=system, aliases=aliases, restart=False)

        elif choice == "12":
            name = input("  Имя пользователя: ").strip()
            if not name:
                continue
            user = find_user(load_state(), name)
            if not user:
                err(f"пользователь не найден: {name}")
                continue
            if "ocserv" not in user_systems(user):
                err("у пользователя не включён ocserv")
                continue
            new_password = getpass.getpass("  Новый пароль OpenConnect/ocserv: ").strip()
            confirm_password = getpass.getpass("  Повторите пароль: ").strip()
            if new_password != confirm_password:
                err("пароли не совпадают")
                continue
            _run(
                cmd_edit_user,
                name=name,
                new_name=None,
                description=None,
                systems=None,
                sni=None,
                uuid=None,
                hysteria_password=None,
                telemt_secret=None,
                ocserv_password=new_password,
                regenerate_keys=False,
                enable=None,
                server=args.server,
                restart=False,
            )

        elif choice == "0":
            print()
            if getattr(args, "no_restart_on_exit", False):
                ok("выход без перезапуска; setup применит изменения позже")
            else:
                info("Проверка изменений перед перезапуском сервисов...")
                restart_services(session_changed)
            print()
            break
        else:
            err("неверный выбор")

        print()


def cmd_show(args: argparse.Namespace) -> None:
    state = load_state()
    user = find_user_or_exit(state, args.name)
    systems = user_systems(user)
    show_secrets = getattr(args, "show_secrets", False)

    header(f"Пользователь: {user['name']}")
    print(f"  {C.dim}Имя:{C.reset}         {C.bold}{user['name']}{C.reset}")
    print(f"  {C.dim}Описание:{C.reset}    {user.get('description', '-')}")
    uuid_value = user["uuid"] if show_secrets else mask_secret(user["uuid"], 8)
    print(f"  {C.dim}UUID:{C.reset}        {uuid_value}")
    enabled_str = f"{C.green}да{C.reset}" if user.get("enabled", True) else f"{C.red}нет{C.reset}"
    print(f"  {C.dim}Включён:{C.reset}     {enabled_str}")
    device = user.get("device", "")
    if device:
        print(f"  {C.dim}Устройство:{C.reset}  {C.magenta}{device}{C.reset}")
    print(f"  {C.dim}Системы:{C.reset}     {', '.join(C.cyan + SYSTEM_LABELS[s] + C.reset for s in systems)}")
    hysteria_value = user.get("hysteria_password", "-")
    telemt_value = user.get("telemt_secret", "-")
    if not show_secrets:
        hysteria_value = mask_secret(hysteria_value)
        telemt_value = mask_secret(telemt_value)
    print(f"  {C.dim}Hysteria:{C.reset}    {hysteria_value}")
    print(f"  {C.dim}Telemt:{C.reset}      {telemt_value}")
    if "amneziawg" in systems:
        awg_user = user.get("amneziawg", {})
        print(f"  {C.dim}AmneziaWG:{C.reset}   {awg_user.get('address', '-')}  {C.dim}(порт {awg_config(state).get('port', 51820)}/udp){C.reset}")
    if "wireguard" in systems:
        wg_user = user.get("wireguard", {})
        print(f"  {C.dim}WireGuard:{C.reset}   {wg_user.get('address', '-')}  {C.dim}(порт {wireguard_config(state).get('port', 51821)}/udp){C.reset}")
    if "ocserv" in systems:
        oc_password = user.get("ocserv_password", "-")
        if not show_secrets:
            oc_password = mask_secret(oc_password)
        oc_host = ocserv_sni(state) or state.get("server", "-")
        oc_port = 443 if ocserv_config(state).get("sni_enabled") else ocserv_public_tcp_port(state)
        print(f"  {C.dim}OpenConnect:{C.reset} https://{oc_host}:{oc_port}/  {C.dim}password:{C.reset} {oc_password}")
    sni_overrides = user.get("sni_overrides", {})
    if sni_overrides:
        print(f"  {C.dim}SNI оверрайды:{C.reset}")
        for sys_name, domain in sni_overrides.items():
            print(f"    {C.green}{sys_name}{C.reset}: {C.yellow}{domain}{C.reset} (по умолчанию: {system_sni(state, sys_name)})")
    else:
        print(f"  {C.dim}SNI: по умолчанию{C.reset}")
    if sub_config(state).get("enabled", True):
        def display_subscription(url: str) -> str:
            if show_secrets:
                return url
            return url.rsplit("/", 1)[0] + "/" + mask_secret(user.get("sub_token", ""), 6)

        print(f"  {C.dim}HAPP:{C.reset}         {display_subscription(happ_sub_url(state, user))}  {C.dim}(self-signed: insecure ON){C.reset}")
        print(f"  {C.dim}Karing:{C.reset}       {display_subscription(karing_sub_url(state, user))}  {C.dim}(Reality xHTTP/TCP, Hysteria2, TLS){C.reset}")
        if "wireguard" in systems:
            print(f"  {C.dim}Karing WG:{C.reset}    {display_subscription(karing_wireguard_sub_url(state, user))}  {C.dim}(standard WG, 51821/udp){C.reset}")
        print(f"  {C.dim}Legacy:{C.reset}       {display_subscription(sub_url(state, user))}  {C.dim}(для существующих клиентов){C.reset}")


def cmd_sni_routes(args: argparse.Namespace) -> None:
    """Управление SNI-маршрутами."""
    state = load_state()

    if args.action == "list":
        routes = get_sni_routes(state)
        for sys_name, route in routes.items():
            if sys_name == "custom":
                customs = route if isinstance(route, list) else []
                if customs:
                    print(f"{C.bold}Кастомные маршруты:{C.reset}")
                    for c in customs:
                        print(f"  {C.cyan}{c['sni']}{C.reset} → {c['dest']}")
                else:
                    print(f"{C.dim}Кастомных маршрутов нет{C.reset}")
                continue
            if isinstance(route, dict):
                aliases = ", ".join(route.get("aliases", []))
                print(f"{C.green}{sys_name}{C.reset}: default={route.get('default', '-')}, dest={route.get('dest', '-')}, aliases=[{aliases}]")

    elif args.action == "diagnose":
        result = probe_sni_target(args.sni, timeout=args.timeout)
        print(f"SNI: {result['sni']}")
        print(f"DNS: {result['dns']}")
        if "addresses" in result:
            print(f"DNS addresses: {result['addresses']}")
        print(f"TLS: {result['tls']}")
        print(f"Result: {result['reason']}")

    elif args.action == "set-default":
        route = ensure_sni_route(state, args.system)
        domain = validate_sni_domain(args.sni)
        route["default"] = domain
        aliases = route.setdefault("aliases", [])
        if domain not in aliases:
            aliases.insert(0, domain)
        render_changed = render_all(state)
        save_state(state)
        if getattr(args, "restart", False):
            restart_services(render_changed)
        ok(f"default SNI для {args.system}: {domain}")

    elif args.action == "set-aliases":
        route = ensure_sni_route(state, args.system)
        aliases = parse_sni_csv(args.aliases)
        default_sni = validate_sni_domain(route.get("default", DEFAULT_SNIS[args.system]))
        if default_sni not in aliases:
            aliases.insert(0, default_sni)
        route["aliases"] = aliases
        render_changed = render_all(state)
        save_state(state)
        if getattr(args, "restart", False):
            restart_services(render_changed)
        ok(f"aliases для {args.system}: {', '.join(aliases)}")

    elif args.action == "add":
        args.sni = validate_sni_domain(args.sni)
        args.dest = validate_backend_dest(args.dest)
        routes = state.setdefault("sni_routes", {})
        customs = routes.setdefault("custom", [])
        if not isinstance(customs, list):
            raise SystemExit("Ошибка: sni_routes.custom повреждён (не список)")
        for c in customs:
            if c.get("sni") == args.sni:
                c["dest"] = args.dest
                render_all(state)
                save_state(state)
                ok(f"кастомный маршрут обновлён: {args.sni} → {args.dest}")
                return
        customs.append({"sni": args.sni, "dest": args.dest})
        render_all(state)
        save_state(state)
        ok(f"кастомный маршрут добавлен: {args.sni} → {args.dest}")

    elif args.action == "remove":
        args.sni = validate_sni_domain(args.sni)
        routes = state.get("sni_routes", {})
        customs = routes.get("custom", [])
        if not isinstance(customs, list):
            raise SystemExit("Ошибка: sni_routes.custom повреждён (не список)")
        before = len(customs)
        routes["custom"] = [c for c in customs if c.get("sni") != args.sni]
        if len(routes["custom"]) < before:
            render_all(state)
            save_state(state)
            ok(f"кастомный маршрут удалён: {args.sni}")
        else:
            warn(f"кастомный маршрут не найден: {args.sni}")

    elif args.action == "add-alias":
        args.alias = validate_sni_domain(args.alias)
        system_routes = ensure_sni_route(state, args.system)
        aliases = system_routes.setdefault("aliases", [])
        if not isinstance(aliases, list):
            raise SystemExit(f"Ошибка: aliases повреждены для {args.system}")
        if args.alias not in aliases:
            aliases.append(args.alias)
            render_all(state)
            save_state(state)
            ok(f"алиас {args.alias} добавлен к {args.system}")
        else:
            warn(f"алиас {args.alias} уже есть в {args.system}")

    elif args.action == "remove-alias":
        args.alias = validate_sni_domain(args.alias)
        system_routes = ensure_sni_route(state, args.system)
        aliases = system_routes.get("aliases", [])
        if not isinstance(aliases, list):
            raise SystemExit(f"Ошибка: aliases повреждены для {args.system}")
        if args.alias in aliases:
            aliases.remove(args.alias)
            render_all(state)
            save_state(state)
            ok(f"алиас {args.alias} удалён из {args.system}")
        else:
            warn(f"алиас {args.alias} не найден в {args.system}")


def cmd_mtproto(args: argparse.Namespace) -> None:
    """Статус, диагностика и выбор безопасного camouflage MTProto."""
    state = load_state()
    if args.action == "status":
        for system in MTPROTO_SYSTEMS:
            origin = mtproto_camouflage_origin(state, system)
            sni = system_sni(state, system)
            target = "nginx:8443" if origin == "local-site" else f"{sni}:443"
            scope = "per-user" if system == "telemt" else "shared; без user attribution"
            print(f"{system}: origin={origin}, sni={sni}, target={target}, credentials={scope}")
        print("Ограничение: полную блокировку IP/TCP/TLS гарантированно обойти невозможно.")
        return

    if args.action == "diagnose":
        result = mtproto_diagnose(
            state, args.system, timeout=args.timeout, runtime_checks=not args.no_runtime
        )
        print(
            f"{result['system']}: {result['status']}; origin={result['origin']}; "
            f"sni={result['sni']}; target={result['target']}"
        )
        for check in result["checks"]:
            print(f"  {check['id']}: {check['status']} ({check['detail']})")
        print(result["limitations"])
        return

    if args.action == "set-origin":
        before_state = copy.deepcopy(state)
        mtproto_config(state, args.system)["camouflage_origin"] = args.origin
        prepare_state(state)
        diagnosis = mtproto_diagnose(
            state, args.system, timeout=args.timeout, runtime_checks=False
        )
        if not diagnosis["can_apply"]:
            raise SystemExit(
                "Режим не применён; исправьте: " + ", ".join(diagnosis["errors"])
            )
        rendered = render_all(state)
        save_state(state)
        if args.restart:
            restart_services(rendered, before_state=before_state, after_state=state)
        ok(f"{args.system}.camouflage_origin={args.origin}")
        if diagnosis["warnings"]:
            warn("Диагностические предупреждения: " + ", ".join(diagnosis["warnings"]))
        print("Полную блокировку IP/TCP/TLS гарантированно обойти невозможно.")


# ── CLI парсер ───────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Управление KVN VPN v3")
    sub = parser.add_subparsers(dest="command", required=True)

    # add-user
    add = sub.add_parser("add-user", help="Добавить пользователя")
    add.add_argument("name", help="Имя пользователя")
    add.add_argument("--server", help="IP или домен сервера")
    add.add_argument("--uuid", help="Задать UUID вручную")
    add.add_argument("--hysteria-password", help="Задать пароль Hysteria вручную")
    add.add_argument("--telemt-secret", help="Задать 32-символьный hex secret Telemt")
    add.add_argument("--ocserv-password", help="Задать пароль OpenConnect/ocserv вручную")
    add.add_argument("--description", help="Описание/комментарий")
    add.add_argument("--systems", help="Список систем через запятую: tls,reality-xhttp,reality-tcp,hysteria,telemt,mtg,amneziawg,wireguard,ocserv")
    add.add_argument("--device", choices=ALL_DEVICES, help="Тип устройства: подбирает SNI под экосистему (ios→apple, android→google, windows→microsoft)")
    add.add_argument("--restart", action="store_true", help="Перезапустить сервисы")
    add.set_defaults(func=cmd_add_user)

    # edit-user
    edit = sub.add_parser("edit-user", help="Редактировать пользователя")
    edit.add_argument("name", help="Текущее имя пользователя")
    edit.add_argument("--new-name", help="Новое имя")
    edit.add_argument("--description", help="Новое описание")
    edit.add_argument("--systems", help="Новый список систем через запятую")
    edit.add_argument("--device", choices=ALL_DEVICES + ["none"], help="Сменить тип устройства (none — сбросить SNI-профиль)")
    edit.add_argument("--sni", action="append", help="SNI оверрайд: система=домен (можно несколько раз)")
    edit.add_argument("--uuid", help="Новый UUID")
    edit.add_argument("--hysteria-password", help="Новый пароль Hysteria")
    edit.add_argument("--telemt-secret", help="Новый Telemt secret")
    edit.add_argument("--ocserv-password", help="Новый пароль OpenConnect/ocserv")
    edit.add_argument("--regenerate-keys", action="store_true", help="Регенерировать все ключи")
    edit.add_argument("--enable", type=str_to_bool, default=None, help="Включить (true) или выключить (false)")
    edit.add_argument("--server", help="IP или домен сервера")
    edit.add_argument("--restart", action="store_true", help="Перезапустить сервисы")
    edit.set_defaults(func=cmd_edit_user)

    # remove-user
    remove = sub.add_parser("remove-user", help="Удалить пользователя")
    remove.add_argument("name", help="Имя пользователя")
    remove.add_argument("--server", help="IP или домен сервера")
    remove.add_argument("--restart", action="store_true", help="Перезапустить сервисы")
    remove.set_defaults(func=cmd_remove_user)

    # render
    render = sub.add_parser("render", help="Перегенерировать серверные и клиентские конфиги")
    render.add_argument("--server", help="IP или домен сервера")
    render.add_argument("--certs", action="store_true", help="Пересобрать сертификаты: LE live если есть, иначе self-signed fallback")
    render.add_argument("--restart", action="store_true", help="Перезапустить сервисы")
    render.set_defaults(func=cmd_render)

    reconcile = sub.add_parser("reconcile", help="Повторно применить текущее desired state")
    reconcile.set_defaults(func=cmd_reconcile)

    service_plan = sub.add_parser("service-plan", help="Показать эффективный план запуска сервисов")
    service_plan.add_argument("--format", choices=("json", "lines"), default="json")
    service_plan.set_defaults(func=cmd_service_plan)

    # letsencrypt
    le = sub.add_parser("letsencrypt", help="Выпустить/обновить Let's Encrypt сертификат")
    le_sub = le.add_subparsers(dest="action", required=True)

    le_issue = le_sub.add_parser("issue", help="Выпустить сертификат через certbot standalone HTTP-01")
    le_issue.add_argument("--domain", required=True, action="append", help="Домен, указывающий на сервер; можно повторять для SAN")
    le_issue.add_argument("--email", help="Email для уведомлений Let's Encrypt")
    le_issue.add_argument("--staging", action="store_true", help="Использовать staging CA для теста без rate limits")
    le_issue.add_argument("--target", choices=["site", "ocserv"], default="site", help="Куда установить сертификат: site-certs/ или ocserv/certs/")
    le_issue.add_argument("--force-renewal", action="store_true", help="Принудительно перевыпустить, даже если срок ещё большой")
    le_issue.add_argument("--restart", action="store_true", help="Перезапустить сервисы после установки сертификата")
    le_issue.set_defaults(func=cmd_letsencrypt)

    le_status = le_sub.add_parser("status", help="Показать состояние site/ocserv сертификатов")
    le_status.add_argument("--target", choices=["site", "ocserv", "all"], default="all", help="Что проверить")
    le_status.set_defaults(func=cmd_letsencrypt)

    le_issue_configured = le_sub.add_parser("issue-configured", help="Выпустить сертификаты по доменам из users.json")
    le_issue_configured.add_argument("--target", choices=["site", "ocserv", "all"], default="all", help="Что выпускать")
    le_issue_configured.add_argument("--email", help="Email для уведомлений Let's Encrypt")
    le_issue_configured.add_argument("--staging", action="store_true", help="Использовать staging CA для теста без rate limits")
    le_issue_configured.add_argument("--force-renewal", action="store_true", help="Принудительно перевыпустить вместо keep-until-expiring")
    le_issue_configured.add_argument("--restart", action="store_true", help="Перезапустить сервисы после установки сертификатов")
    le_issue_configured.set_defaults(func=cmd_letsencrypt)

    le_reissue = le_sub.add_parser("reissue", help="Принудительно перевыпустить сертификаты по users.json")
    le_reissue.add_argument("--target", choices=["site", "ocserv", "all"], default="all", help="Что перевыпускать")
    le_reissue.add_argument("--email", help="Email для уведомлений Let's Encrypt")
    le_reissue.add_argument("--staging", action="store_true", help="Использовать staging CA для теста без rate limits")
    le_reissue.add_argument("--restart", action="store_true", help="Перезапустить сервисы после установки сертификатов")
    le_reissue.set_defaults(func=cmd_letsencrypt)

    le_renew = le_sub.add_parser("renew", help="Запустить certbot renew и переустановить сертификат в проект")
    le_renew.add_argument("--restart", action="store_true", help="Перезапустить сервисы после установки сертификата")
    le_renew.set_defaults(func=cmd_letsencrypt)

    le_deploy = le_sub.add_parser("deploy", help="Скопировать уже выпущенный certbot certificate в site-certs/")
    le_deploy.add_argument("--domain", help="Домен сертификата; по умолчанию users.json → letsencrypt.domain")
    le_deploy.add_argument("--target", choices=["site", "ocserv"], default="site", help="Куда установить сертификат: site-certs/ или ocserv/certs/")
    le_deploy.add_argument("--restart", action="store_true", help="Перезапустить сервисы после установки сертификата")
    le_deploy.set_defaults(func=cmd_letsencrypt)

    le_timer = le_sub.add_parser("install-renewal", help="Установить systemd timer автопродления Let's Encrypt")
    le_timer.set_defaults(func=cmd_letsencrypt)

    # portal
    portal = sub.add_parser("portal", help="Настройка и восстановление web-портала")
    portal_sub = portal.add_subparsers(dest="action", required=True)
    portal_configure = portal_sub.add_parser("configure", help="Настроить или отключить портал")
    portal_configure.add_argument("--enable", type=str_to_bool, default=None, help="Включить true/false; без флага запускается мастер")
    portal_configure.add_argument("--confirm-disable", action="store_true", help="Подтвердить неинтерактивное отключение")
    portal_configure.add_argument("--name", help="Название портала")
    portal_configure.add_argument("--domain", help="Публичный домен или IPv4")
    portal_configure.add_argument("--port", type=int, help="Публичный HTTPS-порт")
    portal_configure.add_argument("--path", help="Путь вида /admin")
    portal_configure.add_argument("--login", help="Логин администратора")
    portal_configure.add_argument("--reset-credentials", action="store_true", help="Запросить новый пароль через getpass")
    portal_configure.add_argument(
        "--allow-self-signed-ip", type=str_to_bool, default=None,
        help="Явно разрешить self-signed сертификат с совпадающим IP SAN: true/false",
    )
    portal_configure.add_argument("--restart", action="store_true", help="Применить конфиги и перезапустить portal при необходимости")
    portal_configure.set_defaults(func=cmd_portal)
    portal_status = portal_sub.add_parser("status", help="Показать публичный статус без секретов")
    portal_status.set_defaults(func=cmd_portal)
    portal_reset = portal_sub.add_parser("reset-credentials", help="Сменить логин/пароль и закрыть сессии")
    portal_reset.add_argument("--login", help="Новый логин; пароль только через getpass")
    portal_reset.set_defaults(func=cmd_portal)
    portal_unlock = portal_sub.add_parser("unlock-ip", help="Снять 12-часовую блокировку IP")
    portal_unlock.add_argument("ip", help="IPv4 или IPv6")
    portal_unlock.set_defaults(func=cmd_portal)

    updates = sub.add_parser("updates", help="Настройка обновлений из фиксированного GitHub Releases")
    updates_sub = updates.add_subparsers(dest="action", required=True)
    updates_status = updates_sub.add_parser("status", help="Показать настройки и наличие credential без token")
    updates_status.set_defaults(func=cmd_updates)
    updates_configure = updates_sub.add_parser("configure", help="Настроить канал, asset и credential")
    updates_configure.add_argument("--enable", type=str_to_bool, default=None, help="Включить источник: true/false")
    updates_configure.add_argument("--channel", choices=["stable", "tag"], help="Latest stable или фиксированный tag")
    updates_configure.add_argument("--tag", help="Фиксированный release tag для channel=tag")
    updates_configure.add_argument(
        "--asset-preference", choices=["release", "deploy"],
        help="Полный offline release или облегчённый source deploy",
    )
    token_group = updates_configure.add_mutually_exclusive_group()
    token_group.add_argument("--set-token", action="store_true", help="Безопасно запросить token через getpass")
    token_group.add_argument("--token-file", help="Прочитать token из root-only файла; значение не попадает в argv")
    token_group.add_argument("--clear-token", action="store_true", help="Удалить сохранённый GitHub token")
    updates_configure.set_defaults(func=cmd_updates)

    # amneziawg
    awg = sub.add_parser("amneziawg", help="Проверить AmneziaWG host-службу и peers")
    awg_sub = awg.add_subparsers(dest="action", required=True)

    awg_status = awg_sub.add_parser("status", help="Показать состояние AmneziaWG")
    awg_status.add_argument("name", nargs="?", help="Проверить одного пользователя")
    awg_status.set_defaults(func=cmd_amneziawg)

    awg_diag = awg_sub.add_parser("diagnose", help="Диагностика ожидания рукопожатия")
    awg_diag.add_argument("name", nargs="?", help="Проверить одного пользователя")
    awg_diag.set_defaults(func=cmd_amneziawg)

    awg_verify = awg_sub.add_parser("verify", help="Проверить точное совпадение project/host/runtime peers")
    awg_verify.set_defaults(func=cmd_amneziawg)

    # wireguard
    wg = sub.add_parser("wireguard", help="Проверить стандартную WireGuard host-службу и peers")
    wg_sub = wg.add_subparsers(dest="action", required=True)

    wg_status = wg_sub.add_parser("status", help="Показать состояние WireGuard")
    wg_status.add_argument("name", nargs="?", help="Проверить одного пользователя")
    wg_status.set_defaults(func=cmd_wireguard)

    wg_diag = wg_sub.add_parser("diagnose", help="Диагностика стандартного WireGuard")
    wg_diag.add_argument("name", nargs="?", help="Проверить одного пользователя")
    wg_diag.set_defaults(func=cmd_wireguard)

    wg_verify = wg_sub.add_parser("verify", help="Проверить точное совпадение project/host/runtime peers")
    wg_verify.set_defaults(func=cmd_wireguard)

    # links
    links = sub.add_parser("links", help="Показать ссылки подключения")
    links.add_argument("name", nargs="?")
    links.add_argument("--all", action="store_true", help="Показать всех пользователей")
    links.add_argument("--server", help="IP или домен сервера")
    links.set_defaults(func=cmd_links)

    # Экспорт пользователя и совместимый export-links регистрируются отдельно.
    add_client_export_parsers(
        sub,
        export_user_handler=cmd_export_user,
        export_links_handler=cmd_export_links,
    )

    # list-users
    users = sub.add_parser("list-users", help="Показать пользователей")
    users.set_defaults(func=cmd_list)

    # show
    show = sub.add_parser("show", help="Подробная информация о пользователе")
    show.add_argument("name", help="Имя пользователя")
    show.add_argument("--show-secrets", action="store_true", help="Показать UUID, пароли и token подписки полностью")
    show.set_defaults(func=cmd_show)

    # sni-routes
    sni = sub.add_parser("sni-routes", help="Управление SNI-маршрутами")
    sni_sub = sni.add_subparsers(dest="action", required=True)

    sni_list = sni_sub.add_parser("list", help="Показать все SNI-маршруты")
    sni_list.set_defaults(func=cmd_sni_routes)

    sni_diagnose = sni_sub.add_parser("diagnose", help="Проверить DNS/TLS доступность SNI без изменения маршрута")
    sni_diagnose.add_argument("sni", help="SNI-домен для диагностики")
    sni_diagnose.add_argument("--timeout", type=float, default=3.0, help="Лимит DNS+TLS проверки, 0.5-10 секунд")
    sni_diagnose.set_defaults(func=cmd_sni_routes)

    sni_set_default = sni_sub.add_parser("set-default", help="Изменить default SNI сервиса")
    sni_set_default.add_argument("system", choices=SNI_ROUTE_SYSTEMS, help="Система")
    sni_set_default.add_argument("sni", help="Новый default SNI-домен")
    sni_set_default.add_argument("--restart", action="store_true", help="Перезапустить сервисы после изменения")
    sni_set_default.set_defaults(func=cmd_sni_routes)

    sni_set_aliases = sni_sub.add_parser("set-aliases", help="Задать полный список SNI aliases сервиса")
    sni_set_aliases.add_argument("system", choices=SNI_ROUTE_SYSTEMS, help="Система")
    sni_set_aliases.add_argument("aliases", help="SNI aliases через запятую")
    sni_set_aliases.add_argument("--restart", action="store_true", help="Перезапустить сервисы после изменения")
    sni_set_aliases.set_defaults(func=cmd_sni_routes)

    sni_add = sni_sub.add_parser("add", help="Добавить кастомный SNI-маршрут")
    sni_add.add_argument("sni", help="SNI-домен")
    sni_add.add_argument("dest", help="Назначение (service:port)")
    sni_add.set_defaults(func=cmd_sni_routes)

    sni_rm = sni_sub.add_parser("remove", help="Удалить кастомный SNI-маршрут")
    sni_rm.add_argument("sni", help="SNI-домен")
    sni_rm.set_defaults(func=cmd_sni_routes)

    sni_add_alias = sni_sub.add_parser("add-alias", help="Добавить алиас к системе")
    sni_add_alias.add_argument("system", choices=SNI_ROUTE_SYSTEMS, help="Система")
    sni_add_alias.add_argument("alias", help="SNI-домен алиас")
    sni_add_alias.set_defaults(func=cmd_sni_routes)

    sni_rm_alias = sni_sub.add_parser("remove-alias", help="Удалить алиас из системы")
    sni_rm_alias.add_argument("system", choices=SNI_ROUTE_SYSTEMS, help="Система")
    sni_rm_alias.add_argument("alias", help="SNI-домен алиас")
    sni_rm_alias.set_defaults(func=cmd_sni_routes)

    # mtproto
    mtproto = sub.add_parser("mtproto", help="Маскировка и диагностика Telemt/MTG")
    mtproto_sub = mtproto.add_subparsers(dest="action", required=True)
    mtproto_status = mtproto_sub.add_parser("status", help="Показать режимы без secrets")
    mtproto_status.set_defaults(func=cmd_mtproto)
    mtproto_diagnose_parser = mtproto_sub.add_parser("diagnose", help="Bounded-проверка SNI/маршрута/SAN/decoy")
    mtproto_diagnose_parser.add_argument("system", choices=MTPROTO_SYSTEMS)
    mtproto_diagnose_parser.add_argument("--timeout", type=float, default=3.0)
    mtproto_diagnose_parser.add_argument("--no-runtime", action="store_true", help="Не запускать decoy/mtg doctor")
    mtproto_diagnose_parser.set_defaults(func=cmd_mtproto)
    mtproto_origin = mtproto_sub.add_parser("set-origin", help="Выбрать внешний или внутренний decoy")
    mtproto_origin.add_argument("system", choices=MTPROTO_SYSTEMS)
    mtproto_origin.add_argument("origin", choices=CAMOUFLAGE_ORIGINS)
    mtproto_origin.add_argument("--timeout", type=float, default=3.0)
    mtproto_origin.add_argument("--restart", action="store_true", help="Применить изменения к runtime")
    mtproto_origin.set_defaults(func=cmd_mtproto)

    # interactive
    interactive = sub.add_parser("interactive", help="Интерактивный режим управления (мастер)")
    interactive.add_argument("--server", help="IP или домен сервера")
    interactive.add_argument("--no-restart-on-exit", action="store_true", help="Не перезапускать сервисы при выходе из мастера")
    interactive.set_defaults(func=cmd_interactive)

    return parser


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
