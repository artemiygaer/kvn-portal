"""Карточка и отзыв настоящих VPN-доступов; только синтетические данные Debian VM."""

import base64
from contextlib import contextmanager
import http.client
from http.server import HTTPServer
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile, mkdtemp
from threading import Thread
import time
from urllib.parse import parse_qs, urlencode, urlsplit
from uuid import UUID

from check_debian_core import signed_fixture_session
from check_hysteria_vm import ADDRESS, ORIGIN, PAYLOAD, SITE, Origin, check_client, client_ns, isolated_network
from check_tls_gateway import make_ca, make_pair
from v5.core.lifecycle.assembly import build_lifecycle, host_gateway
from v5.core.packages.manifest import canonical_json
from v5.core.packages.signature import PIN_PATH
from v5.core.packages.status import PACKAGE_STATE
from v5.core.private_files import write_private
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.transaction import publish_gateway
from v5.modules.hysteria.clients import client_profile
from v5.modules.hysteria.config import Settings as HySettings
from v5.modules.xray.config import Settings as XraySettings
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles

BASE = Path("/var/tmp/kvn-v5-phase10")
ADMIN = f"https://{SITE}:8443"
CA_TARGET = Path("/usr/local/share/ca-certificates/kvn-phase10-fixture.crt")
SAVED = BASE / "phase4-preserved"
USERS = PACKAGE_STATE.parent / "users"
MODULES = PACKAGE_STATE.parent / "modules"
XRAY_ORIGIN = "93.184.216.34"


def preserve():
    assert not (BASE / "started").exists() and not (USERS / "users.sqlite3").exists()
    assert not any((MODULES / name).exists() for name in ("xray", "hysteria"))
    assert PIN_PATH.is_file() and not PIN_PATH.is_symlink()
    db = PACKAGE_STATE / "registry.sqlite3"
    assert db.is_file() and not db.is_symlink()
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("SELECT module,enabled FROM modules WHERE current IS NOT NULL").fetchall() == [("xray", 0)]
    gateway = host_gateway()
    assert not gateway.active() and not gateway.network_routes().routes
    SAVED.mkdir(mode=0o700)
    PACKAGE_STATE.rename(SAVED / "packages")
    PIN_PATH.rename(SAVED / "publisher.json")
    PACKAGE_STATE.mkdir(mode=0o700)
    print("Предыдущий учебный реестр и pin сохранены отдельно, без удаления.", flush=True)


def resume_staging():
    assert (SAVED / "publisher.json").is_file() and not (SAVED / "publisher.json").is_symlink()
    db = SAVED / "packages" / "registry.sqlite3"
    assert db.is_file() and not db.is_symlink()
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("SELECT module,enabled FROM modules WHERE current IS NOT NULL").fetchall() == [("xray", 0)]
    assert not any(path.exists() for path in (BASE / "started", PIN_PATH, CA_TARGET,
                                              USERS / "users.sqlite3", PACKAGE_STATE / "registry.sqlite3"))
    gateway = host_gateway()
    assert not gateway.active() and not gateway.network_routes().routes
    print("Проверена граница прерванной подготовки: сценарий ещё не начат, прежний fixture сохранён.", flush=True)


def retire():
    assert (BASE / "started").is_file() and (SAVED / "packages" / "registry.sqlite3").is_file()
    lifecycle = build_lifecycle()
    assert not any(row["enabled"] for row in lifecycle.inventory.installed())
    assert not any(lifecycle.adapters[name].running() for name in ("xray", "hysteria"))
    assert not host_gateway().active() and not host_gateway().network_routes().routes and not CA_TARGET.exists()
    archive = Path(mkdtemp(prefix="retired-", dir=BASE))
    for path in (PACKAGE_STATE, PIN_PATH, USERS, MODULES / "xray", MODULES / "hysteria", BASE / "started"):
        path.rename(archive / path.name)
    (SAVED / "packages").rename(PACKAGE_STATE)
    (SAVED / "publisher.json").rename(PIN_PATH)
    USERS.mkdir(mode=0o700)
    SAVED.rmdir()
    print("Учебное состояние сохранено отдельно; прежний реестр восстановлен.", flush=True)


def xray(uri, ca, directory, *, allowed, diagnose=False):
    # Импортируем опубликованный URI, но доставляем пакеты через учебную сеть без внешнего DNS.
    profile = urlsplit(uri)
    options = parse_qs(profile.query, strict_parsing=True)
    assert profile.scheme == "vless" and profile.hostname == SITE and profile.port == 2443
    assert options == {"type": ["tcp"], "security": ["tls"], "encryption": ["none"], "sni": [SITE]}
    identifier = str(UUID(profile.username))
    port = 18885
    path = directory / "xray-client.json"
    write_private(path, canonical_json({
        "log": {"access": "none", "loglevel": "debug" if diagnose else "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "http"}],
        "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": ADDRESS,
            "port": profile.port, "users": [{"id": identifier, "encryption": "none"}]}]},
            "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {
                "serverName": SITE, "disableSystemRoot": True, "certificates": [{"certificateFile": str(ca)}]}}}],
    }))
    command = client_ns(str(BASE / "xray"), "run", "-config", str(path))
    try:
        with TemporaryFile(dir=directory) as diagnostic, subprocess.Popen(
                command, stdout=diagnostic, stderr=diagnostic) as child:
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline and child.poll() is None:
                    listing = subprocess.run(client_ns("/usr/bin/ss", "-lntH", f"sport = :{port}"),
                                             capture_output=True, check=True, timeout=6)
                    if listing.stdout:
                        break
                    time.sleep(0.25)
                else:
                    raise AssertionError("Не запустился штатный клиент Xray")
                result = subprocess.run(client_ns("/usr/bin/curl", "-fsS", "--max-time", "10", "--noproxy", "",
                                                   "--write-out", "\n%{http_code}",
                                                   "-x", f"http://127.0.0.1:{port}", f"http://{XRAY_ORIGIN}:{ORIGIN}/"),
                                        capture_output=True, check=False, timeout=20)
                body, _, status = result.stdout.rpartition(b"\n")
                if allowed:
                    if result.returncode != 0 or body != PAYLOAD:
                        diagnostic.seek(0)
                        observed = diagnostic.read(64 * 1024).lower()
                        markers = {b"certificate signed by unknown authority": "tls_certificate", b"connection refused": "connection_refused",
                                   b"deadline exceeded": "timeout", b"failed to dial": "dial_failed",
                                   b"handshake failed": "handshake_failed", b"eof": "unexpected_end",
                                   b"tunneling request": "vless_dispatched", b"failed to read response header": "no_vless_reply",
                                   b"closed pipe": "closed_pipe", b"failed to find": "not_found"}
                        reasons = ",".join(code for marker, code in markers.items() if marker in observed) or "none"
                        http = status.decode() if re.fullmatch(rb"[0-5][0-9]{2}", status) else "unknown"
                        raise AssertionError(f"Штатный VLESS-клиент: HTTP {http}, curl exit={result.returncode}, {reasons}")
                else:
                    assert result.returncode != 0 and PAYLOAD not in body, "Отозванный VLESS UUID принят"
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)
    finally:
        path.unlink(missing_ok=True)


@contextmanager
def xray_origin():
    # Freedom блокирует TEST-NET. Маршрут к контрольному адресу остаётся локальным в стенде.
    ip = "/usr/sbin/ip"
    address = f"{XRAY_ORIGIN}/32"
    show = subprocess.check_output([ip, "-4", "addr", "show", "to", address], timeout=8)
    assert not show, "Контрольный адрес уже назначен"
    subprocess.run([ip, "addr", "add", address, "dev", "lo"], check=True, timeout=8)
    try:
        route = subprocess.check_output([ip, "-4", "route", "get", XRAY_ORIGIN], timeout=8)
        assert route.startswith(f"local {XRAY_ORIGIN} dev lo ".encode()), "Контрольный маршрут не локальный"
        with HTTPServer((XRAY_ORIGIN, ORIGIN), Origin) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                yield
            finally:
                server.shutdown()
                thread.join(3)
    finally:
        subprocess.run([ip, "addr", "del", address, "dev", "lo"], check=True, timeout=8)


class Browser:
    def __init__(self, ca):
        self.cookie = signed_fixture_session()
        self.context = ssl.create_default_context(cafile=ca)
        self.context.set_alpn_protocols(["http/1.1"])
        self.csrf = None

    def request(self, path, form=None, *, admin=True):
        method = "GET" if form is None else "POST"
        headers = {"Cookie": self.cookie} if admin else {}
        body = None
        if form is not None:
            headers.update({"Origin": ADMIN, "Content-Type": "application/x-www-form-urlencoded"})
            body = urlencode({"csrf": self.csrf, **form})
        conn = http.client.HTTPSConnection(SITE, 8443, timeout=355, context=self.context)
        conn._create_connection = lambda address, timeout, source_address=None: socket.create_connection(
            ("127.0.0.2", address[1]), timeout, source_address)
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, response.headers, response.read(512 * 1024)
        finally:
            conn.close()

    def create(self):
        status, _, page = self.request("/users")
        assert status == 200, f"Страница пользователей: HTTP {status}"
        self.csrf = re.search(rb'name="csrf" value="([^"<>]+)"', page)[1].decode()
        status, headers, _ = self.request("/users", {"name": "phase10-vpn"})
        assert status == 303 and re.fullmatch(r"/users/[0-9a-f]{32}", headers["Location"])
        return headers["Location"]

    def action(self, card, name, *, expected=303, **fields):
        status, _, page = self.request(card)
        assert status == 200, f"Карточка: HTTP {status}"
        revision = re.search(rb'name="revision" value="([0-9]+)"', page)[1].decode()
        status, _, page = self.request(card + "/" + name, {"revision": revision, **fields})
        assert status == expected, f"Операция пользователя {name}: HTTP {status}"
        return page


def exercise(ca, lifecycle, root):
    xray_adapter, hy_adapter = (lifecycle.adapters[name] for name in ("xray", "hysteria"))
    tls = next(item for item in host_gateway().identities if item.name == SITE)
    for path in sorted(BASE.glob("kvn-module-*.tar.gz")):
        with path.open("rb") as stream:
            lifecycle.inventory.install(lifecycle.inventory.prepare(stream).ticket)
    assert {row["module"] for row in lifecycle.inventory.installed()} == {"xray", "hysteria"}
    assert not any(row["enabled"] for row in lifecycle.inventory.installed())
    xray_adapter.configure(XraySettings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, SITE),)), ipv4=ADDRESS))
    hy_adapter.configure(HySettings(tls, bind=ADDRESS))

    browser = Browser(ca)
    status, headers, _ = browser.request("/users", admin=False)
    assert status == 303 and headers.get("Location") == "/login", f"Гость в /users: HTTP {status}"
    card = browser.create()
    uid = card.rsplit("/", 1)[-1]
    for name in ("wireguard", "xray", "hysteria"):
        browser.action(card, "grant", module=name, enabled="yes")
    status, _, data = browser.request(card)
    assert status == 200 and "Ожидает установки".encode() in data and "Модуль выключен".encode() in data
    assert browser.request(card + "/profiles.txt")[2] == b""
    print("HTTPS и Unix RPC: одна карточка, три сохранённых права, неактивные профили не выдаются.", flush=True)

    assert lifecycle.change("xray", True).active == ("xray",)
    assert set(lifecycle.change("hysteria", True).active) == {"xray", "hysteria"}
    print("Оба модуля активны; проверяется экспорт по HTTPS.", flush=True)
    status, headers, profiles = browser.request(card + "/profiles.txt")
    assert status == 200 and "attachment" in headers.get("Content-Disposition", ""), f"Экспорт профилей: HTTP {status}"
    lines = profiles.decode("ascii").splitlines()
    assert [urlsplit(line).scheme for line in lines] == ["hysteria2", "vless"]
    status, headers, qr = browser.request(card + "/qr/0")
    assert status == 200 and headers["Content-Type"] == "image/png" and qr.startswith(b"\x89PNG\r\n\x1a\n")
    token_page = browser.action(card, "rotate", expected=200)
    sub = re.search(rb"/sub/[A-Za-z0-9_-]{43}", token_page)[0].decode()
    status, headers, encoded = browser.request(sub, admin=False)
    assert status == 200 and headers["Cache-Control"] == "no-store" and base64.b64decode(encoded) == profiles
    assert browser.request("/sub/" + "x" * 43, admin=False)[0] == 404
    print("HTTPS: файл, QR и подписка выданы; неизвестный токен отклонён.", flush=True)
    hy = client_profile(hy_adapter.settings(), uid, active=True, endpoint=ADDRESS)
    assert hy is not None
    check_client(hy, directory=root, binary=BASE / "hysteria")
    print("Hysteria2: штатный клиент передал HTTP по QUIC.", flush=True)
    xray(lines[1], ca, root, allowed=True)
    print("Xray: штатный клиент передал HTTP по VLESS.", flush=True)

    browser.action(card, "grant", module="xray", enabled="no")
    xray_adapter.verify_export()
    xray(lines[1], ca, root, allowed=False)
    check_client(hy, directory=root, binary=BASE / "hysteria")
    assert base64.b64decode(browser.request(sub, admin=False)[2]).decode().splitlines() == lines[:1]
    lifecycle.change("hysteria", False)
    browser.action(card, "grant", module="hysteria", enabled="no")
    assert browser.request(card + "/profiles.txt")[2] == b""
    lifecycle.change("hysteria", True)
    check_client(hy, mode="off-user", denied_account=hy.account, directory=root, binary=BASE / "hysteria")
    assert browser.request(sub, admin=False)[2] == b""
    browser.action(card, "revoke")
    assert browser.request(sub, admin=False)[0] == 404
    print("Отзыв VLESS подтверждён старым UUID; отзыв QUIC при выключенном модуле применён до открытия порта. Токен отозван.",
          flush=True)


def main():
    gateway = host_gateway()
    config = gateway.config
    assert not gateway.active() and not gateway.network_routes().routes
    assert not PIN_PATH.exists() and not CA_TARGET.exists() and not (BASE / "started").exists()
    before = config.read_bytes()
    bootstrap = config.parent / "bootstrap.crt"
    write_private(BASE / "started", b"isolated phase 10\n", replace=False)
    with TemporaryDirectory(dir=BASE, prefix="fixture-") as folder:
        root = Path(folder)
        ca, key = make_ca(root)
        CA_TARGET.write_bytes(ca.read_bytes())
        CA_TARGET.chmod(0o644)
        subprocess.run(["/usr/sbin/update-ca-certificates"], check=True, stdout=subprocess.DEVNULL)
        write_private(PIN_PATH, (BASE / "publisher.json").read_bytes(), replace=False)
        tls = next(item for item in gateway.identities if item.name == SITE)
        lifecycle = build_lifecycle()
        try:
            with isolated_network(), xray_origin():
                gateway.activate(tls, *make_pair(ca, key, tls, 1001), check=check_nginx, reload=reload_nginx,
                                 verify_live=lambda pair: verify_pair(pair, ca_file=ca),
                                 verify_restored=lambda: verify_bootstrap(bootstrap))
                try:
                    exercise(ca, lifecycle, root)
                finally:
                    for row in lifecycle.inventory.installed():
                        if row["enabled"]:
                            lifecycle.change(row["module"], False)
        finally:
            publish_gateway(config, before, check=check_nginx, reload=reload_nginx,
                            verify_live=lambda: verify_bootstrap(bootstrap), verify_restored=lambda: None)
            CA_TARGET.unlink()
            subprocess.run(["/usr/sbin/update-ca-certificates", "--fresh"], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    if len(sys.argv) == 2 and sys.argv[1] in {"preserve", "retire", "resume-staging"}:
        {"preserve": preserve, "retire": retire, "resume-staging": resume_staging}[sys.argv[1]]()
    else:
        main()
