"""Сквозной перенос через nginx/systemd на чистой изолированной Debian VM."""

from collections import Counter
from contextlib import closing
import http.client
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import ssl
import subprocess
import sys
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from check_network_nft import ADDRESSES, add_client, remove_client
from check_tunnel_vm import traffic
from v5.core.lifecycle.assembly import build_lifecycle
from v5.core.migration.crypto import decrypt_archive
from v5.core.migration.legacy import parse_legacy
from v5.core.migration.portable import from_legacy
from v5.core.migration.rpc import build_service
from v5.core.packages.status import PACKAGE_STATE
from v5.core.tls.queue import GATEWAY_ROOT

ROOT = Path("/var/tmp/kvn-v5-phase11")
ORIGIN = "https://127.0.0.1:8443"
PAGE = "/users/migration"
PHRASE = "only-a-synthetic-passphrase"


def run(*argv, timeout=60):
    result = subprocess.run(argv, capture_output=True, check=False, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"Учебная команда {Path(argv[0]).name}: exit={result.returncode}")
    return result.stdout


def listeners():
    # Сравниваем реальный multiset привязок, не порядок вывода и очереди ss.
    raw = run("/usr/bin/ss", "-H", "-lntu")
    rows = [line.split() for line in raw.decode("ascii").splitlines()]
    assert all(len(row) >= 6 and row[0] in {"tcp", "udp"} for row in rows)
    return Counter((row[0], row[4]) for row in rows), raw


def rollback_previous_fixture(source):
    db = PACKAGE_STATE.parent / "users/users.sqlite3"
    assert db.is_file() and not db.is_symlink() and not (PACKAGE_STATE.parent / "modules/wireguard").exists()
    service = build_service()
    assert service.repository.current().encode() == source.encode(), "Это не состояние ожидаемого fixture"
    with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)) as reader:
        (ticket,) = reader.execute("SELECT ticket FROM migration_backup WHERE id=1").fetchone()
    assert service.rollback(ticket) == len(source.users)
    empty = service.repository.current()
    assert not empty.users and not empty.seeds


class Browser:
    def __init__(self):
        self.context = ssl.create_default_context(cafile=GATEWAY_ROOT / "bootstrap.crt")
        self.cookie, self.csrf = "", ""

    def request(self, path, fields=None, *, upload=None):
        method = "GET" if fields is None else "POST"
        headers, body = {"Cookie": self.cookie}, None
        if fields is not None:
            values = {"csrf": self.csrf, **fields}
            headers["Origin"] = ORIGIN
            if upload is None:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urlencode(values)
            else:
                name, file = upload
                boundary = secrets.token_hex(20)
                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
                         for key, value in values.items()]
                body = b"".join((*parts, (f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                                          f'filename="{file.name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode(),
                                 file.read_bytes(), f"\r\n--{boundary}--\r\n".encode()))
        with closing(http.client.HTTPSConnection("127.0.0.1", 8443, timeout=355, context=self.context)) as connection:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            data = response.read(9 * 1024 * 1024)
            if value := response.getheader("Set-Cookie"):
                cookie = SimpleCookie(value)
                self.cookie = "__Host-kvn-v5=" + cookie["__Host-kvn-v5"].value
            if token := re.search(rb'name="csrf" value="([A-Za-z0-9_-]+)"', data):
                self.csrf = token[1].decode()
            return response.status, data, response.getheader("Content-Disposition")

    def expect(self, code, *args, **kwargs):
        status, data, disposition = self.request(*args, **kwargs)
        assert status == code, f"HTTPS {args[0]}: {status}, ожидалось {code}"
        return data, disposition


def main():
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    password = sys.stdin.read().strip()
    assert not (PACKAGE_STATE / "registry.sqlite3").exists() and shutil.which("docker") is None
    assert run("/usr/bin/systemctl", "is-active", "kvn-v5-migration.socket").strip() == b"active"
    archive = ROOT / "fixture.kvn"
    source = from_legacy(parse_legacy(decrypt_archive(archive.read_bytes(), PHRASE)))
    retry = sys.argv[1:] == ["--retry-ports"]
    if retry:
        assert not password
        rollback_previous_fixture(source)
    before, raw_before = listeners()
    before_packages = run("/usr/bin/dpkg-query", "-W")
    browser = Browser()
    browser.expect(303, PAGE)
    if retry or sys.argv[1:] == ["--fixture-session"]:
        assert not password and (retry or not (PACKAGE_STATE.parent / "users/users.sqlite3").exists())
        browser.cookie = signed_fixture_session()
        print("Повтор HTTPS-проверки: одноразовая подписанная сессия только учебной VM.", flush=True)
    else:
        assert password and not sys.argv[1:]
        browser.expect(200, "/login")
        browser.expect(303, "/login", {"login": "admin", "password": password})
    browser.expect(200, PAGE)
    user = source.users[0].document()
    uid = user["id"]
    browser.expect(303, PAGE + "/preview", {"mode": "restore", "phrase": "wrong-fixture-phrase"}, upload=("archive", archive))
    browser.expect(200, PAGE)

    def restore():
        page, _ = browser.expect(200, PAGE + "/preview", {"mode": "restore", "phrase": PHRASE}, upload=("archive", archive))
        assert b"AuditFixture" in page and b"OpenConnect" in page and PHRASE.encode() not in page
        ticket = re.search(rb'name="ticket" value="([0-9a-f]{64})"', page)[1].decode()
        browser.expect(303, PAGE + "/commit", {"ticket": ticket, "confirm": "yes"})
        browser.expect(200, f"/users/{uid}")

    restore()
    encrypted, filename = browser.expect(200, PAGE + "/export", {"phrase": PHRASE, "repeat": PHRASE})
    assert filename == 'attachment; filename="kvn-users-v5.kvn"'
    assert json.loads(decrypt_archive(encrypted, PHRASE)) == source.document()
    browser.expect(303, PAGE + "/rollback", {"confirm": "yes"})
    browser.expect(404, f"/users/{uid}")
    restore()
    assert not (PACKAGE_STATE / "registry.sqlite3").exists() and shutil.which("docker") is None
    assert not (PACKAGE_STATE.parent / "modules" / "wireguard").exists()
    after, raw_after = listeners()
    assert after == before, f"Слушатели изменились: добавлены {list((after - before).elements())}, убраны {list((before - after).elements())}"
    assert run("/usr/bin/dpkg-query", "-W") == before_packages
    if raw_before != raw_after:
        print("Сырые строки ss различаются, но протоколы, адреса и порты совпадают.", flush=True)
    print("HTTPS/systemd: v4.2 → preview → commit → экспорт v5 → откат → восстановление; без VPN-слушателей и Docker.", flush=True)

    run("/usr/bin/apt-get", "install", "-y", "--no-install-recommends", "wireguard-tools", "nftables", timeout=480)
    run("/usr/sbin/modprobe", "wireguard")
    browser.expect(200, "/modules")
    page, _ = browser.expect(200, "/modules/upload", {}, upload=("package", ROOT / "kvn-module-wireguard-1.0.0.tar.gz"))
    ticket = re.search(rb'name="ticket" value="([0-9a-f]{64})"', page)[1].decode()
    browser.expect(303, "/modules/install", {"ticket": ticket})
    lifecycle = build_lifecycle()
    assert lifecycle.inventory.installed()[0]["enabled"] == 0
    run(sys.executable, "-m", "v5.core.lifecycle.manage", "init-tunnel", "wireguard")
    adapter = lifecycle.adapters["wireguard"]
    assert not adapter.running() and adapter.runtime.link() is None
    browser.expect(303, "/modules/enable", {"module": "wireguard", "confirm": "yes"})
    try:
        adapter.verify()
        state = adapter.settings()
        peer = user["credentials"]["wireguard"]
        seed = source.document()["seeds"]["wireguard"]
        assert state.settings.private_key == seed["private_key"] and state.settings.peers[0].public_key == peer["public_key"]
        config, _ = browser.expect(200, f"/users/{uid}/files/wireguard.conf")
        assert peer["private_key"].encode() in config and seed["private_key"].encode() not in config
        add_client()
        try:
            traffic(state, {"private_key": peer["private_key"], "server_key": seed["public_key"],
                            "endpoint": ADDRESSES[0], "active": True})
        finally:
            remove_client()
    finally:
        browser.expect(303, "/modules/disable", {"module": "wireguard", "confirm": "yes"})
    assert adapter.runtime.link() is None and not run("/usr/bin/ss", "-Hlnu", "sport", "=", ":51821")
    browser.expect(404, f"/users/{uid}/files/wireguard.conf")
    print("Подписанный WireGuard: отдельное включение, прежние ключи, .conf и реальный handshake/трафик; отключение закрывает порт.", flush=True)


if __name__ == "__main__":
    main()
