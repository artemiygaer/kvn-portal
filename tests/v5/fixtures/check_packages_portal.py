"""Проверить HTTP → Flask → systemd socket → реестр в учебной Debian VM."""

import hashlib
import http.client
import re
import secrets
import sqlite3
import ssl
import subprocess
from pathlib import Path
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session

ROOT = Path("/var/tmp/kvn-v5-phase2")
ORIGIN = "https://127.0.0.1:8443"


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True)


def multipart(csrf, data):
    boundary = secrets.token_hex(24)
    return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n"
            f"{csrf}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"package\";"
            " filename=\"package.tar.gz\"\r\nContent-Type: application/gzip\r\n\r\n").encode() + data + (
                f"\r\n--{boundary}--\r\n").encode(), f"multipart/form-data; boundary={boundary}"


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    assert run("systemctl", "is-active", "kvn-v5-package.socket").stdout == b"active\n"
    ports = run("ss", "-H", "-lntu").stdout.splitlines()
    assert not run("systemctl", "list-units", "kvn-v5-package@*.service",
                   "--state=running", "--no-legend").stdout.strip()
    assert run("test", "-e", "/usr/bin/docker", check=False).returncode == 1
    pin = Path("/etc/kvn-v5/packages/publisher.json")
    database = Path("/var/lib/kvn-v5/packages/registry.sqlite3")
    prior_ticket = None
    if database.exists():
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
            history = db.execute("SELECT action,module,archive FROM journal ORDER BY id").fetchall()
            assert db.execute("SELECT count(*) FROM modules").fetchone() == (0,)
            if history:
                digest = hashlib.sha256((ROOT / "fixture-xray.tar.gz").read_bytes()).hexdigest()
                assert history == [("prepare", "xray", digest)]
                tickets = db.execute("SELECT ticket FROM staged WHERE archive=?", (digest,)).fetchall()
                assert len(tickets) == 1
                prior_ticket = tickets[0][0]
    context = ssl.create_default_context(cafile="/etc/kvn-v5/gateway/bootstrap.crt")
    connection = http.client.HTTPSConnection("127.0.0.1", 8443, timeout=45, context=context)
    cookie = signed_fixture_session()
    base_headers = {"Cookie": cookie, "Origin": ORIGIN}

    def request(method, path, body=None, headers=None):
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        if headers and "Cookie" in headers and response.getheader("Set-Cookie"):
            base_headers["Cookie"] = response.getheader("Set-Cookie").split(";", 1)[0]
        return response.status, response.read().decode()

    def form(action, values):
        headers = base_headers | {"Content-Type": "application/x-www-form-urlencoded"}
        return request("POST", "/modules/" + action, urlencode({"csrf": csrf} | values), headers)

    def upload(data, token=None):
        body, content_type = multipart(token or csrf, data)
        return request("POST", "/modules/upload", body, base_headers | {"Content-Type": content_type})

    def prepare(name):
        data = (ROOT / name).read_bytes()
        status, html = upload(data)
        assert status == 200 and "Пакет проверен" in html
        assert hashlib.sha256(data).hexdigest() in html
        return re.search(r'name="ticket" value="([0-9a-f]{64})"', html)[1]

    try:
        assert request("GET", "/modules")[0] == 303
        status, html = request("GET", "/modules", headers=base_headers)
        assert status == 200
        csrf = re.search(r'name="csrf" value="([^"]+)"', html)[1]
        trusted = (ROOT / "fixture-publisher.json").read_bytes()
        if pin.exists():
            assert pin.read_bytes() == trusted
        else:
            assert "Ключ издателя ещё не настроен" in html
            with pin.open("xb") as handle:
                pin.chmod(0o600)
                handle.write(trusted)
        assert "Модули не установлены" in request("GET", "/modules", headers=base_headers)[1]
        assert upload(b"x", "incorrect")[0] == 403
        assert upload(b"not a gzip")[0] == 303
        assert "отклонены проверкой" in request("GET", "/modules", headers=base_headers)[1]
        xray = prior_ticket or prepare("fixture-xray.tar.gz")
        assert "Модули не установлены" in request("GET", "/modules", headers=base_headers)[1]
        print("HTTPS/CSRF, подготовка с SHA-256 без установки: OK", flush=True)
        assert form("install", {"ticket": xray})[0] == 303
        assert "xray 1.0.0 · выключен" in request("GET", "/modules", headers=base_headers)[1]
        for name in ("fixture-wg-v1.tar.gz", "fixture-wg-v2.tar.gz"):
            assert form("install", {"ticket": prepare(name)})[0] == 303
        assert "wireguard 1.0.1 · выключен" in request("GET", "/modules", headers=base_headers)[1]
        assert form("install", {"ticket": prepare("fixture-wg-v1.tar.gz")})[0] == 303
        assert "Старая версия не устанавливается" in request("GET", "/modules", headers=base_headers)[1]
        assert form("rollback", {"module": "wireguard", "confirm": "yes"})[0] == 303
        assert "wireguard 1.0.0 · выключен" in request("GET", "/modules", headers=base_headers)[1]
        assert form("remove", {"module": "wireguard", "confirm": "yes"})[0] == 303
        assert "wireguard 1.0.0" not in request("GET", "/modules", headers=base_headers)[1]
    finally:
        connection.close()
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
        assert db.execute("SELECT module,version,enabled FROM modules WHERE current IS NOT NULL").fetchall() == [
            ("xray", "1.0.0", 0)]
        assert [row[0] for row in db.execute("SELECT action FROM journal ORDER BY id")] == [
            "prepare", "install", "prepare", "install", "prepare", "upgrade", "prepare", "rollback", "remove"]
    assert run("runuser", "-u", "kvn-v5-web", "--", "test", "-r", str(database), check=False).returncode == 1
    assert run("ss", "-H", "-lntu").stdout.splitlines() == ports
    assert run("test", "-e", "/usr/bin/docker", check=False).returncode == 1
    print("Debian: HTTPS multipart >768 КиБ, SHA, CSRF, отдельная установка, downgrade/rollback/remove, журнал: OK")
    print("Docker и новые сетевые порты отсутствуют; реестр закрыт от web UID: OK")


if __name__ == "__main__":
    main()
