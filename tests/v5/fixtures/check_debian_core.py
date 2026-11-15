"""Проверки развёрнутого ядра в изолированном Debian; пароль — только stdin."""

import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode


def output(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def web(*args):
    return subprocess.run(["runuser", "-u", "kvn-v5-web", "--", *args], capture_output=True, text=True)


def verify_permissions(http01=False):
    assert Path("/root").stat().st_mode & 0o077 == 0
    assert Path("/root/portal").stat().st_mode & 0o077 == 0
    assert Path("/root/portal/modules.json").read_text() == '{"schema":1,"installed":[]}'
    web_uid = web("id", "-u").stdout.strip()
    assert web_uid not in ("", "0")
    pid = output("systemctl", "show", "kvn-v5-web", "-p", "MainPID", "--value")
    assert pid.isdecimal() and int(pid) > 1 and Path(f"/proc/{pid}").stat().st_uid == int(web_uid)
    for private in ("/root/portal/install.json", "/etc/kvn-v5/gateway/bootstrap.key", "/run/docker.sock"):
        assert web("test", "-r", private).returncode != 0
    for binary in ("docker", "dockerd", "dkms", "wg", "awg"):
        assert not any((Path(base) / binary).exists() for base in ("/usr/bin", "/usr/sbin", "/usr/local/bin"))
    assert output("systemctl", "is-active", "kvn-v5-agent", "kvn-v5-web", "kvn-v5-gateway") == "active\nactive\nactive"
    bound = {line.split()[3] for line in output("ss", "-H", "-ltn").splitlines()}
    allowed = {"127.0.0.1:8443"}
    if http01:
        allowed.update(("0.0.0.0:80", "[::]:80"))
        assert "0.0.0.0:80" in bound
    for address in bound:
        if address.endswith((":80", ":443", ":8443")):
            assert address in allowed, address
    assert "127.0.0.1:8443" in bound
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(4)
        peer.connect("/run/kvn-v5-agent/control.sock")
        assert b'"forbidden"' in peer.recv(1024)
    rpc = """import socket, sys
with socket.socket(socket.AF_UNIX) as peer:
    peer.settimeout(4)
    peer.connect('/run/kvn-v5-agent/control.sock')
    peer.sendall(sys.argv[1].encode() + b'\\n')
    print(peer.makefile('rb').readline().decode().strip())
"""
    assert '"ready"' in web("python3", "-c", rpc, '{"version":1,"method":"health","params":{}}').stdout
    assert '"unknown_method"' in web("python3", "-c", rpc, '{"version":1,"method":"shell","params":{}}').stdout
    print("systemd, порты, отсутствие VPN/Docker, права и закрытая схема RPC: OK")


def verify_http01():
    root = Path("/var/lib/kvn-v5/acme/webroot/.well-known/acme-challenge")
    token, link = root / "phase3-Token_1", root / "phase3-link"
    conn = http.client.HTTPConnection("127.0.0.1", 80, timeout=20)

    def request(method, path, host):
        conn.request(method, path, headers={"Host": host, "Cookie": "kvn-test-cookie=ignored"})
        response = conn.getresponse()
        assert response.getheader("Set-Cookie") is None
        return response.status, response.getheader("Location"), response.read()

    try:
        for name in ("portal.example", "www.portal.example", "192.0.2.8"):
            assert request("GET", "/login?x=1", name + ":80")[:2] == (308, f"https://{name}/login?x=1")
        assert request("GET", "/", "unknown.example")[0] == 421
        challenge = "/.well-known/acme-challenge/"
        assert request("GET", challenge + token.name, "portal.example")[0] == 404
        token.write_bytes(b"synthetic-acme-response\n")
        token.chmod(0o644)
        for name in ("portal.example", "www.portal.example", "192.0.2.8"):
            assert request("GET", challenge + token.name, name) == (200, None, token.read_bytes())
        assert request("POST", challenge + token.name, "portal.example")[0] == 403
        link.symlink_to("/etc/passwd")
        assert request("GET", challenge + link.name, "portal.example")[0] in (403, 404)
        token.unlink()
        assert request("GET", challenge + token.name, "portal.example")[0] == 404
        print("TCP/80: два имени и IP, HTTP-01, 308, отказ чужому Host, POST и симлинку: OK")
    finally:
        conn.close()
        token.unlink(missing_ok=True)
        link.unlink(missing_ok=True)


def verify_https(password, *, phase3_app=False, fixture_session=False):
    context = ssl.create_default_context(cafile="/etc/kvn-v5/gateway/bootstrap.crt")
    conn = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=30)

    def request(method, path, *, body=None, headers=None):
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read().decode()

    try:
        status, headers, _ = request("GET", "/")
        assert status == 303 and headers["Location"] == "/login"
        status, headers, body = request("GET", "/login")
        assert status == 200 and "HttpOnly" in headers["Set-Cookie"] and "Secure" in headers["Set-Cookie"]
        if not password:
            print("HTTPS с проверкой сертификата, анонимный вход/переадресация: OK")
            if phase3_app and fixture_session:
                verify_phase3_app(request, signed_fixture_session())
            return
        csrf = re.search(r'name="csrf" value="([^"]+)"', body)[1]
        values = urlencode({"csrf": csrf, "login": "admin", "password": password})
        headers = {"Cookie": headers["Set-Cookie"].split(";", 1)[0],
                   "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://127.0.0.1:8443"}
        status, headers, _ = request("POST", "/login", body=values, headers=headers)
        assert status == 303 and headers["Location"] == "/"
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, dashboard_headers, body = request("GET", "/", headers={"Cookie": cookie})
        if dashboard_headers.get("Set-Cookie"):
            cookie = dashboard_headers["Set-Cookie"].split(";", 1)[0]
        assert status == 200
        for label in ("Агент доступен", "CPU", "Свободная память", "Свободный диск", "Сеть", "Время работы",
                      "История настраивается отдельно"):
            assert label in body, label
        if 'href="/modules"' in body:
            modules_status, _, modules = request("GET", "/modules", headers={"Cookie": cookie})
            assert modules_status == 200 and "Модули" in modules and "Ключ издателя ещё не настроен" in modules
            assert not Path("/var/lib/kvn-v5/packages/registry.sqlite3").exists()
        else:
            assert "Модули не установлены" in body
        print("Вход по паролю из мастера и все карточки живой сводки: OK")
        if phase3_app:
            verify_phase3_app(request, cookie)
    finally:
        conn.close()


def signed_fixture_session():
    # Только повторная проверка в учебной VM: реальный вход уже прошёл, пароль не сохранялся.
    from flask import Flask

    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    config = json.loads(Path("/etc/kvn-v5/web/config.json").read_text())
    app = Flask(__name__)
    app.secret_key = config["session_key"]
    serializer = app.session_interface.get_signing_serializer(app)
    return "__Host-kvn-v5=" + serializer.dumps({"admin": True, "_permanent": True, "csrf": secrets.token_urlsafe(24)})


def verify_phase3_app(request, cookie):
    authenticated = {"Cookie": cookie}
    site = "/settings/site"
    tls = "/settings/tls"
    status, settings_headers, page = request("GET", site, headers=authenticated)
    assert status == 200 and "Активна стандартная страница" in page
    if settings_headers.get("Set-Cookie"):
        authenticated = {"Cookie": settings_headers["Set-Cookie"].split(";", 1)[0]}
    post = {**authenticated, "Origin": "https://127.0.0.1:8443"}
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    marker = b"phase3-upload-fixture"
    html = b"<main><h1>" + marker + b"</h1><p>" + b"x" * 6144 + b"</p></main>"
    boundary = b"KVNPhase3FixtureBoundary"
    body = (b"--" + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
            + b"\r\n--" + boundary + b'\r\nContent-Disposition: form-data; name="html"; filename="index.html"'
            + b"\r\nContent-Type: text/html\r\n\r\n" + html + b"\r\n--" + boundary + b"--\r\n")
    multipart = {**post, "Content-Type": "multipart/form-data; boundary=" + boundary.decode()}
    status, headers, preview = request("POST", site + "/preview", body=body, headers=multipart)
    assert status == 200 and marker.decode() in preview and "sandbox" in headers["Content-Security-Policy"], status
    index = Path("/var/lib/kvn-v5/site/index.html")
    previous = index.read_bytes()
    assert marker not in previous
    assert request("POST", site + "/publish", body=body, headers=multipart)[0] == 303
    assert marker in index.read_bytes()
    form = {**post, "Content-Type": "application/x-www-form-urlencoded"}
    assert request("POST", site + "/reset", body=urlencode({"csrf": csrf, "confirm": "yes"}), headers=form)[0] == 303
    assert index.read_bytes() == previous
    status, _, page = request("GET", tls, headers=authenticated)
    assert status == 200 and "Сертификаты HTTPS" in page
    assert not Path("/usr/local/lib/kvn-v5-acme/bin/certbot").exists()
    records = Path("/var/lib/kvn-v5/tls/results.json")
    previous_result = records.stat().st_mtime_ns if records.exists() else 0
    issue = urlencode({"csrf": csrf, "name": "portal.example", "mode": "staging", "email": "lab@example.net"})
    assert request("POST", tls, body=issue, headers=form)[0] == 303
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        status, _, page = request("GET", tls, headers=authenticated)
        assert status == 200
        if "Certbot не установлен" in page and records.stat().st_mtime_ns > previous_result:
            break
        time.sleep(1)
    else:
        raise AssertionError("Служба TLS не обработала очередь")
    assert output("systemctl", "is-active", "kvn-v5-tls.path", "kvn-v5-tls-renew.timer") == "active\nactive"
    output("systemctl", "start", "kvn-v5-tls-renew.service")
    assert output("systemctl", "show", "kvn-v5-tls-renew.service", "-p", "Result", "--value") == "success"
    print("HTTPS-панель: multipart >4 КиБ, sandbox, publish/reset через RPC, ACME .path и renew.service: OK")


if __name__ == "__main__":
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    verify_permissions(http01="--http01" in sys.argv[1:])
    if "--http01" in sys.argv[1:]:
        verify_http01()
    verify_https(sys.stdin.read().strip(), phase3_app="--phase3-app" in sys.argv[1:],
                 fixture_session="--fixture-session" in sys.argv[1:])
