"""HTTPS-проверки аварийного доступа в отдельном гостевом Debian."""

import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlencode

ORIGIN = "https://127.0.0.1:8443"
BOOTSTRAP = "/etc/kvn-v5/gateway/bootstrap.crt"


def request(path, *, cookie=None, data=None):
    conn = http.client.HTTPSConnection("127.0.0.1", 8443, timeout=10,
                                       context=ssl.create_default_context(cafile=BOOTSTRAP))
    try:
        headers = {"Cookie": cookie} if cookie else {}
        if data is not None:
            headers.update({"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"})
        conn.request("POST" if data is not None else "GET", path, headers=headers,
                     body=None if data is None else urlencode(data))
        response = conn.getresponse()
        return response.status, response.getheader("Set-Cookie", "").split(";", 1)[0], response.read()
    finally:
        conn.close()


def login(password, expected):
    status, cookie, body = request("/login")
    assert status == 200
    csrf = re.search(rb'name="csrf" value="([^"]+)"', body)[1].decode("ascii")
    status, cookie, _ = request("/login", cookie=cookie,
                                data={"csrf": csrf, "login": "fixture-admin", "password": password})
    assert status == expected, f"HTTPS login: HTTP {status}, ожидался {expected}"
    return cookie


def digest_state():
    digest = hashlib.sha256()
    for name in (BOOTSTRAP, "/etc/kvn-v5/gateway/bootstrap.key", "/etc/kvn-v5/gateway/nginx.conf",
                 "/var/lib/kvn-v5/site/index.html", "/var/lib/kvn-v5/packages/registry.sqlite3"):
        path = Path(name)
        if path.is_file():
            digest.update(path.read_bytes())
    sockets = subprocess.check_output(["/usr/bin/ss", "-H", "-lntu"], timeout=5)
    bindings = sorted((row[0], row[4]) for line in sockets.splitlines() if (row := line.split()))
    return {"config": digest.hexdigest(), "bindings": [(p.decode(), a.decode()) for p, a in bindings]}


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    mode = sys.argv[1]
    if mode == "snapshot":
        print(json.dumps(digest_state()))
    elif mode == "first":
        fields = json.load(sys.stdin)
        cookie = login(fields["password"], 303)
        assert request("/maintenance", cookie=cookie)[0] == 200
        print(json.dumps({"cookie": cookie}))
    elif mode == "check":
        fields = json.load(sys.stdin)
        assert request("/maintenance", cookie=fields["cookie"])[0] == 303
        login(fields["old"], 401)
        cookie = login(fields["new"], 303)
        assert request("/maintenance", cookie=cookie)[0] == 200
        print("Проверенный HTTPS: старая сессия и пароль недействительны, новый вход работает.")
    else:
        raise ValueError("Неизвестный режим теста")


if __name__ == "__main__":
    main()
