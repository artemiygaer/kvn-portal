"""Проверка SSH-учёток и публичной страницы после обновления учебного Debian."""

import http.client
import json
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import time

from check_debian_core import signed_fixture_session


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    text = "Этот узел используется для служебных сетевых задач и проверки доступности HTTP/HTTPS."
    registered = {"Host": "portal.example"}
    for _ in range(30):
        with_http = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
        try:
            with_http.request("GET", "/", headers=registered)
            reply = with_http.getresponse()
            if reply.status == 200:
                assert text in reply.read().decode()
                assert reply.getheader("Content-Security-Policy")
                break
        finally:
            with_http.close()
        time.sleep(2)
    else:
        raise AssertionError("HTTP/80 не отдал нейтральную страницу")
    public = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
    try:
        for path, headers, expected in (("/login", registered, 404), ("/", {"Host": "unknown.invalid"}, 421)):
            public.request("GET", path, headers=headers)
            reply = public.getresponse()
            assert reply.status == expected
            reply.read()
    finally:
        public.close()

    context = ssl.create_default_context(cafile="/etc/kvn-v5/gateway/bootstrap.crt")
    web = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=40)
    cookie = signed_fixture_session()
    try:
        for path, marker in (("/", "Активные SSH-сеансы"), ("/users/ssh-accounts", "Перенос SSH-пользователей")):
            web.request("GET", path, headers={"Cookie": cookie})
            reply = web.getresponse()
            page = reply.read().decode()
            assert reply.status == 200 and marker in page, (path, reply.status)
            assert "KVN" not in re.search(r"<title>(.*?)</title>", page, re.S)[1]
            if path == "/":
                assert "kvnlab" in page and " UTC" in page
            print(f"HTTPS {path}: OK", flush=True)
    finally:
        web.close()

    login = "sshfixture_" + secrets.token_hex(4)
    fixture = """import json, sys
from pathlib import Path
from v5.portal.rpc import CoreUpdateClient
account = CoreUpdateClient(Path("/run/kvn-v5-core-update.sock")).ssh_accounts
name, password = json.load(sys.stdin)
archive = {"format": "ssh-accounts/v1", "accounts": [{"login": name, "status": "active", "key": ""}]}
assert account("import", archive=archive)["added"] == [name]
assert account("import", archive=archive)["skipped"] == [name]
account("password", login=name, password=password)
assert (archive["accounts"][0] | {"status": "disabled"}) in account("export")["accounts"]
account("enable", login=name)
assert archive["accounts"][0] in account("export")["accounts"]
account("disable", login=name)
account("delete", login=name)
"""
    subprocess.run(["/usr/sbin/runuser", "-u", "kvn-v5-web", "--", "/usr/bin/python3", "-c", fixture],
                   input=json.dumps([login, secrets.token_urlsafe(24)]), text=True, check=True, timeout=120)
    print("HTTP: нейтральная страница без доступа к панели; HTTPS-панель: SSH в обзоре; "
          "импорт, экспорт, смена пароля и переключение статуса проверены.")


if __name__ == "__main__":
    main()
