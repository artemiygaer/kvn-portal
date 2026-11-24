"""Проверить настоящую APT-проверку через HTTPS на выделенной Debian VM."""

import http.client
from pathlib import Path
import re
import ssl
import time
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    assert Path("/etc/hostname").read_text().strip() == "kvn-v5-isolated"
    route = "/maintenance/system"
    context = ssl.create_default_context(cafile="/etc/kvn-v5/gateway/bootstrap.crt")
    boot = Path("/proc/sys/kernel/random/boot_id").read_bytes()
    cookie = signed_fixture_session()

    def call(method, path, body=None):
        nonlocal cookie
        with http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=25) as client:
            headers = {"Cookie": cookie}
            if method == "POST":
                headers.update(Origin="https://127.0.0.1:8443")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            client.request(method, path, body=body, headers=headers)
            response = client.getresponse()
            if response.getheader("Set-Cookie"):
                cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            return response.status, response.read().decode()

    status, page = call("GET", route)
    assert status == 200 and "Проверить обновления" in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    body = urlencode({"csrf": csrf})
    assert call("POST", route + "/reboot", body)[0] == 400
    assert call("POST", route + "/check", body)[0] == 303
    deadline = time.monotonic() + 420
    while time.monotonic() < deadline:
        status, page = call("GET", route)
        if status == 200 and ("Доступных обновлений нет" in page or "Установить пакеты" in page):
            break
        if "не завершена" in page or "не подтвердил" in page:
            raise RuntimeError("Проверка APT не завершилась")
        time.sleep(5)
    else:
        raise RuntimeError("Не дождались результата APT")
    code, overview = call("GET", "/")
    if "Установить пакеты" in page:
        assert code == 200 and "Доступно обновлений:" in overview
    assert Path("/proc/sys/kernel/random/boot_id").read_bytes() == boot
    print("HTTPS: APT-план получен, показан в обзоре; перезагрузка без подтверждения отклонена.")


if __name__ == "__main__":
    main()
