"""Проверка выбора центра через HTTPS только на изолированной Debian VM."""

import http.client
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    context = ssl.create_default_context(cafile="/etc/kvn-v5/gateway/bootstrap.crt")
    client = http.client.HTTPSConnection("127.0.0.1", 8443, timeout=45, context=context)
    route = "/settings/tls"
    headers = {"Cookie": signed_fixture_session()}
    try:
        client.request("GET", route, headers=headers)
        response = client.getresponse()
        page = response.read().decode()
        assert response.status == 200
        assert 'value="public">Let’s Encrypt' in page and 'value="zerossl" disabled' in page
        assert "python3 -m v5.core.tls.zerossl" in page
        assert "portal.example" in page
        if response.getheader("Set-Cookie"):
            headers["Cookie"] = response.getheader("Set-Cookie").split(";", 1)[0]
        csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
        post_headers = {**headers, "Origin": "https://127.0.0.1:8443",
                        "Content-Type": "application/x-www-form-urlencoded"}
        body = urlencode({"name": "portal.example", "mode": "zerossl", "csrf": csrf, "email": ""})
        client.request("POST", route, body=body, headers=post_headers)
        response = client.getresponse()
        response.read()
        assert response.status == 303
        if response.getheader("Set-Cookie"):
            headers["Cookie"] = response.getheader("Set-Cookie").split(";", 1)[0]
        client.request("GET", route, headers=headers)
        response = client.getresponse()
        assert "Аккаунт ZeroSSL не привязан" in response.read().decode()
        assert not Path("/var/lib/kvn-v5/tls/pending.json").exists()
        print("HTTPS: Let’s Encrypt по умолчанию; ZeroSSL без EAB не ставится в очередь.")
    finally:
        client.close()


if __name__ == "__main__":
    main()
