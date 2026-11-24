"""Синтетическая запись shadow подмонтируется только тестовому агенту."""

from contextlib import closing
import http.client
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import sys

from v5.core.private_files import write_private
from v5.portal.console_ws import BrowserGate, COOKIE

STAGE = Path("/var/tmp/kvn-v5-console-config")
DROP_IN = Path("/etc/systemd/system/kvn-v5-console-agent.service.d/90-browser-fixture.conf")
SHADOW = STAGE / "browser-shadow"
PASSPHRASE = b"console-lab-only-fixture"


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    assert Path("/etc/hostname").read_text().strip() == "kvn-v5-isolated"
    action = sys.argv[1]
    if action == "mount":
        result = subprocess.run(["/usr/bin/openssl", "passwd", "-6", "-stdin"], input=PASSPHRASE + b"\n",
                                capture_output=True, timeout=10, check=True)
        write_private(SHADOW, b"root:" + result.stdout.strip() + b":20000:0:99999:7:::\n")
        DROP_IN.parent.mkdir(mode=0o755, exist_ok=True)
        DROP_IN.write_text(f"[Service]\nBindReadOnlyPaths={SHADOW}:/etc/shadow\n", encoding="ascii")
    elif action == "cleanup":
        DROP_IN.unlink(missing_ok=True)
        SHADOW.unlink(missing_ok=True)
    else:
        config = json.loads(Path("/etc/kvn-v5/web/config.json").read_bytes())
        signed = BrowserGate(config).serializer.dumps({"admin": True, "_permanent": True,
                                                        "console_sid": secrets.token_urlsafe(24),
                                                        "csrf": secrets.token_urlsafe(24)})
        if action == "cookie":
            print(json.dumps({"cookies": [{"name": COOKIE, "value": signed, "domain": "127.0.0.1",
                                          "path": "/", "expires": -1, "httpOnly": True, "secure": True,
                                          "sameSite": "Strict"}], "origins": []}))
        elif action == "disabled":
            context = ssl.create_default_context(cafile="/etc/kvn-v5/gateway/bootstrap.crt")
            for path in ("/maintenance/console", "/maintenance/console/ws"):
                with closing(http.client.HTTPSConnection("127.0.0.1", 8443, timeout=10, context=context)) as connection:
                    connection.request("GET", path, headers={"Cookie": COOKIE + "=" + signed,
                                                             "Origin": "https://127.0.0.1:8443",
                                                             "Upgrade": "websocket", "Connection": "upgrade"})
                    response = connection.getresponse()
                    if path.endswith("/ws"):
                        assert response.status == 404, path
                    else:
                        body = response.read()
                        assert response.status == 200 and b"systemctl start kvn-v5-console-web.socket" in body, path
                        assert b"xterm.js" not in body
            print("HTTPS: справка доступна, WebSocket закрыт, фоновые службы консоли не запущены.")
        else:
            raise ValueError("Неизвестная операция теста")


if __name__ == "__main__":
    main()
