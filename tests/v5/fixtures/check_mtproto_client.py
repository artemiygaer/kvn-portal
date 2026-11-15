"""Внешний клиент получает только учебную ссылку через stdin, без root."""

import subprocess
import sys

from check_network_nft import NS

CLIENT_ROOT = "/var/tmp/kvn-v5-mtproto-client"
_CLIENT = """
import logging
import sys

events = []
class SafeHandler(logging.Handler):
    def emit(self, record):
        event = getattr(record, "event", "")
        if event in {"tcp_connected", "faketls_handshake_complete", "obfuscated2_init_sent", "req_pq_multi_sent"}:
            events.append(event)
logging.basicConfig(level=logging.INFO, handlers=[SafeHandler()])
from mtproxy_checker.checker import check_proxy
from mtproxy_checker.models import CheckOptions, Mode
logging.getLogger("mtproxy_checker").addHandler(SafeHandler())
logging.getLogger("mtproxy_checker").setLevel(logging.INFO)

uri = sys.stdin.readline(4096).strip()
result = check_proxy(uri, CheckOptions(mode=Mode.FAKETLS, dc=2, connect_timeout=10, response_timeout=30))
if result.ok and result.mode == Mode.FAKETLS and result.server_nonce:
    print("ok")
else:
    print(result.error_code.value if result.error_code else "unknown")
    print(events[-1] if events else "no_stage")
    sys.exit(1)
"""
_COVER = """
import http.client
import socket
import ssl
import sys

ip, port, name, ca = sys.argv[1:]
try:
    context = ssl.create_default_context(cafile=ca or None)
    with socket.create_connection((ip, int(port)), timeout=8) as transport:
        with context.wrap_socket(transport, server_hostname=name) as secured:
            secured.sendall(f"GET / HTTP/1.1\\r\\nHost: {name}\\r\\nConnection: close\\r\\n\\r\\n".encode("ascii"))
            with http.client.HTTPResponse(secured) as response:
                response.begin()
                if not 100 <= response.status <= 599:
                    raise RuntimeError("Нет ответа HTTP от маскировки")
except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
    print(type(exc).__name__)
    sys.exit(1)
"""


def fake_tls(profile, *, expected=True):
    result = subprocess.run(
        ["/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/setpriv", "--reuid=nobody", "--regid=nogroup",
         "--clear-groups", "--no-new-privs", "--bounding-set=-all",
         sys.executable, "-B", "-c", _CLIENT],
        input=(profile.uri() + "\n").encode("ascii"), capture_output=True, check=False, timeout=60, cwd="/",
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/nonexistent", "PYTHONPATH": CLIENT_ROOT},
    )
    lines = result.stdout.decode("ascii", errors="replace").splitlines()
    reason = lines[0].strip() if lines else ""
    recognized = bool(reason and reason.isascii() and reason.replace("_", "").isalnum() and len(reason) <= 48)
    if ((expected and (result.returncode != 0 or reason != "ok"))
            or (not expected and (result.returncode != 1 or not recognized or reason == "ok"))):
        # Не выводим traceback библиотеки, саму ссылку, URI или сетевые пакеты.
        safe = reason if recognized else "unknown"
        stage = lines[1].strip() if len(lines) > 1 else "no_stage"
        if stage not in {"tcp_connected", "faketls_handshake_complete", "obfuscated2_init_sent", "req_pq_multi_sent"}:
            stage = "no_stage"
        raise AssertionError(f"{profile.module}: результат FakeTLS не совпал, код {safe}, этап {stage}")


def cover_https(profile, *, ca=""):
    result = subprocess.run(
        ["/usr/sbin/ip", "netns", "exec", NS, sys.executable, "-c", _COVER,
         profile.server, str(profile.port), profile.sni, ca],
        capture_output=True, check=False, timeout=18,
    )
    if result.returncode:
        reason = result.stdout.decode("ascii", errors="replace").strip()
        safe = reason if reason.isascii() and reason.isalpha() and len(reason) <= 48 else "unknown"
        raise AssertionError(f"{profile.module}: TLS/HTTP маскировки не подтверждён ({safe})")
