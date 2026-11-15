"""Проверки настоящего nginx и активного TLS после системного reload."""

import http.client
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time

from .certificates import MAX_CHAIN_BYTES, SYSTEM_CA
from .transaction import StoredPair


UNIT = "kvn-v5-gateway.service"


def check_nginx(config: Path) -> None:
    subprocess.run(["/usr/sbin/nginx", "-e", "stderr", "-t", "-c", str(config)], check=True, timeout=15,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def reload_nginx() -> None:
    subprocess.run(["/usr/bin/systemctl", "reload", UNIT], check=True, timeout=25,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _probe(address: str, port: int, name: str, host: str, path: str, context: ssl.SSLContext,
           expected: bytes | None = None) -> None:
    with socket.create_connection((address, port), timeout=3) as plain:
        with context.wrap_socket(plain, server_hostname=name) as session:
            if expected is not None and session.getpeercert(binary_form=True) != expected:
                raise ssl.SSLError("Шлюз ещё не использует выбранный сертификат")
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            session.sendall(request.encode("ascii"))
            with http.client.HTTPResponse(session, method="GET") as response:
                response.begin()
                if response.status != 200:
                    raise OSError("Шлюз не вернул HTTPS 200")


def _until(check, timeout: float = 25) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            check()
            return
        except (OSError, http.client.HTTPException) as exc:
            if time.monotonic() >= deadline:
                raise OSError("Готовность TLS-шлюза не подтверждена") from exc
        time.sleep(0.5)


def verify_pair(pair: StoredPair, *, ca_file: Path = SYSTEM_CA) -> None:
    identity = pair.metadata.identity
    with pair.chain.open("rb") as stream:
        first = stream.read(MAX_CHAIN_BYTES + 1).split(b"-----END CERTIFICATE-----", 1)[0]
    expected = ssl.PEM_cert_to_DER_cert((first + b"-----END CERTIFICATE-----").decode("ascii"))
    context = ssl.create_default_context(cafile=str(ca_file))
    # 127.0.0.1:8443 закреплён за аварийным bootstrap, публичный wildcard проверяем через .2.
    address = "::1" if identity.is_ip and ":" in identity.name else "127.0.0.2"

    def check() -> None:
        _probe(address, 443, identity.name, identity.authority, "/", context, expected)
        _probe(address, 8443, identity.name, f"{identity.authority}:8443", "/login", context, expected)

    _until(check)


def verify_bootstrap(certificate: Path) -> None:
    context = ssl.create_default_context(cafile=str(certificate))
    _until(lambda: _probe("127.0.0.1", 8443, "127.0.0.1", "127.0.0.1:8443", "/login", context))


_REVISION = re.compile(rb"(?m)^# kvn-v5-gateway-revision ([0-9a-f]{64})$")


def verify_gateway_revision(config: bytes, certificate: Path) -> None:
    """HUP и nginx -t недостаточны: ответить должен worker нужного поколения."""
    expected = _REVISION.search(config)
    if expected is None:
        verify_bootstrap(certificate)
        return
    context = ssl.create_default_context(cafile=str(certificate))

    def check() -> None:
        connection = http.client.HTTPSConnection("127.0.0.1", 8443, context=context, timeout=3)
        try:
            connection.request("GET", "/__kvn_gateway_revision")
            response = connection.getresponse()
            if response.status != 200 or response.read(65) != expected[1]:
                raise OSError("Работает прежняя ревизия nginx")
        finally:
            connection.close()

    _until(check)
