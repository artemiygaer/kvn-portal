"""Прогон TLS на отдельной Debian VM в QEMU и со стороны WSL."""

import argparse
import hashlib
import http.client
from pathlib import Path
import socket
import ssl
import subprocess
import sys

from tests.v5.debian_core_e2e import Lab


def verify_forward(ca: str, port: int, tls_name: str, authority: str, path: str):
    context = ssl.create_default_context(cadata=ca)
    with socket.create_connection(("127.0.0.1", port), timeout=20) as plain:
        with context.wrap_socket(plain, server_hostname=tls_name) as secure:
            secure.sendall(f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n".encode("ascii"))
            with http.client.HTTPResponse(secure) as response:
                response.begin()
                assert response.status == 200


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", nargs=2, metavar=("ARCHIVE", "SHA256"),
                        help="Проверить новое ядро поверх начального учебного bootstrap")
    args = parser.parse_args()
    lab = Lab(22056, Path("/var/tmp/kvn-v5-lab"))
    lab.wait()
    local = Path(__file__).with_name("fixtures") / "check_tls_gateway.py"
    directory = "/var/tmp/kvn-v5-phase2"
    pythonpath = "/usr/local/lib/kvn-v5"
    flags = ""
    if args.candidate:
        archive, digest = Path(args.candidate[0]), args.candidate[1].lower()
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            parser.error("Неверный SHA-256 учебного архива")
        directory = "/var/tmp/kvn-v5-phase3-candidate"
        pythonpath = directory
        flags = " --prepare-bootstrap"
        lab.run(f"install -d -m 0700 {directory}")
        lab.upload(archive, f"{directory}/candidate.tar.gz")
        lab.run(f"set -eu; umask 077; cd {directory}; sha256sum --check --strict; tar -xzf candidate.tar.gz --no-same-owner",
                data=f"{digest}  candidate.tar.gz\n".encode())
    remote = f"{directory}/check_tls_gateway.py"
    lab.upload(local, remote)
    result = lab.run(f"PYTHONPATH={pythonpath} python3 {remote}{flags}", timeout=400)
    print(result.stdout.decode(), flush=True)
    ca = lab.run("cat /var/tmp/kvn-v5-phase3-ca.pem").stdout.decode("ascii")
    for name in ("portal.example", "www.portal.example", "192.0.2.8"):
        verify_forward(ca, 22443, name, name, "/")
        verify_forward(ca, 22444, name, f"{name}:8443", "/login")
    print("Из WSL через QEMU: HTTPS 200 на обоих входах для двух DNS-имён и IP, доверенный тестовый CA.")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stdout.decode(errors="replace"), file=sys.stderr)
        print(exc.stderr.decode(errors="replace"), file=sys.stderr)
        raise SystemExit(exc.returncode)
