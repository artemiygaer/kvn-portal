"""Настоящий nginx/systemd на учебной VM; CA и ключи только синтетические."""

import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
from tempfile import TemporaryDirectory

from v5.core.site.document import DEFAULT_SITE, SiteStore, UnsafeDocument
from v5.core.tls.certificates import CertificateError
from v5.core.tls.controller import GatewayController
from v5.core.tls.gateway import SITE_ROOT, render_gateway
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.transaction import CertificateStore, GatewayApplyError, publish_gateway


GATEWAY = Path("/etc/kvn-v5/gateway")
LAB_CA = Path("/var/tmp/kvn-v5-phase3-ca.pem")


def openssl(*arguments: str) -> None:
    subprocess.run(["/usr/bin/openssl", *arguments], check=True, capture_output=True, timeout=30)


def make_ca(root: Path) -> tuple[Path, Path]:
    ca, key = root / "ca.pem", root / "ca.key"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-subj", "/CN=KVN v5 isolated fixture", "-days", "7",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash", "-keyout", str(key), "-out", str(ca))
    return ca, key


def make_pair(ca: Path, ca_key: Path, identity: TLSIdentity, serial: int, days: int = 1) -> tuple[bytes, bytes]:
    key, csr, cert, ext = (ca.parent / f"{serial}.{suffix}" for suffix in ("key", "csr", "pem", "ext"))
    san = f"{'IP' if identity.is_ip else 'DNS'}:{identity.name}"
    ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                   "extendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid:always\n"
                   f"subjectKeyIdentifier=hash\nsubjectAltName={san}\n", encoding="ascii")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-subj", "/CN=KVN v5 fixture leaf", "-keyout", str(key), "-out", str(csr))
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-set_serial", str(serial),
            "-days", str(days), "-extfile", str(ext), "-out", str(cert))
    return cert.read_bytes(), key.read_bytes()


def request(context, name, host, port, path="/", *, origin=None, method="GET"):
    with socket.create_connection(("127.0.0.2", port), timeout=20) as plain:
        with context.wrap_socket(plain, server_hostname=name) as session:
            origin_header = f"Origin: {origin}\r\n" if origin else ""
            session.sendall((f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n{origin_header}"
                             "Content-Length: 0\r\nCookie: __Host-kvn-v5=ignored\r\nConnection: close\r\n\r\n").encode("ascii"))
            with http.client.HTTPResponse(session, method=method) as reply:
                reply.begin()
                return reply.status, reply.headers, reply.read(256 * 1024)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-bootstrap", action="store_true")
    args = parser.parse_args()
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    config = GATEWAY / "nginx.conf"
    identities = json.loads((GATEWAY / "identities.json").read_text())
    ip = TLSIdentity(identities["ip"], True)
    one, two = (TLSIdentity(name, False) for name in identities["names"])
    assert (one.name, two.name, ip.name) == ("portal.example", "www.portal.example", "192.0.2.8")
    if args.prepare_bootstrap:
        assert not GatewayController(config, CertificateStore(GATEWAY / "certs"),
                                     (ip, one, two), ipv6=identities["ipv6"]).active()

        def restart_fixture():
            subprocess.run(["/usr/bin/systemctl", "restart", "kvn-v5-gateway.service"], check=True, timeout=60)

        def bootstrap_fixture():
            verify_bootstrap(GATEWAY / "bootstrap.crt")

        # Только в VM: обновить начальные параметры сокета старого учебного ядра.
        publish_gateway(config, render_gateway((ip, one, two), ipv6=identities["ipv6"]).encode(),
                        check=check_nginx, reload=restart_fixture, verify_live=bootstrap_fixture,
                        verify_restored=bootstrap_fixture)
        print("Учебный bootstrap подготовлен; все дальнейшие применения — только reload.", flush=True)
    before = config.read_bytes()
    master = Path("/run/kvn-v5-gateway/nginx.pid").read_text().strip()
    site = SiteStore(SITE_ROOT)
    with TemporaryDirectory(prefix="kvn-v5-tls-fixture-") as directory:
        ca, ca_key = make_ca(Path(directory))
        context = ssl.create_default_context(cafile=str(ca))
        store = CertificateStore(GATEWAY / "certs", ca_file=ca)
        controller = GatewayController(config, store, (ip, one, two), ipv6=identities["ipv6"])
        assert not controller.active()
        material = {item: make_pair(ca, ca_key, item, index) for index, item in enumerate((one, two, ip), 1)}

        def bootstrap():
            verify_bootstrap(GATEWAY / "bootstrap.crt")

        def live(pair):
            verify_pair(pair, ca_file=ca)

        def apply(item, data, *, confirm=live, restored=bootstrap):
            return controller.activate(item, *data, check=check_nginx, reload=reload_nginx,
                                       verify_live=confirm, verify_restored=restored)

        try:
            for item, data in material.items():
                apply(item, data)
            active = {pair.metadata.identity: pair for pair in controller.active()}
            assert set(active) == set(material)
            for pair in active.values():
                live(pair)
            bootstrap()
            assert Path("/run/kvn-v5-gateway/nginx.pid").read_text().strip() == master
            assert request(context, one.name, two.name, 443)[0] == 421
            assert request(context, one.name, f"{two.name}:8443", 8443, "/login")[0] == 421
            assert request(context, one.name, "wrong.example", 443)[0] == 421
            assert request(context, one.name, one.name, 443, "/login")[0] == 404
            assert request(context, one.name, one.name, 443, "/run/kvn-v5-agent/control.sock")[0] == 404
            assert request(context, one.name, f"{one.name}:8443", 8443, "/login", method="POST",
                           origin=f"https://{one.name}")[0] == 403
            assert request(context, ip.name, ip.name, 443)[0] == 200
            assert request(context, ip.name, f"{ip.name}:8443", 8443, "/login")[0] == 200
            print("nginx/systemd: две DNS-пары, IP без SNI, SNI/Host и CSRF на 443/8443, bootstrap: OK", flush=True)

            source = "<main><h1>Публичная страница стенда</h1></main>".encode()
            site.publish(source)
            for item in (one, two):
                status, headers, body = request(context, item.name, item.name, 443)
                assert status == 200 and source in body and "sandbox" in headers["Content-Security-Policy"]
                assert headers["Set-Cookie"] is None
            try:
                site.publish(b"<script>alert(1)</script>")
                raise AssertionError("Скрипт прошёл фильтр")
            except UnsafeDocument:
                assert source in request(context, one.name, one.name, 443)[2]
            site.reset()
            assert request(context, two.name, two.name, 443)[2] == DEFAULT_SITE

            snapshot = config.read_bytes()
            try:
                apply(one, make_pair(ca, ca_key, one, 10, days=0))
                raise AssertionError("Просроченный сертификат принят")
            except CertificateError:
                assert config.read_bytes() == snapshot

            def fail_after_reload(pair):
                live(pair)
                raise OSError("Учебный отказ после применения кандидата")

            try:
                apply(one, make_pair(ca, ca_key, one, 11), confirm=fail_after_reload,
                      restored=lambda: live(active[one]))
                raise AssertionError("Откат не вызван")
            except GatewayApplyError as exc:
                assert exc.code == "apply_rolled_back"
                assert config.read_bytes() == snapshot
                for pair in active.values():
                    live(pair)
            assert Path("/run/kvn-v5-gateway/nginx.pid").read_text().strip() == master
            LAB_CA.write_bytes(ca.read_bytes())
            print("Публикация/возврат сайта, отказ просроченной пары и настоящий reload/откат: OK", flush=True)
        except BaseException:
            if config.read_bytes() != before:
                publish_gateway(config, before, check=check_nginx, reload=reload_nginx,
                                verify_live=bootstrap, verify_restored=bootstrap)
            site.reset()
            raise


if __name__ == "__main__":
    main()
