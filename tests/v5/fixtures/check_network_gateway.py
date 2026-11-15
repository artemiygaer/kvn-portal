"""Смена SNI ingress и сертификата на настоящем nginx учебной VM."""

import http.client
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import threading
from tempfile import TemporaryDirectory

from check_tls_gateway import make_ca, make_pair
from v5.core.network.plan import Binding, ModuleNetwork, Route, SITE_BACKEND_PORT, build_plan
from v5.core.tls.controller import GatewayController
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.probe import reload_nginx, verify_bootstrap, verify_gateway_revision, verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, GatewayApplyError, publish_gateway


def request(context, address, port, name, host, path="/"):
    with socket.create_connection((address, port), timeout=20) as plain:
        with context.wrap_socket(plain, server_hostname=name) as session:
            session.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
            with http.client.HTTPResponse(session, method="GET") as response:
                response.begin()
                return response.status, response.read(4096)


def check_nginx(path):
    result = subprocess.run(["/usr/sbin/nginx", "-e", "stderr", "-t", "-c", str(path)],
                            capture_output=True, text=True, timeout=25)
    if result.returncode:
        raise ValueError(result.stderr.strip())


class Backend(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with self.server.context.wrap_socket(self.request, server_side=True) as connection:
                connection.settimeout(5)
                connection.recv(4096)
                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nmodule\n")
        except OSError:
            pass


class SitePassthrough(socketserver.BaseRequestHandler):
    """Учебный эквивалент Reality fallback; сам Reality проверяется в фазе Xray."""

    def handle(self):
        self.server.hits += 1
        with socket.create_connection(("127.0.0.1", SITE_BACKEND_PORT), timeout=8) as target:
            streams = (self.request, target)
            while readable := select.select(streams, [], [], 10)[0]:
                for stream in readable:
                    data = stream.recv(65536)
                    if not data:
                        return
                    (target if stream is self.request else self.request).sendall(data)


def main():
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    names, ipv6 = registry()
    site = next(item for item in names if not item.is_ip)
    assert site.name == "portal.example"
    cfg = GATEWAY_ROOT / "nginx.conf"
    before = cfg.read_bytes()
    bootstrap = GATEWAY_ROOT / "bootstrap.crt"
    master_file = Path("/run/kvn-v5-gateway/nginx.pid")
    master = master_file.read_bytes()
    with TemporaryDirectory(prefix="kvn-v5-network-lab-") as directory:
        root = Path(directory)
        ca, ca_key = make_ca(root)
        store = CertificateStore(GATEWAY_ROOT / "certs", ca_file=ca)
        gateway = GatewayController(cfg, store, names, ipv6=ipv6)
        assert not gateway.active(), "Для прогона нужен незанятый учебный bootstrap"
        tls = ssl.create_default_context(cafile=str(ca))
        module = TLSIdentity(("a" * 59 + ".") * 4 + "example", False)
        make_pair(ca, ca_key, module, 401)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / "401.pem", root / "401.key")

        def health():
            verify_bootstrap(bootstrap)

        def activate(identity, serial):
            return gateway.activate(identity, *make_pair(ca, ca_key, identity, serial),
                                    check=check_nginx, reload=reload_nginx,
                                    verify_live=lambda pair: verify_pair(pair, ca_file=ca), verify_restored=health)

        with (socketserver.TCPServer(("127.0.0.1", 0), Backend) as backend,
              socketserver.TCPServer(("127.0.0.1", 0), SitePassthrough) as passthrough):
            backend.context = context
            passthrough.hits = 0
            workers = [threading.Thread(target=server.serve_forever, daemon=True)
                       for server in (backend, passthrough)]
            for worker in workers:
                worker.start()
            independent = ModuleNetwork("telemt", True, (
                Route(module.name, Binding("tcp", "127.0.0.1", backend.server_address[1])),))
            shared_site = ModuleNetwork("xray", True, (
                Route(site.name, Binding("tcp", "127.0.0.1", passthrough.server_address[1]), self_steal=True),))
            enabled = build_plan((independent, shared_site), site_names=gateway.site_names)
            only_other = build_plan((independent,), site_names=gateway.site_names)
            empty = build_plan(())

            def live_module():
                assert request(tls, "127.0.0.2", 443, module.name, module.name) == (200, b"module\n")

            def live_site():
                for address in ("127.0.0.2", "::1") if ipv6 else ("127.0.0.2",):
                    assert request(tls, address, 443, site.name, site.name)[0] == 200
                    assert request(tls, address, 8443, site.name, site.name + ":8443", "/login")[0] == 200

            def change(plan, confirm, restored):
                gateway.replace_routes(plan, check=check_nginx, reload=reload_nginx,
                                       verify_live=confirm, verify_restored=restored,
                                       verify_loaded=lambda value: verify_gateway_revision(value, bootstrap))

            try:
                activate(site, 402)
                change(enabled, live_module, live_site)
                live_site()
                assert passthrough.hits > 0
                assert gateway.network_routes().routes == enabled.routes
                print("Debian/nginx: реальный SNI backend, сайт и независимый 8443 одновременно: OK", flush=True)
                active = activate(site, 403)
                assert gateway.generation(site) == active.chain.parent.name
                live_module()
                live_site()
                print("Реальное переключение сертификата сохранило SNI ingress: OK", flush=True)

                def fail():
                    live_site()
                    raise OSError("Контрольный отказ после reload")

                snapshot = cfg.read_bytes()
                try:
                    change(only_other, fail, live_module)
                except GatewayApplyError as exc:
                    assert exc.code == "apply_rolled_back" and cfg.read_bytes() == snapshot
                else:
                    raise AssertionError("Контрольный отказ не вызвал откат")
                live_site()
                live_module()
                hits = passthrough.hits
                change(only_other, live_site, live_module)
                live_site()
                live_module()
                assert passthrough.hits == hits
                assert gateway.network_routes().routes == only_other.routes
                print("После отключения self-steal то же имя отдаёт сайт напрямую; второй SNI жив: OK", flush=True)
                change(empty, live_site, live_module)
                assert not gateway.network_routes().routes
                assert b"load_module" not in cfg.read_bytes()
                try:
                    request(tls, "127.0.0.2", 443, module.name, module.name)
                except ssl.SSLError:
                    pass
                else:
                    raise AssertionError("Выключенный SNI доступен")
                assert master_file.read_bytes() == master
                print("Отказ/откат, удаление SNI, сохранение сайта, PID master без смены: OK", flush=True)
            finally:
                if cfg.read_bytes() != before:
                    publish_gateway(cfg, before, check=check_nginx, reload=reload_nginx,
                                    verify_live=health, verify_restored=health)
                for server, worker in zip((backend, passthrough), workers):
                    server.shutdown()
                    worker.join(10)


if __name__ == "__main__":
    main()
