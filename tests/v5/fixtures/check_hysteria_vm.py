"""Подписанный Hysteria2 на учебном Debian: UDP, TLS, трафик и перезагрузка."""

import base64
from contextlib import contextmanager
from dataclasses import replace
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from threading import Thread
from tempfile import mkdtemp
import time

from check_network_gateway import request
from check_network_nft import ADDRESSES, HOST, NS, add_client, remove_client, run
from check_tls_gateway import make_ca, make_pair
from v5.core.lifecycle.assembly import HostContext
from v5.core.lifecycle.controller import Lifecycle
from v5.core.lifecycle.journal import IntentJournal, PENDING_NAME
from v5.core.network.plan import NetworkConflict
from v5.core.network.runtime import NetworkRuntime
from v5.core.packages.manifest import PackageError, canonical_json
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.signature import load_publisher
from v5.core.private_files import read_private, write_private
from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, publish_gateway
from v5.modules.hysteria.adapter import HysteriaAdapter
from v5.modules.hysteria.clients import client_profile, subscription
from v5.modules.hysteria.config import Account, Settings, render_server
from v5.modules.hysteria.runtime import MODULE_ROOT, inspect_container, runtime_state

BASE = Path("/var/tmp/kvn-v5-phase8")
FIXTURE = BASE / "fixture"
CA = FIXTURE / "ca.pem"
NEW_CA = FIXTURE / "renewed" / "ca.pem"
CONFIG = GATEWAY_ROOT / "nginx.conf"
BOOT = Path("/proc/sys/kernel/random/boot_id")
BOOT_UNIT = Path("/etc/systemd/system/kvn-v5-phase8-reconcile.service")
SITE = "portal.example"
ADDRESS = ADDRESSES[0]
PORT = 443
ORIGIN = 18887
PAYLOAD = b"kvn-v5-hysteria-quic-fixture"
CLIENT = BASE / "hysteria"


def core():
    names, ipv6 = registry()
    gateway = GatewayController(CONFIG, CertificateStore(GATEWAY_ROOT / "certs", ca_file=CA), names, ipv6=ipv6)
    packages = PackageRegistry(FIXTURE / "registry", load_publisher(BASE / "publisher.json"))
    adapter = HysteriaAdapter(HostContext(packages, gateway))
    lifecycle = Lifecycle(packages, {"hysteria": adapter}, NetworkRuntime(gateway),
                          IntentJournal(packages.root / PENDING_NAME), site_names=gateway.site_names)
    return adapter, lifecycle, gateway


def client_ns(*args):
    return ["/usr/sbin/ip", "netns", "exec", NS, *args]


def check_public():
    context = ssl.create_default_context(cafile=NEW_CA if NEW_CA.exists() else CA)
    context.set_alpn_protocols(["http/1.1"])
    assert request(context, ADDRESS, 443, SITE, SITE)[0] == 200
    assert request(context, ADDRESS, 8443, SITE, f"{SITE}:8443", "/login")[0] == 200


def closed(address=ADDRESS, port=PORT):
    # Точный ICMP port unreachable из отдельного netns, не просто отсутствие ответа QUIC.
    run(*client_ns(sys.executable, __file__, "closed", address, str(port)))


def probe_closed(address, port):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as probe:
        probe.settimeout(3)
        probe.connect((address, port))
        probe.send(PAYLOAD)
        try:
            probe.recv(128)
        except ConnectionRefusedError:
            return
    raise AssertionError("UDP-порт не подтвердил закрытие")


def check_client(profile, *, mode="good", use_uri=False, denied_account=None,
                 directory=FIXTURE, binary=CLIENT):
    config = ({"server": profile.uri(), "tls": {"insecure": False}} if use_uri else profile.native())
    config["http"] = {"listen": "127.0.0.1:18886"}
    ca, renewed = directory / "ca.pem", directory / "renewed" / "ca.pem"
    if mode != "untrusted":
        config["tls"]["ca"] = str(renewed if renewed.exists() and mode != "old-ca" else ca)
    if mode == "bad-auth":
        config["auth"] = profile.account.name + ":" + "z" * 43
    if mode == "off-user":
        config["auth"] = denied_account.auth
    if mode == "bad-sni":
        config["tls"]["sni"] = "wrong.example"
    path = directory / "client.json"
    write_private(path, canonical_json(config))
    command = client_ns(str(binary), "client", "--disable-update-check", "--config", str(path))
    try:
        if mode != "good":
            failure = subprocess.run(command, capture_output=True, check=False, timeout=20)
            assert failure.returncode != 0, mode
            expected = {"bad-auth": (b"authentication", b"auth error"), "off-user": (b"authentication", b"auth error"),
                        "bad-sni": (b"unrecognized name", b"tls", b"crypto_error"),
                        "untrusted": (b"unknown authority", b"x509"), "old-ca": (b"unknown authority", b"x509")}
            assert any(value in failure.stderr.lower() + failure.stdout.lower()
                       for value in expected[mode]), f"Не подтверждена ожидаемая причина отказа {mode}"
            return
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
            try:
                deadline = time.monotonic() + 25
                while child.poll() is None and time.monotonic() < deadline:
                    result = subprocess.run(client_ns("/usr/bin/curl", "-fsS", "--max-time", "2",
                                                       "--noproxy", "", "-x", "http://127.0.0.1:18886",
                                                       f"http://{ADDRESS}:{ORIGIN}/"),
                                            capture_output=True, check=False, timeout=5)
                    if result.returncode == 0 and result.stdout == PAYLOAD:
                        return
                    time.sleep(0.4)
                raise AssertionError("Клиент не передал тестовый HTTP через QUIC")
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=12)
    finally:
        path.unlink(missing_ok=True)


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, *args):
        pass


@contextmanager
def isolated_network():
    assert run("/usr/sbin/ip", "link", "show", HOST, check=False).returncode
    assert NS not in run("/usr/sbin/ip", "netns", "list").stdout.decode().split()
    try:
        add_client()
        with HTTPServer((ADDRESS, ORIGIN), Origin) as origin:
            worker = Thread(target=origin.serve_forever, daemon=True)
            worker.start()
            try:
                yield
            finally:
                origin.shutdown()
                worker.join(3)
    finally:
        remove_client()


def check_initial():
    assert not FIXTURE.exists() and not MODULE_ROOT.exists() and not BOOT_UNIT.exists()
    assert CLIENT.is_file()
    FIXTURE.mkdir(mode=0o700)
    write_private(FIXTURE / "before.nginx", CONFIG.read_bytes())
    ca, key = make_ca(FIXTURE)
    adapter, lifecycle, gateway = core()
    packages = lifecycle.inventory
    assert not gateway.active()
    tls = next(item for item in gateway.identities if item.name == SITE)
    bootstrap = GATEWAY_ROOT / "bootstrap.crt"
    with isolated_network():
        with (BASE / "kvn-module-hysteria-2.13.0.tar.gz").open("rb") as stream:
            ticket = packages.prepare(stream).ticket
        packages.install(ticket)
        assert not packages.installed()[0]["enabled"] and not MODULE_ROOT.exists()
        assert inspect_container(adapter.docker) is None
        closed()

        settings = Settings(tls, (Account.create("reader"), replace(Account.create("off"), enabled=False)),
                            bind=ADDRESS, salamander=Account.create("obfs").password)
        adapter.configure(settings)
        try:
            lifecycle.change("hysteria", True)
        except PackageError as exc:
            assert str(exc) == "hysteria_trusted_tls_required", str(exc)
        else:
            raise AssertionError("Hysteria2 открыт без доверенного сертификата")
        closed()
        assert lifecycle.journal.read() is None
        verify_bootstrap(bootstrap)
        print("Подписанный пакет установлен выключенным; без доверенного TLS UDP/443 не открывается.")
        gateway.activate(tls, *make_pair(ca, key, tls, 801), check=check_nginx, reload=reload_nginx,
                         verify_live=lambda pair: verify_pair(pair, ca_file=ca),
                         verify_restored=lambda: verify_bootstrap(bootstrap))
        check_public()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as foreign:
            foreign.bind((ADDRESS, PORT))
            before = CONFIG.read_bytes()
            try:
                lifecycle.change("hysteria", True)
            except NetworkConflict as exc:
                assert str(exc) == "publication_port_unavailable", str(exc)
            else:
                raise AssertionError("Занятый UDP-порт принят")
            assert CONFIG.read_bytes() == before and lifecycle.journal.read() is None
            assert inspect_container(adapter.docker) is None and not packages.installed()[0]["enabled"]
        print("Занятый UDP/443 отклонён до журналирования/apply, сайт и Docker не изменены.")

        snapshot = CONFIG.read_bytes()
        state = lifecycle.change("hysteria", True)
        assert not state.routes and tuple(x.publication.public for x in state.publications) == (settings.binding,)
        assert not gateway.network_routes().routes and CONFIG.read_bytes() == snapshot
        closed(ADDRESS, 11443)
        closed(ADDRESSES[1], PORT)
        check_public()
        profile = client_profile(settings, "reader", active=True, endpoint=ADDRESS)
        assert base64.b64decode(subscription(profile)).decode().strip() == profile.uri()
        assert client_profile(settings, "off", active=True) is None
        check_client(profile)
        check_client(profile, use_uri=True)
        for mode in ("bad-auth", "untrusted", "bad-sni"):
            check_client(profile, mode=mode)
        check_client(profile, mode="off-user", denied_account=settings.accounts[1])
        print("UDP/443: QUIC и HTTP-трафик штатным клиентом; плохой пароль, чужая CA и SNI отвергнуты.")

        NEW_CA.parent.mkdir(mode=0o700)
        new_ca, new_key = make_ca(NEW_CA.parent)
        before = inspect_container(adapter.docker)["id"]
        renewed = GatewayController(CONFIG, CertificateStore(GATEWAY_ROOT / "certs", ca_file=new_ca),
                                    gateway.identities, ipv6=gateway.ipv6)
        renewed.activate(tls, *make_pair(new_ca, new_key, tls, 802), check=check_nginx, reload=reload_nginx,
                         verify_live=lambda pair: verify_pair(pair, ca_file=new_ca),
                         verify_restored=lambda: verify_bootstrap(bootstrap))
        adapter.refresh_certificate()
        check_client(profile)
        check_client(profile, mode="old-ca")
        check_public()
        assert inspect_container(adapter.docker)["id"] == before
        print("Переизданный сертификат принят при следующем QUIC-подключении без смены контейнера.")

        assert not lifecycle.change("hysteria", False).active
        check_disabled(adapter, lifecycle, settings)
    seal_boot(profile)


def check_disabled(adapter, lifecycle, settings):
    records = lifecycle.inventory.installed()
    assert len(records) == 1 and records[0]["module"] == "hysteria" and records[0]["version"] == "2.13.0"
    active = bool(records[0]["enabled"])  # SQLite хранит флаг как INTEGER.
    assert not active and lifecycle.journal.read() is None
    assert not adapter.running() and inspect_container(adapter.docker) is None
    assert client_profile(settings, "reader", active=active) is None
    assert adapter.settings() == settings
    assert (runtime_state().folder / "server.json").read_bytes() == canonical_json(render_server(settings))
    closed()
    check_public()
    print("После disable: UDP/443 закрыт, экспорт скрыт, настройки сохранены; TCP/443 и 8443 доступны.")


def seal_boot(profile):
    assert not BOOT_UNIT.exists() and not (FIXTURE / "boot-before").exists()
    write_private(FIXTURE / "boot-before", BOOT.read_bytes())
    write_private(FIXTURE / "profile.sha256", hashlib.sha256(profile.uri().encode()).hexdigest().encode())
    BOOT_UNIT.write_text(
        "[Unit]\nDescription=KVN v5 phase 8 isolated reconciliation\n"
        "Wants=kvn-v5-gateway.service docker.service\nAfter=kvn-v5-gateway.service docker.service\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=PYTHONPATH=/usr/local/lib/kvn-v5\n"
        f"ExecStart=/usr/bin/python3 {__file__} boot\n[Install]\nWantedBy=multi-user.target\n")
    run("/usr/bin/systemctl", "enable", BOOT_UNIT.name)


def resume_disabled():
    """Продолжить учебный прогон после сбоя драйвера уже после disable."""
    assert NEW_CA.is_file() and not BOOT_UNIT.exists() and not (FIXTURE / "boot-before").exists()
    adapter, lifecycle, _ = core()
    settings = adapter.settings()
    assert settings.bind == ADDRESS and {item.name for item in settings.accounts} == {"reader", "off"}
    with isolated_network():
        check_disabled(adapter, lifecycle, settings)
    seal_boot(client_profile(settings, "reader", active=True, endpoint=ADDRESS))


def check_reboot_marker():
    assert BOOT.read_bytes() != read_private(FIXTURE / "boot-before", 64)
    assert read_private(FIXTURE / "boot-reconciled", 64) == BOOT.read_bytes()


def verify_reboot_disabled():
    check_reboot_marker()
    adapter, lifecycle, _ = core()
    with isolated_network():
        check_disabled(adapter, lifecycle, adapter.settings())
    print("Текущий boot ID подтверждён; после загрузки Hysteria2 выключен и UDP закрыт.")


def after_reboot():
    check_reboot_marker()
    adapter, lifecycle, _ = core()
    with isolated_network():
        closed()
        check_public()
        assert not lifecycle.inventory.installed()[0]["enabled"] and inspect_container(adapter.docker) is None
        settings = adapter.settings()
        assert client_profile(settings, "reader", active=False) is None
        lifecycle.change("hysteria", True)
        try:
            profile = client_profile(settings, "reader", active=True, endpoint=ADDRESS)
            assert hashlib.sha256(profile.uri().encode()).hexdigest().encode() == read_private(
                FIXTURE / "profile.sha256", 64)
            check_client(profile)
            check_public()
        finally:
            lifecycle.change("hysteria", False)
        closed()
        check_public()
    print("После reboot: UDP закрыт; повторное включение вернуло прежнюю ссылку и реальный трафик.")
    run("/usr/bin/systemctl", "disable", BOOT_UNIT.name)
    BOOT_UNIT.unlink()
    run("/usr/bin/systemctl", "daemon-reload")
    bootstrap = GATEWAY_ROOT / "bootstrap.crt"
    publish_gateway(CONFIG, read_private(FIXTURE / "before.nginx", 512 * 1024),
                    check=check_nginx, reload=reload_nginx, verify_live=lambda: verify_bootstrap(bootstrap),
                    verify_restored=lambda: None)
    MODULE_ROOT.rename(FIXTURE / "module-state")
    write_private(FIXTURE / "completed", BOOT.read_bytes())


def preserve_fixture():
    """Освободить только ресурсы собственного прогона, сохранив его данные."""
    if not FIXTURE.exists():
        return
    assert not BOOT_UNIT.exists()
    assert not (FIXTURE / "boot-before").exists() or (FIXTURE / "completed").is_file()
    before = read_private(FIXTURE / "before.nginx", 512 * 1024)
    if not (FIXTURE / "completed").is_file():
        adapter, _, gateway = core()
        pairs = gateway.active()
        assert not pairs or len(pairs) == 1 and pairs[0].metadata.identity.name == SITE
        if MODULE_ROOT.exists():
            # Подтвердить настройки учебного модуля до остановки любого процесса.
            settings = adapter.settings()
            assert settings.bind == ADDRESS and {item.name for item in settings.accounts} == {"reader", "off"}
            if adapter.running():
                adapter.stop()
            assert inspect_container(adapter.docker) is None
            MODULE_ROOT.rename(FIXTURE / "module-state")
        bootstrap = GATEWAY_ROOT / "bootstrap.crt"
        publish_gateway(CONFIG, before, check=check_nginx, reload=reload_nginx,
                        verify_live=lambda: verify_bootstrap(bootstrap), verify_restored=lambda: None)
    folder = Path(mkdtemp(dir=BASE, prefix="archived-"))
    FIXTURE.rename(folder / "fixture")


if __name__ == "__main__":
    assert os.geteuid() == 0
    mode = sys.argv[1] if len(sys.argv) > 1 else "initial"
    if mode == "closed":
        # Без доступа к хостовым listener'ам: только клиентский netns стенда.
        assert os.path.samefile("/proc/self/ns/net", Path("/run/netns") / NS)
        assert sys.argv[2] in ADDRESSES
        probe_closed(sys.argv[2], int(sys.argv[3]))
        sys.exit(0)
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    if mode == "boot":
        assert not core()[1].reconcile().active
        write_private(FIXTURE / "boot-reconciled", BOOT.read_bytes())
    elif mode == "after-reboot":
        after_reboot()
    elif mode == "check-disabled-after-reboot":
        verify_reboot_disabled()
    elif mode == "resume-disabled":
        resume_disabled()
    elif mode == "preserve":
        preserve_fixture()
    else:
        assert mode == "initial"
        check_initial()
