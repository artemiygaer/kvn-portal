"""Живой systemd lifecycle и восстановление после убийства процесса/reboot."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time

from check_network_gateway import request
from check_network_nft import ADDRESSES, HOST, PAYLOAD, add_client, probe, remove_client, run
from check_tls_gateway import make_ca, make_pair
from v5.core.lifecycle.controller import Lifecycle, LifecycleError
from v5.core.lifecycle.journal import IntentJournal, PENDING_NAME
from v5.core.lifecycle.systemd import SystemdAdapter
from v5.core.network.plan import Binding, ModuleNetwork, NetworkConflict, Publication
from v5.core.network.runtime import NetworkRuntime
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.signature import load_publisher
from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, publish_gateway

BASE = Path("/var/tmp/kvn-v5-phase5")
STATE = BASE / "lifecycle"
MODULE = "wireguard"
PORT = 52181
BOOT_UNIT = "kvn-v5-phase5-fixture.service"
UNIT = f"kvn-v5-module-{MODULE}.service"
SYSTEMD = Path("/etc/systemd/system")
CA = STATE / "ca.pem"
CONFIG = GATEWAY_ROOT / "nginx.conf"


def check_identity():
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"


def write_new(path, value, mode=0o600):
    with path.open("xb") as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(value)


def settings_hash():
    return hashlib.sha256((STATE / "fixture.json").read_bytes() + (STATE / "fixture.key").read_bytes()).hexdigest()


def gateway():
    identities, ipv6 = registry()
    return GatewayController(CONFIG, CertificateStore(GATEWAY_ROOT / "certs", ca_file=CA), identities, ipv6=ipv6)


def public_core():
    ca = ssl.create_default_context(cafile=str(CA))
    for address in ADDRESSES:
        assert request(ca, address, 443, "portal.example", "portal.example")[0] == 200
        assert request(ca, address, 8443, "portal.example", "portal.example:8443", "/login")[0] == 200
        conn = http.client.HTTPConnection(address, 80, timeout=8)
        try:
            conn.request("GET", "/", headers={"Host": "portal.example"})
            assert conn.getresponse().status == 308
        finally:
            conn.close()


def publications():
    return ModuleNetwork(MODULE, publications=tuple(
        Publication(Binding("udp", address, PORT)) for address in ("0.0.0.0", "::")))


def verify_udp():
    deadline = time.monotonic() + 30
    while True:
        try:
            for address in ADDRESSES:
                probe(address, "udp", PORT, "open")
            return
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def make_lifecycle(live_probe=None):
    inventory = PackageRegistry(STATE / "packages", load_publisher(BASE / "lifecycle-publisher.json"))
    router = gateway()
    network = NetworkRuntime(router, live_probe=live_probe)
    adapter = SystemdAdapter(MODULE, publications, verify_udp)
    intent = IntentJournal(inventory.root / PENDING_NAME)
    return Lifecycle(inventory, {MODULE: adapter}, network, intent, site_names=router.site_names), adapter


def backend():
    config = json.loads((STATE / "fixture.json").read_text())
    assert config == {"port": PORT} and (STATE / "fixture.key").stat().st_size == 32
    with selectors.DefaultSelector() as selector, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as v4, \
            socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as v6:
        v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        for endpoint, address in ((v4, "0.0.0.0"), (v6, "::")):
            endpoint.bind((address, PORT))
            selector.register(endpoint, selectors.EVENT_READ)
        while True:
            for key, _ in selector.select():
                data, address = key.fileobj.recvfrom(128)
                if data == PAYLOAD:
                    key.fileobj.sendto(data, address)


def install(inventory, version):
    with (BASE / f"lifecycle-{version}.tar.gz").open("rb") as handle:
        ticket = inventory.prepare(handle).ticket
    assert inventory.install(ticket).version == version


def closed(lifecycle, adapter):
    assert not adapter.running()
    assert not any(row["enabled"] for row in lifecycle.inventory.installed())
    assert f":{PORT} " not in run("/usr/bin/ss", "-H", "-lntu").stdout.decode()
    for address in ADDRESSES:
        probe(address, "udp", PORT, "closed")


def interrupted():
    lifecycle, adapter = make_lifecycle()
    empty, target = frozenset(), frozenset({MODULE})
    with lifecycle.inventory.runtime_guard():
        lifecycle.journal.write(empty, target)
        adapter.start()
        adapter.verify()
        lifecycle.ingress.apply(lifecycle._plan(target))
        os.kill(os.getpid(), signal.SIGKILL)


def initial():
    assert not STATE.exists() and not (SYSTEMD / UNIT).exists() and not (SYSTEMD / BOOT_UNIT).exists()
    assert run("/usr/sbin/ip", "link", "show", HOST, check=False).returncode != 0
    STATE.mkdir(mode=0o700)
    write_new(STATE / "fixture.json", json.dumps({"port": PORT}).encode())
    write_new(STATE / "fixture.key", os.urandom(32))
    write_new(STATE / "settings.sha", settings_hash().encode())
    write_new(STATE / "baseline.conf", CONFIG.read_bytes())
    add_client()
    path = str(Path(__file__).resolve())
    pythonpath = os.environ["PYTHONPATH"]
    common = f"Environment=PYTHONPATH={pythonpath}\nUMask=0077\n"
    write_new(SYSTEMD / UNIT, ("[Unit]\nDescription=KVN phase5 isolated echo\n[Service]\nType=simple\n"
                              + common + f"ExecStart=/usr/bin/python3 {path} backend\n").encode(), 0o644)
    boot = ("[Unit]\nDescription=KVN phase5 isolated reconcile\nAfter=kvn-v5-gateway.service\n"
            "Wants=kvn-v5-gateway.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=150\n"
            + common + f"ExecStart=/usr/bin/python3 {path} reconcile\n"
            "[Install]\nWantedBy=multi-user.target\n")
    write_new(SYSTEMD / BOOT_UNIT, boot.encode(), 0o644)
    run("/usr/bin/systemctl", "daemon-reload")
    ca, key = make_ca(STATE)
    assert ca == CA
    router = gateway()
    site = next(item for item in router.identities if not item.is_ip)
    router.activate(site, *make_pair(ca, key, site, 501), check=check_nginx, reload=reload_nginx,
                    verify_live=lambda pair: verify_pair(pair, ca_file=ca),
                    verify_restored=lambda: verify_bootstrap(GATEWAY_ROOT / "bootstrap.crt"))
    lifecycle, adapter = make_lifecycle()
    install(lifecycle.inventory, "1.0.0")
    closed(lifecycle, adapter)
    public_core()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conflict:
        conflict.bind(("0.0.0.0", PORT))
        try:
            lifecycle.change(MODULE, True)
        except NetworkConflict as exc:
            assert str(exc) == "publication_port_unavailable"
        else:
            raise AssertionError("Занятый порт принят")
    assert lifecycle.journal.read() is None

    def fail_once(plan):
        if plan.active:
            public_core()
            raise OSError("Контрольный отказ после запуска")

    failed, _ = make_lifecycle(fail_once)
    try:
        failed.change(MODULE, True)
    except LifecycleError as exc:
        assert exc.code == "network_apply_rolled_back"
    else:
        raise AssertionError("Контрольный отказ не вызвал rollback")
    closed(lifecycle, adapter)
    public_core()
    assert lifecycle.journal.read() is None
    print("systemd/UDP: конфликт до apply и настоящий rollback после контрольного отказа: OK", flush=True)

    result = subprocess.run([sys.executable, path, "interrupt"], timeout=100)
    assert result.returncode == -signal.SIGKILL and lifecycle.journal.read() is not None and adapter.running()
    verify_udp()
    assert not lifecycle.reconcile().active
    closed(lifecycle, adapter)
    public_core()
    print("SIGKILL после запуска backend: reconcile убрал неподтверждённый сервис: OK", flush=True)

    lifecycle.change(MODULE, True)
    verify_udp()
    lifecycle.change(MODULE, False)
    closed(lifecycle, adapter)
    install(lifecycle.inventory, "1.0.1")
    lifecycle.reconcile()
    closed(lifecycle, adapter)
    assert settings_hash() == (STATE / "settings.sha").read_text()
    run("/usr/bin/systemctl", "enable", BOOT_UNIT)
    print("Отключение, обновление подписанного пакета и reconcile без возврата порта: OK", flush=True)


def reconcile():
    if run("/usr/sbin/ip", "link", "show", HOST, check=False).returncode:
        add_client()
    lifecycle, _ = make_lifecycle()
    lifecycle.reconcile()


def after_reboot():
    deadline = time.monotonic() + 150
    while run("/usr/bin/systemctl", "is-active", BOOT_UNIT, check=False).stdout != b"active\n":
        if time.monotonic() >= deadline:
            raise AssertionError("Автоматическое восстановление после boot не подтвердилось")
        time.sleep(2)
    lifecycle, adapter = make_lifecycle()
    assert run("/usr/bin/systemctl", "is-active", BOOT_UNIT).stdout == b"active\n"
    closed(lifecycle, adapter)
    public_core()
    assert lifecycle.inventory.installed()[0]["version"] == "1.0.1"
    assert settings_hash() == (STATE / "settings.sha").read_text()
    lifecycle.change(MODULE, True)
    verify_udp()
    assert settings_hash() == (STATE / "settings.sha").read_text()
    lifecycle.change(MODULE, False)
    closed(lifecycle, adapter)
    public_core()
    print("После reboot: выключенный порт закрыт, HTTPS сохранён, enable вернул доступ с теми же настройками и ключом.", flush=True)
    run("/usr/bin/systemctl", "disable", "--now", BOOT_UNIT)
    (SYSTEMD / BOOT_UNIT).unlink()
    (SYSTEMD / UNIT).unlink()
    run("/usr/bin/systemctl", "daemon-reload")
    remove_client()
    health = lambda: verify_bootstrap(GATEWAY_ROOT / "bootstrap.crt")
    publish_gateway(CONFIG, (STATE / "baseline.conf").read_bytes(), check=check_nginx, reload=reload_nginx,
                    verify_live=health, verify_restored=health)


if __name__ == "__main__":
    check_identity()
    {"backend": backend, "initial": initial, "interrupt": interrupted,
     "reconcile": reconcile, "after-reboot": after_reboot}[sys.argv[1]]()
