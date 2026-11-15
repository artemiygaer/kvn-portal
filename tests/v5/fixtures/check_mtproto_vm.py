"""Проверка подписанных Telemt и MTG только на выделенной Debian VM."""

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import ssl
import subprocess
import sys

from check_mtproto_client import cover_https, fake_tls
from check_network_gateway import request
from check_network_nft import ADDRESSES, HOST, NS, add_client, remove_client, run
from check_tls_gateway import make_ca, make_pair
from v5.core.lifecycle.assembly import HostContext
from v5.core.lifecycle.controller import Lifecycle
from v5.core.lifecycle.journal import IntentJournal, PENDING_NAME
from v5.core.network.runtime import NetworkRuntime
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.signature import load_publisher
from v5.core.private_files import read_private, write_private
from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, publish_gateway
from v5.modules.mtg import settings as mtg
from v5.modules.mtg.adapter import mtg_adapter
from v5.modules.mtproto_common.profiles import Exposure, PORTS, Secret
from v5.modules.mtproto_common.runtime import MODULES, inspect_container
from v5.modules.telemt import settings as telemt
from v5.modules.telemt.adapter import telemt_adapter

BASE = Path("/var/tmp/kvn-v5-phase9")
FIXTURE = BASE / "fixture"
CA = FIXTURE / "ca.pem"
CONFIG = GATEWAY_ROOT / "nginx.conf"
BOOT = Path("/proc/sys/kernel/random/boot_id")
UNIT = Path("/etc/systemd/system/kvn-v5-phase9-reconcile.service")
ADDRESS = ADDRESSES[0]
VERSION = {"telemt": "3.5.17", "mtg": "2.3.0"}


def core():
    names, ipv6 = registry()
    gateway = GatewayController(CONFIG, CertificateStore(GATEWAY_ROOT / "certs", ca_file=CA), names, ipv6=ipv6)
    packages = PackageRegistry(FIXTURE / "registry", load_publisher(BASE / "publisher.json"))
    context = HostContext(packages, gateway)
    adapters = {"telemt": telemt_adapter(context), "mtg": mtg_adapter(context)}
    return Lifecycle(packages, adapters, NetworkRuntime(gateway),
                     IntentJournal(packages.root / PENDING_NAME), site_names=gateway.site_names), gateway


@contextmanager
def isolated_network():
    assert run("/usr/sbin/ip", "link", "show", HOST, check=False).returncode
    assert NS not in run("/usr/sbin/ip", "netns", "list").stdout.decode().split()
    try:
        add_client()
        yield
    finally:
        remove_client()


def closed(port):
    code = ("import errno,socket,sys; s=socket.socket(); s.settimeout(3); "
            "r=s.connect_ex((sys.argv[1],int(sys.argv[2]))); s.close(); "
            "sys.exit(0 if r==errno.ECONNREFUSED else 1)")
    run("/usr/sbin/ip", "netns", "exec", NS, sys.executable, "-c", code, ADDRESS, str(port))


def browser(names):
    tls = ssl.create_default_context(cafile=CA)
    tls.set_alpn_protocols(["http/1.1"])
    for name in names:
        assert request(tls, ADDRESS, 443, name, name)[0] == 200
        assert request(tls, ADDRESS, 8443, name, f"{name}:8443", "/login")[0] == 200


def profile(module, settings, *, direct):
    if module == "telemt":
        return telemt.client_profile(settings, "reader", ADDRESS, active=True, direct=direct)
    return mtg.client_profile(settings, ADDRESS, active=True, allowed=True, direct=direct)


def initial():
    assert not FIXTURE.exists() and not UNIT.exists()
    assert all(not (MODULES / module).exists() for module in VERSION)
    FIXTURE.mkdir(mode=0o700)
    write_private(FIXTURE / "before.nginx", CONFIG.read_bytes())
    ca, key = make_ca(FIXTURE)
    lifecycle, gateway = core()
    assert not gateway.active()
    names = tuple(item for item in gateway.identities if not item.is_ip)
    assert len(names) >= 2
    one, two = names[:2]
    bootstrap = GATEWAY_ROOT / "bootstrap.crt"
    with isolated_network():
        for index, name in enumerate((one, two), 901):
            gateway.activate(name, *make_pair(ca, key, name, index), check=check_nginx, reload=reload_nginx,
                             verify_live=lambda pair: verify_pair(pair, ca_file=ca),
                             verify_restored=lambda: verify_bootstrap(bootstrap))
        browser((one.name, two.name))
        for module, version in VERSION.items():
            with (BASE / f"kvn-module-{module}-{version}.tar.gz").open("rb") as stream:
                ticket = lifecycle.inventory.prepare(stream).ticket
            lifecycle.inventory.install(ticket)
            assert not lifecycle.adapters[module].running()
            assert inspect_container(lifecycle.adapters[module].docker, module) is None
            closed(PORTS[module])
        settings = {
            "telemt": telemt.Settings(Exposure(one.name, own_site=True, direct_ip="0.0.0.0"),
                                      (telemt.Account.create("reader"),)),
            "mtg": mtg.Settings(Exposure(two.name, own_site=True, direct_ip="0.0.0.0"), Secret.create()),
        }
        for module in VERSION:
            lifecycle.adapters[module].configure(settings[module])
        for module in VERSION:
            plan = lifecycle.change(module, True)
            assert module in plan.active
        assert {item.owner for item in gateway.network_routes().routes} == set(VERSION)
        for module in VERSION:
            for direct in (False, True):
                item = profile(module, settings[module], direct=direct)
                fake_tls(item)
                fake_tls(replace(item, secret=Secret.create()), expected=False)
                cover_https(item, ca=str(CA))
            print(f"Debian {module}: FakeTLS/resPQ и локальная HTTPS-маскировка через 443 и прямой порт.")
        before = {module: hashlib.sha256((MODULES / module / "settings.json").read_bytes()).hexdigest()
                  for module in VERSION}
        lifecycle.change("mtg", False)
        closed(PORTS["mtg"])
        assert tuple(item.owner for item in gateway.network_routes().routes) == ("telemt",)
        fake_tls(profile("telemt", settings["telemt"], direct=False))
        assert hashlib.sha256((MODULES / "telemt" / "settings.json").read_bytes()).hexdigest() == before["telemt"]
        lifecycle.change("telemt", False)
        for module in VERSION:
            closed(PORTS[module])
            assert hashlib.sha256((MODULES / module / "settings.json").read_bytes()).hexdigest() == before[module]
        assert not gateway.network_routes().routes
        browser((one.name, two.name))
        print("Debian: отключение MTG не затронуло Telemt; оба порта закрыты, SNI удалены, HTTPS доступен.")
    write_private(FIXTURE / "boot-before", BOOT.read_bytes())
    UNIT.write_text("[Unit]\nDescription=KVN v5 phase 9 isolated reconciliation\n"
                    "Wants=kvn-v5-gateway.service docker.service\nAfter=kvn-v5-gateway.service docker.service\n"
                    "[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironment=PYTHONPATH=/usr/local/lib/kvn-v5\n"
                    f"ExecStart=/usr/bin/python3 {__file__} boot\n[Install]\nWantedBy=multi-user.target\n")
    run("/usr/bin/systemctl", "enable", UNIT.name)


def after_reboot():
    assert BOOT.read_bytes() != read_private(FIXTURE / "boot-before", 64)
    assert BOOT.read_bytes() == read_private(FIXTURE / "boot-reconciled", 64)
    lifecycle, gateway = core()
    with isolated_network():
        assert not any(row["enabled"] for row in lifecycle.inventory.installed())
        assert not gateway.network_routes().routes
        for module in VERSION:
            assert not lifecycle.adapters[module].running()
            closed(PORTS[module])
        browser(gateway.site_names[:2])
    print("Debian: после reboot оба модуля выключены, их порты и SNI закрыты, HTTPS доступен.")
    run("/usr/bin/systemctl", "disable", UNIT.name)
    UNIT.unlink()
    run("/usr/bin/systemctl", "daemon-reload")
    bootstrap = GATEWAY_ROOT / "bootstrap.crt"
    publish_gateway(CONFIG, read_private(FIXTURE / "before.nginx", 512 * 1024),
                    check=check_nginx, reload=reload_nginx, verify_live=lambda: verify_bootstrap(bootstrap),
                    verify_restored=lambda: None)
    for module in VERSION:
        (MODULES / module).rename(FIXTURE / f"{module}-state")


def archive_failed_fixture():
    """Сохранить неудачный изолированный прогон и вернуть учебный gateway."""
    assert FIXTURE.is_dir() and not UNIT.exists()
    archived = next(BASE / f"failed-r{index}" for index in range(1, 100)
                    if not (BASE / f"failed-r{index}").exists())
    client = Path("/var/tmp/kvn-v5-mtproto-client")
    assert not archived.exists() and client.is_dir()
    subprocess.run(("/usr/bin/systemctl", "stop", "kvn-v5-module-mtg.service", "kvn-v5-module-telemt.service"),
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
    bootstrap = GATEWAY_ROOT / "bootstrap.crt"
    publish_gateway(CONFIG, read_private(FIXTURE / "before.nginx", 512 * 1024),
                    check=check_nginx, reload=reload_nginx, verify_live=lambda: verify_bootstrap(bootstrap),
                    verify_restored=lambda: None)
    for module in VERSION:
        source = MODULES / module
        if source.exists():
            source.rename(FIXTURE / f"{module}-state")
    client.rename(FIXTURE / "client")
    FIXTURE.rename(archived)
    print("Debian: неудачный тестовый fixture сохранён; gateway восстановлен.")


def diagnose_mtg():
    lifecycle, gateway = core()
    assert lifecycle.adapters["mtg"].running()
    settings = mtg.Settings.load(MODULES / "mtg" / "settings.json")
    with isolated_network():
        failures = 0
        for direct in (True,):
            item = profile("mtg", settings, direct=direct)
            cover_https(item, ca=str(CA))
            print(f"MTG {'прямой порт' if direct else '443'}: HTTPS маскировка доступна.", flush=True)
            try:
                fake_tls(item)
                print(f"MTG {'прямой порт' if direct else '443'}: FakeTLS/resPQ подтверждены.", flush=True)
            except AssertionError as exc:
                failures += 1
                print(str(exc), flush=True)
        logs = subprocess.run(("/usr/bin/docker", "logs", "--tail", "100", "kvn-v5-mtg"),
                              capture_output=True, check=False, timeout=60)
        data = (logs.stdout + logs.stderr).lower()
        for term in (b"timeout", b"refused", b"unreachable", b"handshake", b"error", b"replay"):
            print(f"MTG журнал: {term.decode()}={data.count(term)}", flush=True)
        if failures:
            raise AssertionError("MTG: диагностические проверки FakeTLS не пройдены")


def doctor_mtg():
    result = subprocess.run(("/usr/bin/docker", "exec", "kvn-v5-mtg", "/mtg", "doctor",
                             "/etc/kvn-mtproto/config.toml"), capture_output=True, check=False, timeout=240)
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    for number in (1, 2, 3, 4, 5):
        rows = [row for row in output.splitlines() if f"DC {number}" in row]
        print(f"MTG doctor DC {number}: " + ("OK" if any("✅" in row for row in rows)
                                             else "ошибка или нет результата"), flush=True)
    print(f"MTG doctor: код {result.returncode}", flush=True)


def diagnose_mtg_ipv4():
    lifecycle, _ = core()
    lifecycle.change("mtg", False)
    lifecycle.adapters["mtg"].render = lambda settings, cover: mtg.render_server(settings, cover).replace(
        b"debug = false\n", b'debug = false\nprefer-ip = "prefer-ipv4"\n', 1)
    lifecycle.change("mtg", True)
    diagnose_mtg()


if __name__ == "__main__":
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    action = sys.argv[1]
    if action == "boot":
        assert not core()[0].reconcile().active
        write_private(FIXTURE / "boot-reconciled", BOOT.read_bytes())
    elif action == "after-reboot":
        after_reboot()
    elif action == "archive-failed":
        archive_failed_fixture()
    elif action == "diagnose-mtg":
        diagnose_mtg()
    elif action == "doctor-mtg":
        doctor_mtg()
    elif action == "diagnose-mtg-ipv4":
        diagnose_mtg_ipv4()
    else:
        assert action == "initial"
        initial()
