"""Подписанный Xray на изолированном Debian: systemd, порт, сайт и откат."""

import hashlib
import os
from pathlib import Path
import socket
import ssl
import sys
from tempfile import TemporaryDirectory

from check_network_gateway import request
from check_network_nft import ADDRESSES, HOST, NS, add_client, remove_client, run
from check_tls_gateway import make_ca, make_pair
from v5.core.lifecycle.assembly import HostContext
from v5.core.lifecycle.controller import Lifecycle, LifecycleError
from v5.core.lifecycle.journal import IntentJournal, PENDING_NAME
from v5.core.network.runtime import NetworkRuntime
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.signature import load_publisher
from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, publish_gateway
from v5.modules.xray.adapter import XrayAdapter
from v5.modules.xray.config import Settings
from v5.modules.xray.credentials import Account
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles, Reality
from v5.modules.xray.runtime import MODULE_ROOT, inspect_container

BASE = Path('/var/tmp/kvn-v5-phase6')
SITE = 'portal.example'
CONFIG = GATEWAY_ROOT / 'nginx.conf'
UNIT = 'kvn-v5-module-xray.service'


def browser(ca):
    tls = ssl.create_default_context(cafile=ca)
    tls.set_alpn_protocols(['http/1.1'])
    for address in ADDRESSES:
        assert request(tls, address, 443, SITE, SITE)[0] == 200
        assert request(tls, address, 8443, SITE, f'{SITE}:8443', '/login')[0] == 200


def remote(ca, direct):
    run('/usr/sbin/ip', 'netns', 'exec', NS, sys.executable, __file__, 'client', str(ca), str(int(direct)))


def client(ca, direct):
    browser(ca)
    tls = ssl.create_default_context(cafile=ca)
    for address in ADDRESSES:
        if direct:
            with socket.create_connection((address, 2443), timeout=3) as plain:
                with tls.wrap_socket(plain, server_hostname=SITE) as encrypted:
                    assert encrypted.version().startswith('TLSv1.')
        for port in ((2444, 2445) if direct else (2443, 2444, 2445)):
            try:
                connection = socket.create_connection((address, port), timeout=2)
            except OSError:
                continue
            connection.close()
            raise AssertionError(f'Лишний внешний порт {address}:{port}')


def digest_state():
    return tuple(hashlib.sha256((MODULE_ROOT / name).read_bytes()).digest()
                 for name in ('settings.json', 'reality.json'))


def package_ticket(packages, version):
    with (BASE / f'kvn-module-xray-{version}.tar.gz').open('rb') as stream:
        return packages.prepare(stream).ticket


def check():
    assert not MODULE_ROOT.exists(), 'Тест не изменяет существующее состояние Xray'
    assert run('/usr/sbin/ip', 'link', 'show', HOST, check=False).returncode
    assert run('/usr/bin/systemctl', 'is-active', UNIT, check=False).returncode
    before = CONFIG.read_bytes()
    bootstrap = GATEWAY_ROOT / 'bootstrap.crt'
    verify_bootstrap(bootstrap)
    names, ipv6 = registry()
    site = next(name for name in names if name.name == SITE)
    with TemporaryDirectory(dir=BASE, prefix='run-') as directory:
        root = Path(directory)
        packages = PackageRegistry(root / 'registry', load_publisher(BASE / 'publisher.json'))
        ca, key = make_ca(root)
        gateway = GatewayController(CONFIG, CertificateStore(GATEWAY_ROOT / 'certs', ca_file=ca), names, ipv6=ipv6)
        assert not gateway.active(), 'Для теста нужен bootstrap без активной пары'
        adapter = XrayAdapter(HostContext(packages, gateway))
        lifecycle = Lifecycle(packages, {'xray': adapter}, NetworkRuntime(gateway),
                              IntentJournal(packages.root / PENDING_NAME), site_names=gateway.site_names)
        health = lambda: verify_bootstrap(bootstrap)
        try:
            add_client()
            gateway.activate(site, *make_pair(ca, key, site, 601), check=check_nginx, reload=reload_nginx,
                             verify_live=lambda pair: verify_pair(pair, ca_file=ca), verify_restored=health)
            remote(ca, False)
            assert packages.install(package_ticket(packages, '26.10.31')).version == '26.10.31'
            assert not adapter.running() and inspect_container(adapter.docker) is None and not MODULE_ROOT.exists()
            print('Проверенный offline-пакет установлен без запуска, ingress и рабочей конфигурации.', flush=True)

            settings = Settings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, SITE),
                                          Profile(Kind.REALITY_TCP, Exposure.SHARED, SITE, Reality.SELF_STEAL))),
                                (Account('lab-client', 'f8b7598c-3411-4c0c-9824-4c5bc2af0f19',
                                         (Kind.TLS, Kind.REALITY_TCP)),))
            adapter.configure(settings)
            active = lifecycle.change('xray', True)
            assert len(active.routes) == 1 and active.routes[0].route.self_steal
            assert {(item.publication.public.ip, item.publication.public.port) for item in active.publications} == {
                ('0.0.0.0', 2443), ('::', 2443),
            }
            remote(ca, True)
            first = inspect_container(adapter.docker)['id']
            state = digest_state()
            print('Docker/systemd: TLS:2443 по IPv4/IPv6 и Reality:443, сайт и админка с доверенным HTTPS работают.',
                  flush=True)

            original_verify = adapter.verify
            failures = []

            def fail_candidate():
                original_verify()
                if packages.installed()[0]['version'] == '26.10.32':
                    failures.append(inspect_container(adapter.docker)['id'])
                    raise LifecycleError('fixture_health_failed')

            adapter.verify = fail_candidate
            try:
                lifecycle.upgrade('xray', package_ticket(packages, '26.10.32'))
            except LifecycleError as exc:
                assert exc.code == 'module_upgrade_rolled_back', exc.code
            else:
                raise AssertionError('Кандидат с неподтверждённым health принят')
            assert len(failures) == 1 and failures[0] != first
            assert inspect_container(adapter.docker)['id'] not in (first, failures[0])
            assert packages.pending_upgrade() is None and packages.installed()[0]['enabled']
            assert packages.installed()[0]['version'] == '26.10.31' and digest_state() == state
            remote(ca, True)
            print('Ошибка health нового контейнера вернула старый подписанный пакет, настройки и ключи сохранены.', flush=True)

            assert not lifecycle.change('xray', False).active
            assert not adapter.running() and inspect_container(adapter.docker) is None
            assert not gateway.network_routes().routes and digest_state() == state
            remote(ca, False)
            print('После отключения прямые порты недоступны, маршрута модуля нет, сайт и админка работают.', flush=True)
        finally:
            try:
                if adapter.running():
                    adapter.stop()
                publish_gateway(CONFIG, before, check=check_nginx, reload=reload_nginx,
                                verify_live=health, verify_restored=lambda: None)
            finally:
                remove_client()
                if MODULE_ROOT.is_dir():
                    # Каталога не было до fixture. Удаляется только синтетический конфиг внутри TemporaryDirectory.
                    MODULE_ROOT.rename(root / 'module-fixture')


if __name__ == '__main__':
    assert os.geteuid() == 0 and Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    if len(sys.argv) == 4 and sys.argv[1] == 'client':
        client(sys.argv[2], sys.argv[3] == '1')
    else:
        check()
