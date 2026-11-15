"""Живые kernel handshake, данные, syncconf и отключение на отдельной Debian VM."""

from dataclasses import asdict, replace
from hashlib import sha256
from ipaddress import IPv4Interface
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
from threading import Thread
from tempfile import TemporaryDirectory, mkdtemp

from check_network_nft import ADDRESSES, HOST, NS, add_client, remove_client
from v5.core.lifecycle.assembly import HostContext, host_gateway
from v5.core.lifecycle.controller import Lifecycle, LifecycleError
from v5.core.lifecycle.journal import IntentJournal, PENDING_NAME
from v5.core.network.runtime import NetworkRuntime
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.signature import load_publisher
from v5.core.private_files import read_private, write_private
from v5.core.tls.probe import verify_bootstrap
from v5.core.tls.queue import GATEWAY_ROOT
from v5.modules.amneziawg.profile import Profile
from v5.modules.host_tunnel.adapter import TunnelAdapter
from v5.modules.host_tunnel.config import AWG, WG, Peer, Settings
from v5.modules.host_tunnel.platform import capability, tools
from v5.modules.host_tunnel.state import MODULES_ROOT, State


BASE = Path('/var/tmp/kvn-v5-phase7')
STATE = BASE / 'fixture'
SPECS = (WG, AWG)
PAYLOAD = b'kvn-phase7-handshake-traffic'
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
BOOT_UNIT = Path('/etc/systemd/system/kvn-v5-phase7-reconcile.service')
BOOT_UNIT_TEXT = f'''[Unit]
Description=KVN v5 phase 7 reconciliation fixture
Wants=kvn-v5-gateway.service
After=kvn-v5-gateway.service

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PYTHONPATH=/usr/local/lib/kvn-v5
ExecStart=/usr/bin/python3 {BASE}/check_tunnel_vm.py reconcile
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
'''


def call(*argv, data=None, check=True, timeout=55):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f'Ошибка учебной команды {Path(argv[0]).name}: {result.returncode}')
    return result


def capture(*argv, data=None):
    return call(*argv, data=data).stdout.decode('ascii').strip()


def client(*argv, data=None, check=True, timeout=55):
    return call('/usr/sbin/ip', 'netns', 'exec', NS, *argv, data=data, check=check, timeout=timeout)


def stored():
    packs = PackageRegistry(STATE / 'packages', load_publisher(BASE / 'publisher.json'))
    gateway = host_gateway()
    adapters = {spec.module: TunnelAdapter(HostContext(packs, gateway), spec) for spec in SPECS}
    lifecycle = Lifecycle(packs, adapters, NetworkRuntime(gateway), IntentJournal(packs.root / PENDING_NAME),
                          site_names=gateway.site_names)
    return packs, adapters, lifecycle


def material(spec):
    tool = tools(spec)
    server_key, client_key = capture(tool, 'genkey'), capture(tool, 'genkey')
    preshared = capture(tool, 'genpsk')
    address = IPv4Interface(spec.address)
    peer = Peer(capture(tool, 'pubkey', data=(client_key + '\n').encode()), str(address.ip + 1), preshared)
    server_public = capture(tool, 'pubkey', data=(server_key + '\n').encode())
    state = State(spec, Settings(spec.address, server_key, (peer,)), Profile() if spec == AWG else None)
    return state, {'private_key': client_key, 'server_key': server_public, 'endpoint': ADDRESSES[0], 'active': True}


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        if packet == PAYLOAD:
            sock.sendto(packet, self.client_address)


def traffic(state, credentials, *, expected=True):
    spec = state.spec
    interface = 'c' + spec.interface
    address = str(IPv4Interface(state.settings.address).ip)
    peer = state.settings.peers[0]
    executable = tools(spec)
    profile = state.client(peer, **credentials)
    assert profile
    raw = b'\n'.join(line for line in profile.splitlines() if not line.startswith((b'Address = ', b'MTU = '))) + b'\n'
    client('/usr/sbin/ip', 'link', 'add', interface, 'type', spec.link_type)
    try:
        client(executable, 'setconf', interface, '/dev/stdin', data=raw)
        client('/usr/sbin/ip', 'address', 'add', f'{peer.address}/32', 'dev', interface)
        client('/usr/sbin/ip', 'link', 'set', interface, 'mtu', str(state.settings.mtu), 'up')
        client('/usr/sbin/ip', 'route', 'add', f'{address}/32', 'dev', interface)
        if expected:
            with socketserver.UDPServer((address, 28080), Echo) as server:
                worker = Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    client(sys.executable, __file__, 'client', address, 'up', timeout=45)
                    handshakes = client(executable, 'show', interface, 'latest-handshakes').stdout.split()
                    assert len(handshakes) == 2 and int(handshakes[1]) > 0
                finally:
                    server.shutdown()
                    worker.join(5)
        else:
            client(sys.executable, __file__, 'client', address, 'down', timeout=30)
    finally:
        client('/usr/sbin/ip', 'link', 'delete', interface, check=False)


def client_ping(address, expected):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(2 if expected == 'up' else 3)
        channel.connect((address, 28080))
        for _ in range(8 if expected == 'up' else 1):
            channel.send(PAYLOAD)
            try:
                reply = channel.recv(256)
            except (TimeoutError, ConnectionRefusedError):
                continue
            assert expected == 'up' and reply == PAYLOAD
            return
    assert expected == 'down', 'Не получен ответ через туннель'


def closed(adapter):
    assert not adapter.running() and adapter.runtime.link() is None
    assert not call('/usr/bin/ss', '-Hlnu', 'sport', '=', f':{adapter.spec.port}').stdout
    adapter.runtime.firewall.verify_compiled(adapter.runtime.firewall.compile(None))


def persisted_hash():
    return sha256(b''.join(read_private(MODULES_ROOT / spec.module / 'settings.json', 262144)
                           for spec in SPECS)).hexdigest()


def missing_dependency(empty):
    # Только отдельный mount namespace. Общее ядро и рабочие mounts не изменяются.
    assert Path('/proc/self/ns/mnt').stat().st_ino != Path('/proc/1/ns/mnt').stat().st_ino
    directory = Path(empty).resolve()
    assert directory.parent == STATE.resolve() and not tuple(directory.iterdir())
    for path in ('/lib/modules', '/sys/module'):
        call('/usr/bin/mount', '--bind', str(directory), path)
    packs, adapters, lifecycle = stored()
    assert capability(AWG).issue == 'amneziawg_kernel_headers_missing'
    try:
        lifecycle.change(AWG.module, True)
    except LifecycleError as exc:
        assert exc.code == 'amneziawg_kernel_headers_missing'
    else:
        raise AssertionError('Модуль без видимого ядра принят')
    assert not any(row['enabled'] for row in packs.installed())
    assert adapters[AWG.module].runtime.link() is None and lifecycle.journal.read() is None


def initial():
    assert not STATE.exists() and all(not (MODULES_ROOT / spec.module).exists() for spec in SPECS)
    assert call('/usr/sbin/ip', 'link', 'show', 'dev', HOST, check=False).returncode
    STATE.mkdir(mode=0o700)
    packs, adapters, lifecycle = stored()
    states, keys = {}, {}
    try:
        add_client()
        for spec in SPECS:
            ready = capability(spec)
            print(f'{spec.module}: {json.dumps(asdict(ready))}', flush=True)
            assert ready.issue is None and (spec == WG or '3.1' in ready.profiles)
            with (BASE / f'kvn-module-{spec.module}-1.0.0.tar.gz').open('rb') as handle:
                packs.install(packs.prepare(handle).ticket)
            closed(adapters[spec.module])
            state, creds = material(spec)
            adapters[spec.module].configure(state)
            states[spec.module], keys[spec.module] = state, creds

        wg, awg = (adapters[spec.module] for spec in SPECS)
        with TemporaryDirectory(dir=STATE, prefix='hidden-deps-') as folder:
            call('/usr/bin/unshare', '--mount', '--propagation', 'private', sys.executable, __file__,
                 'missing-dependency', folder, timeout=130)
        verify_bootstrap(GATEWAY_ROOT / 'bootstrap.crt')
        print('Нет модуля и заголовков: причина видна, ingress не изменён, портал доступен.', flush=True)
        lifecycle.change(WG.module, True)
        closed(awg)
        traffic(states[WG.module], keys[WG.module])
        print('WireGuard handshake и UDP внутри туннеля прошли, awg0 не поднялся.', flush=True)

        lifecycle.change(AWG.module, True)
        traffic(states[AWG.module], keys[AWG.module])
        print('AmneziaWG legacy handshake и UDP внутри туннеля прошли.', flush=True)
        for adapter in (wg, awg):
            spec = adapter.spec
            original = states[spec.module]
            before = adapter.runtime.verify(original)
            new_private = capture(tools(spec), 'genkey')
            extra = Peer(capture(tools(spec), 'pubkey', data=(new_private + '\n').encode()),
                         str(IPv4Interface(spec.address).ip + 2))
            updated = replace(original, settings=replace(original.settings, peers=(*original.settings.peers, extra)))
            adapter.configure(updated)
            assert adapter.runtime.verify(updated).index == before.index
            traffic(updated, keys[spec.module])
            states[spec.module] = updated
        print('WG и AWG добавили peer через syncconf без смены ifindex; прежние профили работают.', flush=True)

        lifecycle.change(WG.module, False)
        closed(wg)
        traffic(states[WG.module], keys[WG.module], expected=False)
        traffic(states[AWG.module], keys[AWG.module])
        lifecycle.change(AWG.module, False)
        closed(awg)
        traffic(states[AWG.module], keys[AWG.module], expected=False)
        modern = replace(states[AWG.module], profile=Profile.modern(capture(tools(AWG), 'genpsk')))
        awg.configure(modern)
        lifecycle.change(AWG.module, True)
        closed(wg)
        traffic(modern, keys[AWG.module])
        lifecycle.change(AWG.module, False)
        closed(awg)
        traffic(modern, keys[AWG.module], expected=False)
        print('AWG 3.1 handshake/UDP прошли; disable закрывает свой порт и не затрагивает другой туннель.', flush=True)
        write_private(STATE / 'clients.json', json.dumps(keys).encode())
        write_private(STATE / 'settings.sha', persisted_hash().encode())
        with BOOT_UNIT.open('x', encoding='ascii') as handle:
            handle.write(BOOT_UNIT_TEXT)
        call('/usr/bin/systemctl', 'daemon-reload')
        call('/usr/bin/systemctl', 'enable', BOOT_UNIT.name)
    finally:
        remove_client()


def after_reboot():
    packs, adapters, lifecycle = stored()
    assert call('/usr/bin/systemctl', 'is-active', BOOT_UNIT.name).stdout.strip() == b'active'
    assert read_private(STATE / 'reconciled-boot', 128) == BOOT_ID.read_bytes()
    assert not any(row['enabled'] for row in packs.installed())
    assert read_private(STATE / 'settings.sha', 128).decode() == persisted_hash()
    keys = json.loads(read_private(STATE / 'clients.json', 4096))
    add_client()
    try:
        for spec in SPECS:
            adapter = adapters[spec.module]
            closed(adapter)
            state = adapter.settings()
            lifecycle.change(spec.module, True)
            traffic(state, keys[spec.module])
            lifecycle.change(spec.module, False)
            closed(adapter)
        assert read_private(STATE / 'settings.sha', 128).decode() == persisted_hash()
        verify_bootstrap(GATEWAY_ROOT / 'bootstrap.crt')
        print('После reboot оба выключены; enable возвращает те же ключи и адреса, реальные клиенты подключились.',
              flush=True)
    finally:
        remove_client()
        if BOOT_UNIT.read_text(encoding='ascii') == BOOT_UNIT_TEXT:
            call('/usr/bin/systemctl', 'disable', '--now', BOOT_UNIT.name)
            BOOT_UNIT.unlink()
            call('/usr/bin/systemctl', 'daemon-reload')


def reconcile():
    packs, adapters, lifecycle = stored()
    assert not any(row['enabled'] for row in packs.installed())
    assert not lifecycle.reconcile().active
    for adapter in adapters.values():
        closed(adapter)
    write_private(STATE / 'reconciled-boot', BOOT_ID.read_bytes())


def preserve_failed_fixture():
    # Только ручной повтор после завершившегося неуспехом первоначального прогона.
    assert STATE.is_dir() and not (STATE / 'settings.sha').exists() and not BOOT_UNIT.exists()
    assert call('/usr/sbin/ip', 'link', 'show', 'dev', HOST, check=False).returncode
    packs, adapters, lifecycle = stored()
    assert not any(row['enabled'] for row in packs.installed()) and lifecycle.journal.read() is None
    for adapter in adapters.values():
        assert not adapter.running() and adapter.runtime.link() is None
        adapter.runtime.stop()  # Разрешено убрать только таблицу со своей подтверждённой меткой.
    evidence = Path(mkdtemp(prefix='failed-fixture-', dir=BASE))
    for spec in SPECS:
        root = MODULES_ROOT / spec.module
        if root.exists():
            root.rename(evidence / spec.module)
    STATE.rename(evidence / 'fixture')
    print('Данные неудачной учебной попытки сохранены отдельно, слушателей нет.', flush=True)


if __name__ == '__main__':
    assert os.geteuid() == 0 and Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    if len(sys.argv) == 4 and sys.argv[1] == 'client':
        client_ping(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == 'missing-dependency':
        missing_dependency(sys.argv[2])
    elif sys.argv[1:] == ['reconcile']:
        reconcile()
    elif sys.argv[1:] == ['preserve-failed']:
        preserve_failed_fixture()
    elif sys.argv[1:] == ['after-reboot']:
        after_reboot()
    elif not sys.argv[1:]:
        initial()
    else:
        raise ValueError('Неизвестный режим теста')
