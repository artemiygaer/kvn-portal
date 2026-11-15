"""Проверить реальный IPv4-трафик через туннель и его отдельный NAT в новых namespaces."""

import os
import json
from pathlib import Path
import select
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

from v5.core.lifecycle.controller import LifecycleError
from v5.core.migration.material import MigrationMaterial
from v5.core.migration.repository import MigrationRepository
from v5.core.migration.service import MigrationService
from v5.core.migration.target import MigrationTarget
from v5.core.users.store import UserStore
from v5.modules.host_tunnel.config import AWG, WG
from v5.modules.host_tunnel.credentials import allocate
from v5.modules.host_tunnel.platform import tools
from v5.modules.host_tunnel.runtime import TunnelRuntime
from v5.modules.host_tunnel.users import client_file, restore_seed, set_user


IP = "/usr/sbin/ip"
CLIENT = "kvn-v5-client"
ORIGIN = "kvn-v5-origin"
SERVER_OUTER = "198.51.100.1"
CLIENT_OUTER = "198.51.100.2"
SERVER_EGRESS = "203.0.113.1"
ORIGIN_IP = "203.0.113.2"
DEST = 28080
PAYLOAD = b"kvn-v5-egress"


def run(*argv, data=None):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name}: exit={result.returncode}")
    return result.stdout


def inside(ns, *argv, data=None):
    return run(IP, "netns", "exec", ns, *argv, data=data)


def make_network(ns, host, peer, host_address, peer_address):
    run(IP, "netns", "add", ns)
    run(IP, "link", "add", host, "type", "veth", "peer", "name", peer)
    run(IP, "link", "set", peer, "netns", ns)
    run(IP, "address", "add", host_address + "/24", "dev", host)
    run(IP, "link", "set", host, "up")
    inside(ns, IP, "address", "add", peer_address + "/24", "dev", peer)
    inside(ns, IP, "link", "set", peer, "up")
    inside(ns, IP, "link", "set", "lo", "up")


def source_echo():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.bind((ORIGIN_IP, DEST))
        channel.settimeout(30)
        print("ready", flush=True)
        data, peer = channel.recvfrom(256)
        assert data == PAYLOAD
        channel.sendto(peer[0].encode("ascii"), peer)


def client_echo():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(10)
        channel.connect((ORIGIN_IP, DEST))
        channel.send(PAYLOAD)
        assert channel.recv(64) == SERVER_EGRESS.encode("ascii"), "Трафик не прошёл ожидаемый IPv4 NAT"


def verify_path():
    python = (sys.executable, str(Path(__file__).resolve()))
    with subprocess.Popen((IP, "netns", "exec", ORIGIN, *python, "echo"), stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as server:
        try:
            ready, _, _ = select.select([server.stdout], [], [], 10)
            assert ready and server.stdout.readline() == b"ready\n"
            inside(CLIENT, *python, "send")
            assert server.wait(timeout=10) == 0
        finally:
            if server.poll() is None:
                server.kill()
                server.wait(timeout=5)


def import_fixture(path, module):
    """Настоящий v4.2 .kvn; закрытый реестр не переживает учебный namespace."""
    before = run("/usr/bin/ss", "-Hlnu")
    with TemporaryDirectory(prefix="kvn-v5-egress-import-") as directory:
        root = Path(directory)
        store = UserStore(root / "users")
        target = MigrationTarget(root / "packages", root / "gateway")
        target.packages.mkdir(mode=0o700)
        repository = MigrationRepository(store, guard=target.guard, restore_ready=target.restore_ready,
                                         check_target=target.check_archive, target_revision=target.revision)
        migration = MigrationService(repository, export_data=repository.current)
        owner = "b" * 64
        preview = migration.preview(path.read_bytes(), "only-a-synthetic-passphrase", mode="restore", owner=owner)
        migration.commit(preview.ticket, owner=owner)
        (row,) = repository.current().users
        assert store.module_policy(module) == ((row.user.id, True),)
        assert not any(grant.applied for grant in store.get(row.user.id)[2])
        assert not tuple(target.modules.glob("*")) and not (target.packages / "registry.sqlite3").exists()
        assert run("/usr/bin/ss", "-Hlnu") == before, "Импорт не должен создавать listeners"
        material = MigrationMaterial(store)
        return material.server_seed(module), material.credential(row.user.id, module)


def fixture(module, archive=None):
    assert os.geteuid() == 0
    for namespace in ("net", "mnt"):
        assert Path(f"/proc/self/ns/{namespace}").stat().st_ino != Path(f"/proc/1/ns/{namespace}").stat().st_ino
    assert [link["ifname"] for link in json.loads(run(IP, "-j", "link", "show"))] == ["lo"]
    Path("/run/netns").mkdir(mode=0o755, exist_ok=True)
    run("/usr/bin/mount", "-t", "tmpfs", "-o", "mode=0755", "tmpfs", "/run/netns")
    run(IP, "link", "set", "lo", "up")
    run("/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1")
    make_network(CLIENT, "kvn-in", "kvn-peer", SERVER_OUTER, CLIENT_OUTER)
    make_network(ORIGIN, "kvn-wan", "kvn-remote", SERVER_EGRESS, ORIGIN_IP)
    spec = {"wireguard": WG, "amneziawg": AWG}[module]
    binary = tools(spec)
    runtime = TunnelRuntime(spec)
    seed, credential = import_fixture(archive, module) if archive is not None else (None, None)
    initial = runtime.initial_state(egress="kvn-wan")
    assert initial.mode == ("3.1" if spec == AWG else "standard"), "Неожиданный профиль новой установки"
    if seed is not None:
        initial = restore_seed(initial, seed)
    if credential is None:
        credential = allocate(initial.settings, ())
    state = set_user(initial, credential, True)
    run(IP, "link", "add", spec.interface, "type", "dummy")
    try:
        foreign = runtime.link()
        assert foreign is not None and not foreign.owned
        try:
            runtime.start(state)
        except LifecycleError as exc:
            assert exc.code == "tunnel_interface_already_exists"
        else:
            raise AssertionError("Занятый интерфейс перезаписан")
        assert runtime.link() == foreign
    finally:
        run(IP, "link", "delete", "dev", spec.interface)
    runtime.start(state)
    try:
        data = client_file(state, credential, endpoint=SERVER_OUTER, active=True)
        wire = b"\n".join(line for line in data.splitlines() if not line.startswith((b"Address = ", b"MTU = "))) + b"\n"
        inside(CLIENT, IP, "link", "add", "kvn-client", "type", spec.link_type)
        inside(CLIENT, binary, "setconf", "kvn-client", "/dev/stdin", data=wire)
        inside(CLIENT, IP, "address", "add", credential["address"] + "/32", "dev", "kvn-client")
        inside(CLIENT, IP, "link", "set", "kvn-client", "up")
        inside(CLIENT, IP, "route", "add", ORIGIN_IP + "/32", "dev", "kvn-client")
        verify_path()
        assert int(inside(CLIENT, binary, "show", "kvn-client", "latest-handshakes").split()[1]) > 0
        index = runtime.verify(state).index
        runtime.sync(state, initial)
        assert runtime.verify(initial).index == index
        assert not client_file(initial, credential, endpoint=SERVER_OUTER, active=True)
    finally:
        runtime.stop()
    assert runtime.link() is None and not run("/usr/bin/ss", "-Hlnu", "sport", "=", f":{spec.port}")
    origin = "v4.2 .kvn" if archive is not None else "новая настройка"
    print(f"{spec.module} ({origin}, {state.mode}): handshake, трафик, IPv4 NAT и syncconf прошли; порт закрыт.")


if __name__ == "__main__":
    if sys.argv[1:] == ["echo"]:
        source_echo()
    elif sys.argv[1:] == ["send"]:
        client_echo()
    elif len(sys.argv) in (2, 3):
        fixture(sys.argv[1], Path(sys.argv[2]) if len(sys.argv) == 3 else None)
    else:
        raise ValueError("Укажите wireguard или amneziawg")
