"""Проверить реальный DNAT с отдельного клиента IPv4/IPv6 на учебной VM."""

from contextlib import ExitStack
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import threading

from v5.core.network.nft import TABLE, Nftables
from v5.core.network.plan import Binding, ModuleNetwork, NetworkConflict, Publication, build_plan


NS = "kvn-v5-nft-client"
HOST = "kvn5nat0"
PEER = "kvn5nat1"
ADDRESSES = ("198.51.100.8", "fd42:5:5::8")
CLIENTS = ("198.51.100.9", "fd42:5:5::9")
UNMANAGED = "kvn_phase5_unmanaged"
PORTS = {"tcp": (25443, 25444), "udp": (24443, 15443)}
PAYLOAD = b"kvn-phase5-fixture"


def run(*args, check=True):
    result = subprocess.run(args, check=False, capture_output=True, timeout=25)
    if check and result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    return result


class LabNft(Nftables):
    def _call(self, *args, data=None):
        result = subprocess.run(["/usr/sbin/nft", *args], input=data, capture_output=True, timeout=25)
        if result.returncode:
            raise ValueError(result.stderr.decode(errors="replace").strip())
        return result.stdout


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        self.request.sendall(self.request.recv(128))


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        packet, server = self.request
        server.sendto(packet, self.client_address)


class Tcp6(socketserver.TCPServer):
    address_family = socket.AF_INET6


class Udp6(socketserver.UDPServer):
    address_family = socket.AF_INET6


def client(address, protocol, port, expected):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as connection:
        connection.settimeout(1.4)
        try:
            connection.connect((address, int(port)))
            connection.sendall(PAYLOAD)
            received = connection.recv(128)
        except OSError:
            if expected == "closed":
                return
            raise
        assert expected == "open" and received == PAYLOAD, "Неожиданная достижимость порта"


def probe(address, protocol, port, expected):
    run("/usr/sbin/ip", "netns", "exec", NS, "/usr/bin/python3", __file__,
        "--client", address, protocol, str(port), expected)


def add_client():
    run("/usr/sbin/ip", "netns", "add", NS)
    run("/usr/sbin/ip", "link", "add", HOST, "type", "veth", "peer", "name", PEER)
    run("/usr/sbin/ip", "link", "set", PEER, "netns", NS)
    for address, remote in zip(ADDRESSES, CLIENTS):
        length = "64" if ":" in address else "24"
        options = ("nodad",) if ":" in address else ()
        run("/usr/sbin/ip", "addr", "add", f"{address}/{length}", "dev", HOST, *options)
        run("/usr/sbin/ip", "-n", NS, "addr", "add", f"{remote}/{length}", "dev", PEER, *options)
    run("/usr/sbin/ip", "link", "set", HOST, "up")
    run("/usr/sbin/ip", "-n", NS, "link", "set", "lo", "up")
    run("/usr/sbin/ip", "-n", NS, "link", "set", PEER, "up")


def remove_client():
    run("/usr/sbin/ip", "link", "del", HOST, check=False)
    run("/usr/sbin/ip", "netns", "del", NS, check=False)


def main():
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    assert run("/usr/sbin/ip", "link", "show", HOST, check=False).returncode != 0
    assert run("/usr/sbin/nft", "list", "table", "inet", TABLE, check=False).returncode != 0
    assert run("/usr/sbin/nft", "list", "table", "inet", UNMANAGED, check=False).returncode != 0
    nat = LabNft()
    empty = build_plan(())
    entries = tuple(Publication(Binding(protocol, address, public), Binding(protocol, address, private))
                    for protocol, (public, private) in PORTS.items() for address in ADDRESSES)
    plan = build_plan((ModuleNetwork("xray", True, publications=entries),))
    with ExitStack() as cleanup:
        cleanup.callback(remove_client)
        add_client()
        run("/usr/sbin/nft", f'create table inet {UNMANAGED} {{ comment "fixture-existing"; }}')
        cleanup.callback(run, "/usr/sbin/nft", "delete", "table", "inet", UNMANAGED)
        before = run("/usr/sbin/nft", "-a", "-j", "list", "table", "inet", UNMANAGED).stdout
        run("/usr/sbin/nft", f'create table inet {TABLE} {{ comment "fixture-foreign"; }}')
        try:
            try:
                nat.apply(plan, check_only=True)
            except NetworkConflict as exc:
                assert str(exc) == "unmanaged_nft_table"
            else:
                raise AssertionError("Одноимённая чужая таблица не была защищена")
        finally:
            run("/usr/sbin/nft", "delete", "table", "inet", TABLE)
        cleanup.callback(nat.apply, empty)
        nat.apply(plan, check_only=True)
        nat.verify(empty)
        nat.apply(plan)
        nat.verify(plan)
        for protocol, (public, private) in PORTS.items():
            for address in ADDRESSES:
                is_v6 = ":" in address
                server_class, handler = ((Tcp6 if is_v6 else socketserver.TCPServer, Tcp) if protocol == "tcp"
                                         else (Udp6 if is_v6 else socketserver.UDPServer, Udp))
                server = cleanup.enter_context(server_class((address, private), handler))
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                cleanup.callback(worker.join, 3)
                cleanup.callback(server.shutdown)
                probe(address, protocol, public, "open")
                probe(address, protocol, private, "closed")
        sockets = run("/usr/bin/ss", "-H", "-lntu").stdout.decode()
        for public, private in PORTS.values():
            assert f":{public} " not in sockets and f":{private} " in sockets
        assert nat._document("list", "table", "inet", TABLE)
        nat.apply(plan, check_only=True)
        nat.apply(plan)
        nat.verify(plan)
        nat.apply(empty)
        nat.verify(empty)
        for protocol, (public, _) in PORTS.items():
            for address in ADDRESSES:
                probe(address, protocol, public, "closed")
        assert run("/usr/sbin/nft", "-a", "-j", "list", "table", "inet", UNMANAGED).stdout == before
        print("Debian: отдельный namespace-клиент, TCP/UDP IPv4/IPv6, DNAT и защита backend: OK", flush=True)
        print("Инвентарь sockets/nft, удаление своей таблицы и сохранение чужой таблицы: OK", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--client":
        client(*sys.argv[2:])
    else:
        main()
