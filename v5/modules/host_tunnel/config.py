"""Проверяемые адреса, ключи и рендер без shell-команд и wg-quick."""

import base64
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Interface, IPv4Network, ip_address
import re

from v5.core.network.plan import Binding, ModuleNetwork, Publication
from v5.core.tls.identity import dns_name


_KEY = re.compile(r"[A-Za-z0-9+/]{43}=", re.ASCII)
_INTERFACE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", re.ASCII)
_PRIVATE = tuple(IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
MAX_PEERS = 512


def key(value: str) -> str:
    if not isinstance(value, str) or not _KEY.fullmatch(value):
        raise ValueError("Недопустимый ключ туннеля")
    raw = base64.b64decode(value, validate=True)
    if raw == bytes(32) or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Недопустимый ключ туннеля")
    return value


@dataclass(frozen=True, slots=True)
class Tunnel:
    module: str
    interface: str
    link_type: str
    port: int
    address: str

    @property
    def alias(self) -> str:
        return f"kvn-v5:{self.module}"

    def network(self, *, ipv6: bool) -> ModuleNetwork:
        addresses = ("0.0.0.0", "::") if ipv6 else ("0.0.0.0",)
        return ModuleNetwork(self.module, publications=tuple(Publication(Binding("udp", address, self.port))
                                                              for address in addresses))


WG = Tunnel("wireguard", "wg0", "wireguard", 51821, "10.67.67.1/24")
AWG = Tunnel("amneziawg", "awg0", "amneziawg", 51820, "10.66.66.1/24")


@dataclass(frozen=True, slots=True)
class Peer:
    public_key: str = field(repr=False)
    address: str
    preshared_key: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        key(self.public_key)
        if not isinstance(self.address, str):
            raise ValueError("Некорректный адрес пользователя")
        object.__setattr__(self, "address", str(IPv4Address(self.address)))
        if self.preshared_key is not None:
            key(self.preshared_key)


@dataclass(frozen=True, slots=True)
class Settings:
    address: str
    private_key: str = field(repr=False)
    peers: tuple[Peer, ...] = ()
    mtu: int = 1280
    egress: str | None = None

    def __post_init__(self) -> None:
        key(self.private_key)
        if not isinstance(self.address, str):
            raise ValueError("Некорректный адрес сервера туннеля")
        address = IPv4Interface(self.address)
        network = address.network
        if (not 16 <= network.prefixlen <= 30 or not any(network.subnet_of(item) for item in _PRIVATE)
                or address.ip in (network.network_address, network.broadcast_address)):
            raise ValueError("Нужен IPv4 хоста внутри частной подсети /16–/30")
        object.__setattr__(self, "address", str(address))
        if type(self.mtu) is not int or not 576 <= self.mtu <= 1420:
            raise ValueError("Некорректный MTU туннеля")
        if self.egress is not None and (not isinstance(self.egress, str) or not _INTERFACE.fullmatch(self.egress)
                                        or self.egress in {"lo", WG.interface, AWG.interface}):
            raise ValueError("Недопустимый исходящий интерфейс туннеля")
        if not isinstance(self.peers, tuple) or len(self.peers) > MAX_PEERS or any(
                not isinstance(peer, Peer) for peer in self.peers):
            raise ValueError("Некорректный список пользователей туннеля")
        addresses = {IPv4Address(peer.address) for peer in self.peers}
        if (len(addresses) != len(self.peers) or len({peer.public_key for peer in self.peers}) != len(self.peers)
                or any(ip not in network or ip in (network.network_address, network.broadcast_address, address.ip)
                       for ip in addresses)):
            raise ValueError("Адреса и ключи пользователей должны быть уникальны и принадлежать подсети")

    @property
    def subnet(self) -> IPv4Network:
        return IPv4Interface(self.address).network


def settings_from_document(document) -> Settings:
    if (not isinstance(document, dict) or document.keys() != {"address", "private_key", "peers", "mtu", "egress"}
            or not isinstance(document["peers"], list) or len(document["peers"]) > MAX_PEERS):
        raise ValueError("Некорректная схема настроек туннеля")
    peers = []
    for item in document["peers"]:
        if not isinstance(item, dict) or item.keys() != {"public_key", "address", "preshared_key"}:
            raise ValueError("Некорректная схема пользователя туннеля")
        peers.append(Peer(**item))
    return Settings(document["address"], document["private_key"], tuple(peers), document["mtu"], document["egress"])


def render_server(spec: Tunnel, settings: Settings, *, obfuscation: tuple[str, ...] = ()) -> bytes:
    if spec == WG and obfuscation:
        raise ValueError("WireGuard не принимает поля AmneziaWG")
    rows = ["[Interface]", f"PrivateKey = {settings.private_key}", f"ListenPort = {spec.port}", *obfuscation]
    for peer in sorted(settings.peers, key=lambda item: IPv4Address(item.address)):
        rows.extend(("", "[Peer]", f"PublicKey = {peer.public_key}"))
        if peer.preshared_key:
            rows.append(f"PresharedKey = {peer.preshared_key}")
        rows.append(f"AllowedIPs = {peer.address}/32")
    return ("\n".join(rows) + "\n").encode("ascii")


def render_client(spec: Tunnel, settings: Settings, peer: Peer, *, private_key: str, server_key: str,
                  endpoint: str, active: bool, obfuscation: tuple[str, ...] = ()) -> bytes:
    if type(active) is not bool:
        raise ValueError("Некорректный статус туннеля")
    if not active or peer not in settings.peers:
        return b""
    if spec == WG and obfuscation:
        raise ValueError("WireGuard не принимает поля AmneziaWG")
    if not isinstance(endpoint, str) or "%" in endpoint:
        raise ValueError("Недопустимый адрес сервера")
    try:
        ip = ip_address(endpoint)
    except ValueError:
        endpoint = dns_name(endpoint)
    else:
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise ValueError("Недопустимый адрес сервера")
        endpoint = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    rows = ["[Interface]", f"PrivateKey = {key(private_key)}", f"Address = {peer.address}/32",
            f"MTU = {settings.mtu}", *obfuscation, "", "[Peer]", f"PublicKey = {key(server_key)}"]
    if peer.preshared_key:
        rows.append(f"PresharedKey = {peer.preshared_key}")
    allowed = "0.0.0.0/0" if settings.egress else str(settings.subnet)
    rows.extend((f"Endpoint = {endpoint}:{spec.port}", f"AllowedIPs = {allowed}", "PersistentKeepalive = 25"))
    return ("\n".join(rows) + "\n").encode("ascii")
