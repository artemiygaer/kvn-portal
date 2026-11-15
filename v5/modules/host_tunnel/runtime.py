"""Управление только своим kernel-интерфейсом без shell и wg-quick."""

from dataclasses import dataclass
from ipaddress import IPv4Interface, IPv4Network
import json
from pathlib import Path
import secrets
import subprocess

from v5.core.lifecycle.controller import LifecycleError
from v5.modules.amneziawg.profile import Profile

from .config import AWG, Settings, Tunnel, key
from .firewall import TunnelFirewall
from .platform import capability, tools
from .state import State


IP = "/usr/sbin/ip"
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


def _run(*argv, data=None, optional=False, code="tunnel_command_failed") -> bytes | None:
    try:
        result = subprocess.run(argv, input=data if data is not None else b"", stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=20, check=False, env=_ENV)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LifecycleError(code) from exc
    if result.returncode:
        if optional:
            return None
        raise LifecycleError(code)
    return result.stdout


def _json(raw: bytes, code: str) -> list[dict]:
    try:
        data = json.loads(raw)
        if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
            raise ValueError
        return data
    except (TypeError, ValueError, RecursionError) as exc:
        raise LifecycleError(code) from exc


def _create_link(spec: Tunnel) -> None:
    # Создание игнорирует alias; назначить владельца до публикации рабочего имени.
    temporary = "kvn" + secrets.token_hex(5)
    _run(IP, "link", "add", "name", temporary, "type", spec.link_type, code="tunnel_kernel_link_failed")
    try:
        _run(IP, "link", "set", "dev", temporary, "alias", spec.alias, code="tunnel_link_owner_failed")
        _run(IP, "link", "set", "dev", temporary, "name", spec.interface, code="tunnel_interface_already_exists")
    except BaseException:
        _run(IP, "link", "delete", "dev", temporary, optional=True)
        raise


@dataclass(frozen=True, slots=True)
class Link:
    index: int
    owned: bool
    up: bool


class TunnelRuntime:
    def __init__(self, spec: Tunnel):
        self.spec = spec
        self.firewall = TunnelFirewall(spec)

    def link(self) -> Link | None:
        raw = _run(IP, "-j", "-d", "link", "show", "dev", self.spec.interface,
                   optional=True, code="tunnel_link_unavailable")
        if raw is None:
            return None
        rows = _json(raw, "tunnel_link_unavailable")
        if len(rows) != 1 or type(rows[0].get("ifindex")) is not int or rows[0]["ifindex"] <= 0:
            raise LifecycleError("tunnel_link_unavailable")
        row = rows[0]
        metadata = row.get("linkinfo")
        owned = (row.get("ifname") == self.spec.interface and row.get("ifalias") == self.spec.alias
                 and isinstance(metadata, dict) and metadata.get("info_kind") == self.spec.link_type)
        flags = row.get("flags")
        return Link(row["ifindex"], owned, isinstance(flags, list) and "UP" in flags)

    def _tool(self) -> str:
        binary = tools(self.spec)
        if not binary:
            raise LifecycleError(f"{self.spec.module}_tools_missing")
        return binary

    def initial_state(self, *, modern=None, egress=None) -> State:
        if modern is None:
            modern = self.spec == AWG
        if type(modern) is not bool or (modern and self.spec != AWG):
            raise LifecycleError("tunnel_module_mismatch")
        binary = self._tool()
        private = _run(binary, "genkey", code="tunnel_key_generation_failed").decode("ascii").strip()
        profile = None
        if self.spec == AWG:
            profile = (Profile.modern(_run(binary, "genpsk", code="tunnel_key_generation_failed").decode("ascii").strip())
                       if modern else Profile())
        return State(self.spec, Settings(self.spec.address, private, egress=egress), profile)

    def preflight(self, state: State) -> None:
        if state.spec != self.spec:
            raise LifecycleError("tunnel_module_mismatch")
        current = capability(self.spec, check_modern=state.mode == "3.1")
        if current.issue:
            raise LifecycleError(current.issue)
        if state.mode not in current.profiles:
            raise LifecycleError("amneziawg_profile_unsupported")
        if self.link() is not None:
            raise LifecycleError("tunnel_interface_already_exists")
        egress = state.settings.egress
        if egress:
            if _run(IP, "link", "show", "dev", egress, optional=True) is None:
                raise LifecycleError("tunnel_egress_unavailable")
            if Path("/proc/sys/net/ipv4/ip_forward").read_bytes().strip() != b"1":
                raise LifecycleError("tunnel_ipv4_forwarding_required")
        for route in _json(_run(IP, "-j", "-4", "route", "show", "scope", "link"), "tunnel_routes_unavailable"):
            dst = route.get("dst")
            try:
                occupied = IPv4Network(dst) if isinstance(dst, str) and dst != "default" else None
            except ValueError:
                raise LifecycleError("tunnel_routes_unavailable") from None
            if occupied and occupied.overlaps(state.settings.subnet):
                raise LifecycleError("tunnel_subnet_conflict")
        self.firewall.apply_compiled(self.firewall.compile(state.settings), check_only=True)

    def start(self, state: State) -> None:
        self.preflight(state)
        interface = self.spec.interface
        _create_link(self.spec)
        try:
            _run(IP, "address", "add", state.settings.address, "dev", interface, code="tunnel_address_failed")
            _run(self._tool(), "setconf", interface, "/dev/stdin", data=state.server(), code="tunnel_config_rejected")
            self.firewall.apply_compiled(self.firewall.compile(state.settings))
            _run(IP, "link", "set", "dev", interface, "mtu", str(state.settings.mtu), "up")
            self.verify(state)
        except BaseException:
            self.stop()
            raise

    def stop(self) -> None:
        link = self.link()
        if link is not None:
            if not link.owned:
                raise LifecycleError("foreign_tunnel_interface")
            # Сначала закрыть порт, потом снять только правила этого владельца.
            _run(IP, "link", "delete", "dev", self.spec.interface, code="tunnel_link_delete_failed")
        empty = self.firewall.compile(None)
        self.firewall.apply_compiled(empty)
        self.firewall.verify_compiled(empty)

    def _peers(self, binary: str) -> dict[str, str]:
        data = _run(binary, "show", self.spec.interface, "allowed-ips", code="tunnel_peers_unavailable")
        try:
            result = {}
            for line in data.decode("ascii").splitlines():
                public_key, route = line.split("\t")
                result[key(public_key)] = route
            return result
        except (UnicodeError, ValueError) as exc:
            raise LifecycleError("tunnel_peers_unavailable") from exc

    def verify(self, state: State) -> Link:
        link = self.link()
        if state.spec != self.spec or link is None or not link.owned or not link.up:
            raise LifecycleError("tunnel_not_healthy")
        binary, interface = self._tool(), self.spec.interface
        if _run(binary, "show", interface, "listen-port").strip() != str(self.spec.port).encode("ascii"):
            raise LifecycleError("tunnel_listen_port_mismatch")
        rows = _json(_run(IP, "-j", "-4", "address", "show", "dev", interface), "tunnel_address_unavailable")
        address = IPv4Interface(state.settings.address)
        if (len(rows) != 1 or rows[0].get("mtu") != state.settings.mtu or not any(
                row.get("local") == str(address.ip) and row.get("prefixlen") == address.network.prefixlen
                for row in rows[0].get("addr_info", ()) if isinstance(row, dict))):
            raise LifecycleError("tunnel_address_mismatch")
        if self._peers(binary) != {peer.public_key: f"{peer.address}/32" for peer in state.settings.peers}:
            raise LifecycleError("tunnel_peers_mismatch")
        self.firewall.verify_compiled(self.firewall.compile(state.settings))
        return link

    def sync(self, previous: State, desired: State) -> None:
        if previous.spec != self.spec or not previous.peer_only(desired):
            raise LifecycleError("tunnel_structural_change_requires_disable")
        before = self.verify(previous)
        binary, interface = self._tool(), self.spec.interface
        try:
            _run(binary, "syncconf", interface, "/dev/stdin", data=desired.server(), code="tunnel_syncconf_failed")
            if self.verify(desired).index != before.index:
                raise LifecycleError("tunnel_interface_replaced")
        except BaseException:
            _run(binary, "syncconf", interface, "/dev/stdin", data=previous.server(), code="tunnel_sync_rollback_failed")
            self.verify(previous)
            raise
