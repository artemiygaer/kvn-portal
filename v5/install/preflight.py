"""Проверки чистой установки без изменения служб, файлов и firewall."""

from dataclasses import dataclass
import errno
import ipaddress
from pathlib import Path
import socket

from v5.core.tls.identity import dns_name


DEFAULT_INSTALL_DIR = Path("/root/portal")
CORE_PORTS = (80, 443, 8443)
LEGACY_ROOTS = (Path("/root/deploy"), Path("/srv/kvn-vpn"))
LEGACY_UNITS = ("kvn-portal-agent.service", "kvn-amneziawg.service", "kvn-wireguard.service")
SYSTEMD_DIRS = ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")


class InstallPreflightError(ValueError):
    """Состояние узла не позволяет выполнить чистую установку."""


def _host_path(root: Path, absolute: str | Path) -> Path:
    return root / Path(absolute).relative_to("/")


def find_legacy(root: Path = Path("/"), install_dir: Path = DEFAULT_INSTALL_DIR) -> tuple[str, ...]:
    """Искать только известные безопасные признаки, не открывая runtime-данные."""
    found = []
    for unit_dir in SYSTEMD_DIRS:
        for name in LEGACY_UNITS:
            candidate = _host_path(root, unit_dir) / name
            if candidate.is_symlink() or candidate.is_file():
                found.append(str(Path(unit_dir) / name))
    for path in dict.fromkeys((*LEGACY_ROOTS, install_dir)):
        candidate = _host_path(root, path)
        if (candidate / "docker-compose.yml").is_file() and (candidate / "setup.sh").is_file():
            found.append(str(path))
    return tuple(found)


def reject_legacy(root: Path = Path("/"), install_dir: Path = DEFAULT_INSTALL_DIR) -> None:
    """Отказаться до внесения изменений, включая случай отключённых legacy-служб."""
    if found := find_legacy(root, install_dir):
        raise InstallPreflightError("Найдена существующая установка KVN: " + ", ".join(found))


def normalize_name(value: str) -> str:
    try:
        return dns_name(value)
    except ValueError as exc:
        raise InstallPreflightError("Некорректное имя DNS") from exc


@dataclass(frozen=True)
class InstallIdentity:
    ip: str
    names: tuple[str, ...]

    @classmethod
    def parse(cls, ip: str, names: str = "") -> "InstallIdentity":
        try:
            address = ipaddress.ip_address(ip.strip())
        except ValueError as exc:
            raise InstallPreflightError("Некорректный IPv4/IPv6-адрес") from exc
        if address.is_unspecified or address.is_multicast or getattr(address, "scope_id", None):
            raise InstallPreflightError("Нужен обычный одноадресный IP без зоны")
        normalized = tuple(dict.fromkeys(normalize_name(name) for name in names.split() if name))
        if len(normalized) > 16:
            raise InstallPreflightError("Допускается не более 16 имён")
        return cls(address.compressed, normalized)


def check_ports(ports: tuple[int, ...] = CORE_PORTS) -> None:
    """Проверить занятость TCP-портов до изменений; захватывать их только на пробу."""
    for port in ports:
        for family, address in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            try:
                with socket.socket(family, socket.SOCK_STREAM) as probe:
                    if family == socket.AF_INET6:
                        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    probe.bind((address, port))
            except OSError as exc:
                if family == socket.AF_INET6 and exc.errno in _IPV6_UNAVAILABLE:
                    continue
                raise InstallPreflightError(f"TCP/{port} недоступен для установки") from exc


_IPV6_UNAVAILABLE = (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL)


def ipv6_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::", 0))
    except OSError as exc:
        if exc.errno in _IPV6_UNAVAILABLE:
            return False
        raise
    return True
