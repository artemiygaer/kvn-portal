"""Единые правила для имён, IP SAN и адресов публичного входа."""

from dataclasses import dataclass
import hashlib
from ipaddress import ip_address
import re


_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def dns_name(raw: str) -> str:
    value = raw.strip().removesuffix(".")
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Недопустимое имя DNS") from exc
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not _LABEL.fullmatch(label) for label in labels)):
        raise ValueError("Недопустимое имя DNS")
    try:
        ip_address(value)
    except ValueError:
        return value
    raise ValueError("Вместо имени DNS указан IP")


@dataclass(frozen=True, slots=True)
class TLSIdentity:
    name: str
    is_ip: bool

    def __post_init__(self) -> None:
        if type(self.is_ip) is not bool or not isinstance(self.name, str):
            raise ValueError("Недопустимый идентификатор TLS")
        if self.is_ip:
            addr = ip_address(self.name.strip())
            if getattr(addr, "scope_id", None) is not None or addr.is_multicast or addr.is_unspecified:
                raise ValueError("IP TLS должен быть одноадресным и без зоны")
            canonical = addr.compressed
        else:
            canonical = dns_name(self.name)
        object.__setattr__(self, "name", canonical)

    @property
    def authority(self) -> str:
        """Хост для URL/Host; SAN содержит IP без скобок."""
        return f"[{self.name}]" if self.is_ip and ":" in self.name else self.name

    @property
    def slot(self) -> str:
        """Стабильное имя отдельного каталога/lineage без метасимволов."""
        if self.is_ip:
            return f"ip-{self.name.replace(':', '_')}"
        if len(self.name) > 220:
            return "dns-sha256-" + hashlib.sha256(self.name.encode("ascii")).hexdigest()
        return f"dns-{self.name}"
