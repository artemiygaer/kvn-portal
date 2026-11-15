"""Сетевое объявление и экспорт FakeTLS без параметров командной строки."""

from dataclasses import dataclass, field
from ipaddress import ip_address
import re
from secrets import token_hex
from urllib.parse import urlencode

from v5.core.network.plan import Binding, ModuleNetwork, Publication, Route, SITE_BACKEND_PORT
from v5.core.tls.identity import dns_name

PORTS = {"telemt": 2446, "mtg": 2447}
_SECRET = re.compile(r"[0-9a-f]{32}", re.ASCII)
USER = re.compile(r"(?:[A-Za-z0-9][A-Za-z0-9_-]{0,63}|[A-Za-z0-9_.-]{2,32})", re.ASCII)
IDLE_USER = "_kvn_no_user"


def valid_user(value):
    return isinstance(value, str) and value not in {"..", IDLE_USER} and USER.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class Secret:
    value: str = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.value, str) or not _SECRET.fullmatch(self.value):
            raise ValueError("Некорректный секрет MTProto")

    @classmethod
    def create(cls):
        return cls(token_hex(16))

    def for_sni(self, sni: str) -> str:
        return "ee" + self.value + dns_name(sni).encode("ascii").hex()


@dataclass(frozen=True, slots=True)
class Exposure:
    sni: str
    own_site: bool = False
    shared: bool = True
    direct_ip: str | None = None

    def __post_init__(self):
        if (not isinstance(self.sni, str) or type(self.own_site) is not bool or type(self.shared) is not bool
                or (not self.shared and self.direct_ip is None) or (self.own_site and not self.shared)):
            raise ValueError("Некорректная публикация MTProto")
        name = dns_name(self.sni)
        if len(name) > 180:
            raise ValueError("Имя FakeTLS слишком длинное")
        object.__setattr__(self, "sni", name)
        if self.direct_ip is not None:
            candidate = Binding("tcp", self.direct_ip, PORTS["telemt"])
            if (candidate.address.version != 4 or candidate.address.is_loopback
                    or (self.shared and not candidate.address.is_unspecified)):
                raise ValueError("Для SNI с прямым портом нужен общий IPv4 bind")
            object.__setattr__(self, "direct_ip", candidate.ip)

    @property
    def address(self) -> str:
        return self.direct_ip if self.direct_ip is not None else "127.0.0.1"

    def network(self, module: str, *, site_names: tuple[str, ...]) -> ModuleNetwork:
        if self.own_site != (self.sni in site_names):
            raise ValueError("Имя FakeTLS не соответствует режиму маскировки")
        port = PORTS[module]
        routes = (Route(self.sni, Binding("tcp", "127.0.0.1", port), self.own_site),) if self.shared else ()
        direct = (Publication(Binding("tcp", self.direct_ip, port)),) if self.direct_ip is not None else ()
        return ModuleNetwork(module, routes=routes, publications=direct)

    def validate_cover(self, target: "CoverTarget") -> None:
        if not isinstance(target, CoverTarget) or (target.port == SITE_BACKEND_PORT) != self.own_site:
            raise ValueError("Цель не соответствует режиму маскировки MTProto")


@dataclass(frozen=True, slots=True)
class CoverTarget:
    """В конфиге только проверенный IPv4 или фиксированный backend сайта."""

    ip: str
    port: int

    def __post_init__(self):
        if not isinstance(self.ip, str):
            raise ValueError("Некорректная цель маскировки")
        address = ip_address(self.ip)
        if (address.version != 4 or type(self.port) is not int
                or (self.port == SITE_BACKEND_PORT and self.ip != "127.0.0.1")
                or (self.port == 443 and (not address.is_global or address.is_multicast))
                or self.port not in (443, SITE_BACKEND_PORT)):
            raise ValueError("Некорректная цель маскировки")
        object.__setattr__(self, "ip", address.compressed)


def endpoint_name(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Некорректный адрес клиента MTProto")
    try:
        ip = ip_address(value)
    except ValueError:
        return dns_name(value)
    if ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_unspecified or "%" in value:
        raise ValueError("Некорректный адрес клиента MTProto")
    return ip.compressed


@dataclass(frozen=True, slots=True)
class ClientProfile:
    module: str
    server: str
    port: int
    sni: str
    secret: Secret = field(repr=False)
    user: str | None = None

    def __post_init__(self):
        if (not isinstance(self.module, str) or self.module not in PORTS
                or type(self.port) is not int or self.port not in (443, PORTS[self.module])
                or not isinstance(self.secret, Secret)
                or (self.module == "mtg" and self.user is not None)
                or (self.module == "telemt" and not valid_user(self.user))):
            raise ValueError("Некорректный профиль MTProto")
        object.__setattr__(self, "server", endpoint_name(self.server))
        if not isinstance(self.sni, str):
            raise ValueError("Некорректное имя FakeTLS")
        sni = dns_name(self.sni)
        if len(sni) > 180:
            raise ValueError("Имя FakeTLS слишком длинное")
        object.__setattr__(self, "sni", sni)

    @property
    def scope(self) -> str:
        return "user" if self.user is not None else "shared"

    def uri(self) -> str:
        return "tg://proxy?" + urlencode({"server": self.server, "port": self.port,
                                          "secret": self.secret.for_sni(self.sni)})


def profile(module, exposure, secret, server, *, direct=False, user=None):
    if (type(direct) is not bool or (direct and exposure.direct_ip is None)
            or (not direct and not exposure.shared)):
        raise ValueError("Порт MTProto не опубликован")
    return ClientProfile(module, server, PORTS[module] if direct else 443, exposure.sni, secret, user)
