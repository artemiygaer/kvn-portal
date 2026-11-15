"""Режимы Xray и их сетевые ресурсы без запуска Docker."""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
import re

from v5.core.network.plan import Binding, ModuleNetwork, Publication, Route, SITE_BACKEND_PORT
from v5.core.tls.identity import TLSIdentity, dns_name


class Kind(StrEnum):
    TLS = "tls"
    REALITY_TCP = "reality-tcp"
    REALITY_XHTTP = "reality-xhttp"


class Exposure(StrEnum):
    DIRECT = "direct"
    SHARED = "shared"
    BOTH = "both"

    @property
    def direct(self) -> bool:
        return self is not Exposure.SHARED

    @property
    def shared(self) -> bool:
        return self is not Exposure.DIRECT


class Reality(StrEnum):
    EXTERNAL = "external"
    SELF_STEAL = "self-steal"


PORTS = {Kind.TLS: 2443, Kind.REALITY_TCP: 2444, Kind.REALITY_XHTTP: 2445}
_XHTTP_PATH = re.compile(r"/[A-Za-z0-9][A-Za-z0-9/_-]{0,62}", re.ASCII)


@dataclass(frozen=True, slots=True)
class Profile:
    kind: Kind
    exposure: Exposure
    sni: str
    reality: Reality | None = None
    external_host: str | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, Kind) or not isinstance(self.exposure, Exposure) or not isinstance(self.sni, str):
            raise ValueError("Некорректный режим Xray")
        if self.kind is Kind.TLS:
            if self.reality is not None or self.external_host is not None:
                raise ValueError("Режим TLS не принимает параметры Reality")
            try:
                ip_address(self.sni)
            except ValueError:
                identity = TLSIdentity(self.sni, False)
            else:
                identity = TLSIdentity(self.sni, True)
                if self.exposure.shared:
                    raise ValueError("TLS по IP требует прямого порта")
            object.__setattr__(self, "sni", identity.name)
        else:
            object.__setattr__(self, "sni", dns_name(self.sni))
            if self.reality is Reality.EXTERNAL:
                if not isinstance(self.external_host, str):
                    raise ValueError("Укажите DNS-имя внешней цели Reality")
                object.__setattr__(self, "external_host", dns_name(self.external_host))
            elif self.reality is Reality.SELF_STEAL:
                if self.external_host is not None or not self.exposure.shared:
                    raise ValueError("Self-steal требует общего TCP/443 и не принимает внешнюю цель")
            else:
                raise ValueError("Выберите внешний Reality или self-steal явно")
        if self.kind is Kind.REALITY_XHTTP:
            if (not isinstance(self.path, str) or not _XHTTP_PATH.fullmatch(self.path)
                    or "//" in self.path or self.path.endswith("/")):
                raise ValueError("Недопустимый путь xHTTP")
        elif self.path is not None:
            raise ValueError("Путь используется только xHTTP")

    @property
    def port(self) -> int:
        return PORTS[self.kind]

    @property
    def target(self) -> str | None:
        if self.reality is Reality.SELF_STEAL:
            return f"127.0.0.1:{SITE_BACKEND_PORT}"
        if self.reality is Reality.EXTERNAL:
            return f"{self.external_host}:443"
        return None

    def tls_identity(self) -> TLSIdentity | None:
        if self.kind is not Kind.TLS:
            return None
        try:
            ip_address(self.sni)
        except ValueError:
            return TLSIdentity(self.sni, False)
        return TLSIdentity(self.sni, True)


@dataclass(frozen=True, slots=True)
class Profiles:
    values: tuple[Profile, ...] = ()

    def __post_init__(self) -> None:
        if (not isinstance(self.values, tuple) or any(not isinstance(item, Profile) for item in self.values)
                or len({item.kind for item in self.values}) != len(self.values)
                or len({item.sni for item in self.values if item.exposure.shared})
                != sum(item.exposure.shared for item in self.values)):
            raise ValueError("Повтор режима или общего SNI Xray")

    def network(self, *, site_names: tuple[str, ...], ipv4: str = "0.0.0.0") -> ModuleNetwork:
        address = ip_address(ipv4)
        if address.version != 4 or address.is_loopback:
            raise ValueError("Прямой bind Xray требует IPv4 хоста или wildcard")
        site = frozenset(map(dns_name, site_names))
        routes, publications = [], []
        for profile in sorted(self.values, key=lambda item: item.port):
            if profile.exposure is Exposure.BOTH and not address.is_unspecified:
                raise ValueError("Общий и прямой вход одного профиля требуют IPv4 wildcard")
            if profile.reality is Reality.EXTERNAL and profile.external_host in site:
                raise ValueError("Внешняя цель Reality совпадает с сайтом; выберите self-steal явно")
            if profile.reality is Reality.SELF_STEAL and profile.sni not in site:
                raise ValueError("Имя self-steal не настроено для HTTPS-сайта")
            if profile.exposure.shared:
                routes.append(Route(profile.sni, Binding("tcp", "127.0.0.1", profile.port),
                                    self_steal=profile.reality is Reality.SELF_STEAL))
            if profile.exposure.direct:
                publications.append(Publication(Binding("tcp", address.compressed, profile.port)))
                if address.is_unspecified:
                    # Xray трактует wildcard 0.0.0.0 как dual-stack, а не как IPv4-only.
                    publications.append(Publication(Binding("tcp", "::", profile.port)))
        return ModuleNetwork("xray", routes=tuple(routes), publications=tuple(publications))
