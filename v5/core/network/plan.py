"""Построить детерминированный сетевой план до изменения служб и правил."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address

from v5.core.contracts import validate_module_id
from v5.core.tls.identity import dns_name
from v5.core.tls.access import load_access

CORE_TCP = frozenset({80, 443, 8443})
SITE_BACKEND_PORT = 10443
RESERVED_TCP = CORE_TCP | {SITE_BACKEND_PORT}


def reserved_tcp():
    return RESERVED_TCP | {load_access().port}
MAX_SNI_ROUTES = 64
MAX_PUBLICATIONS = 64
OWN_SITE_MODULES = frozenset({"xray", "telemt", "mtg"})


class NetworkConflict(ValueError):
    """Короткий код, пригодный для безопасного ответа портала."""


@dataclass(frozen=True, slots=True)
class Binding:
    protocol: str
    ip: str
    port: int

    def __post_init__(self) -> None:
        if self.protocol not in ("tcp", "udp") or type(self.port) is not int or not 0 < self.port <= 65535:
            raise NetworkConflict("invalid_binding")
        if not isinstance(self.ip, str):
            raise NetworkConflict("invalid_binding_address")
        try:
            addr = ip_address(self.ip)
        except ValueError as exc:
            raise NetworkConflict("invalid_binding_address") from exc
        if (addr.is_multicast or addr.is_link_local
                or getattr(addr, "scope_id", None) is not None
                or getattr(addr, "ipv4_mapped", None) is not None):
            raise NetworkConflict("invalid_binding_address")
        object.__setattr__(self, "ip", addr.compressed)

    @property
    def address(self) -> IPv4Address | IPv6Address:
        return ip_address(self.ip)

    @property
    def sort_key(self) -> tuple[str, int, int, int]:
        addr = self.address
        return self.protocol, addr.version, self.port, int(addr)

    def overlaps(self, other: "Binding") -> bool:
        a, b = self.address, other.address
        # Каждый IPv6 wildcard рендерится с IPV6_V6ONLY; семейства независимы.
        return (self.protocol == other.protocol and self.port == other.port and a.version == b.version
                and (a == b or a.is_unspecified or b.is_unspecified))

    def nginx_address(self) -> str:
        return f"[{self.ip}]:{self.port}" if self.address.version == 6 else f"{self.ip}:{self.port}"


@dataclass(frozen=True, slots=True)
class Publication:
    public: Binding
    redirect: Binding | None = None
    shared: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.public, Binding) or self.public.address.is_loopback:
            raise NetworkConflict("invalid_public_binding")
        if type(self.shared) is not bool or (self.shared and self.redirect is None):
            raise NetworkConflict("invalid_shared_binding")
        if self.redirect is not None:
            if (not isinstance(self.redirect, Binding) or self.redirect.protocol != self.public.protocol
                    or self.redirect.address.version != self.public.address.version
                    or self.redirect.address.is_unspecified or self.redirect.address.is_loopback
                    or self.redirect.port == self.public.port
                    or (self.redirect.protocol == "tcp" and self.redirect.port in reserved_tcp())):
                raise NetworkConflict("invalid_redirect_target")


@dataclass(frozen=True, slots=True)
class Route:
    sni: str
    backend: Binding
    self_steal: bool = False

    def __post_init__(self) -> None:
        try:
            if not isinstance(self.sni, str):
                raise ValueError("Недопустимый SNI")
            canonical = dns_name(self.sni)
        except ValueError as exc:
            raise NetworkConflict("invalid_sni") from exc
        object.__setattr__(self, "sni", canonical)
        if (not isinstance(self.backend, Binding) or self.backend.protocol != "tcp"
                or not self.backend.address.is_loopback or self.backend.port in reserved_tcp()
                or type(self.self_steal) is not bool):
            raise NetworkConflict("invalid_sni_backend")


@dataclass(frozen=True, slots=True)
class ModuleNetwork:
    module: str
    enabled: bool = False
    routes: tuple[Route, ...] = ()
    publications: tuple[Publication, ...] = ()

    def __post_init__(self) -> None:
        try:
            validate_module_id(self.module)
        except ValueError as exc:
            raise NetworkConflict("unsupported_module") from exc
        if (type(self.enabled) is not bool or not isinstance(self.routes, tuple)
                or not isinstance(self.publications, tuple)
                or len(self.routes) > MAX_SNI_ROUTES or len(self.publications) > MAX_PUBLICATIONS
                or any(not isinstance(item, Route) for item in self.routes)
                or any(not isinstance(item, Publication) for item in self.publications)):
            raise NetworkConflict("invalid_module_network")


@dataclass(frozen=True, slots=True)
class ManagedRoute:
    owner: str
    route: Route


@dataclass(frozen=True, slots=True)
class ManagedPublication:
    owners: tuple[str, ...]
    publication: Publication


@dataclass(frozen=True, slots=True)
class NetworkPlan:
    active: tuple[str, ...]
    routes: tuple[ManagedRoute, ...]
    publications: tuple[ManagedPublication, ...]


def build_plan(modules, *, site_names=(), occupied=()) -> NetworkPlan:
    """Посторонние listeners только учитываются; при конфликте нет частичного плана."""
    seen, active = set(), set()
    routes: dict[str, ManagedRoute] = {}
    ports: dict[Binding, ManagedPublication] = {}
    site = frozenset(map(dns_name, site_names))
    used = tuple(occupied)
    for item in modules:
        if not isinstance(item, ModuleNetwork) or item.module in seen:
            raise NetworkConflict("duplicate_module")
        seen.add(item.module)
        if not item.enabled:
            continue
        active.add(item.module)
        for route in item.routes:
            if route.sni in routes or (route.sni in site and not route.self_steal):
                raise NetworkConflict("sni_conflict")
            if route.self_steal and (item.module not in OWN_SITE_MODULES or route.sni not in site):
                raise NetworkConflict("invalid_self_steal")
            routes[route.sni] = ManagedRoute(item.module, route)
        for entry in item.publications:
            binding = entry.public
            if binding.protocol == "tcp" and binding.port in reserved_tcp():
                raise NetworkConflict("core_port_conflict")
            if any(binding.overlaps(other) for other in used):
                raise NetworkConflict("unmanaged_port_conflict")
            previous = ports.get(binding)
            if previous is not None:
                if (not entry.shared or entry != previous.publication or item.module in previous.owners):
                    raise NetworkConflict("publication_conflict")
                ports[binding] = ManagedPublication(tuple(sorted((*previous.owners, item.module))), entry)
                continue
            if any(binding.overlaps(other) for other in ports):
                raise NetworkConflict("publication_conflict")
            ports[binding] = ManagedPublication((item.module,), entry)
    private_targets = tuple(item.publication.redirect for item in ports.values()
                            if item.publication.redirect is not None)
    if any(binding.overlaps(target) for binding in ports for target in private_targets):
        raise NetworkConflict("backend_publication_conflict")
    for item in routes.values():
        backend = item.route.backend
        if any(other.owner != item.owner and backend.overlaps(other.route.backend) for other in routes.values()):
            raise NetworkConflict("backend_port_conflict")
        if any(item.owner not in publication.owners and backend.overlaps(binding)
               for binding, publication in ports.items()):
            raise NetworkConflict("backend_port_conflict")
    if len(routes) > MAX_SNI_ROUTES or len(ports) > MAX_PUBLICATIONS:
        raise NetworkConflict("network_plan_limit")
    return NetworkPlan(tuple(sorted(active)), tuple(routes[name] for name in sorted(routes)),
                       tuple(ports[binding] for binding in sorted(ports, key=lambda item: item.sort_key)))
