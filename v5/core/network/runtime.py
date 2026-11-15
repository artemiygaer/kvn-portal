"""Согласовать nginx, локальные bindings и отдельную таблицу nftables."""

from collections.abc import Callable
from pathlib import Path
import socket

from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_gateway_revision
from v5.core.tls.transaction import read_gateway_config

from .nft import Nftables
from .plan import Binding, NetworkConflict, NetworkPlan, SITE_BACKEND_PORT
from .stream import STREAM_MODULE


def check_binding(binding: Binding) -> None:
    family = socket.AF_INET if binding.address.version == 4 else socket.AF_INET6
    kind = socket.SOCK_STREAM if binding.protocol == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as test:
            if family == socket.AF_INET6:
                test.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            if kind == socket.SOCK_STREAM:
                # TIME_WAIT после остановки не мешает повторному включению, чужой LISTEN — мешает.
                test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test.bind((binding.ip, binding.port))
    except OSError as exc:
        raise NetworkConflict("publication_port_unavailable") from exc


def _bindings(plan: NetworkPlan) -> set[Binding]:
    return ({item.publication.public for item in plan.publications}
            | {item.publication.redirect for item in plan.publications if item.publication.redirect}
            | {item.route.backend for item in plan.routes})


class NetworkRuntime:
    def __init__(self, gateway: GatewayController, *, nft: Nftables | None = None,
                 live_probe: Callable[[NetworkPlan], None] | None = None,
                 check: Callable[[Path], None] = check_nginx,
                 reload: Callable[[], None] = reload_nginx):
        self.gateway = gateway
        self.nft = Nftables() if nft is None else nft
        self.live_probe = (lambda _: None) if live_probe is None else live_probe
        self.check, self.reload = check, reload
        self.bootstrap = gateway.config.parent / "bootstrap.crt"

    def _loaded(self, config: bytes) -> None:
        verify_gateway_revision(config, self.bootstrap)

    def preflight(self, plan: NetworkPlan, previous: NetworkPlan) -> None:
        # Занятые самим активным планом sockets не требуется занимать повторно.
        before, after = _bindings(previous), _bindings(plan)
        for binding in sorted(after - before, key=lambda item: item.sort_key):
            if not any(binding.overlaps(item) for item in before):
                check_binding(binding)
        if plan.routes:
            if not Path(STREAM_MODULE).is_file():
                raise NetworkConflict("nginx_stream_dependency_missing")
            if not self.gateway.active():
                raise NetworkConflict("gateway_tls_required")
            # Проверить активную пару именно выбранного self-steal имени и весь совместный снимок.
            self.gateway.preview_routes(plan)
            if not previous.routes:
                check_binding(Binding("tcp", "127.0.0.1", SITE_BACKEND_PORT))
                if self.gateway.ipv6:
                    check_binding(Binding("tcp", "::1", SITE_BACKEND_PORT))
        self.nft.apply(plan, check_only=True,
                       required=any(item.publication.redirect for item in previous.publications))

    def apply(self, plan: NetworkPlan, *, reconcile: bool = False) -> None:
        self.nft.apply(plan, check_only=True)
        self.gateway.replace_routes(plan, check=self.check, reload=self.reload, verify_loaded=self._loaded,
                                    verify_live=lambda: None, verify_restored=lambda: None, reconcile=reconcile)
        self.nft.apply(plan)

    def verify(self, plan: NetworkPlan) -> None:
        if self.gateway.network_routes().routes != plan.routes:
            raise NetworkConflict("gateway_routes_not_applied")
        self._loaded(read_gateway_config(self.gateway.config))
        self.nft.verify(plan)
        self.live_probe(plan)
