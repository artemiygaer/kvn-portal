"""Кодек только маршрутов nginx; сертификаты сохраняются в том же снимке."""

import json

from .plan import Binding, ManagedRoute, ModuleNetwork, NetworkConflict, NetworkPlan, Route, build_plan
from .stream import STREAM_MODULE

HEADER = b"# kvn-v5-network-index "
_MAX_RECORD = 32 * 1024


def encode_routes(routes: tuple[ManagedRoute, ...]) -> bytes:
    document = [[item.owner, item.route.sni, item.route.backend.ip, item.route.backend.port, item.route.self_steal]
                for item in routes]
    return json.dumps(document, separators=(",", ":")).encode("ascii")


def decode_routes(raw: bytes, *, site_names: tuple[str, ...]) -> NetworkPlan:
    if not 1 <= len(raw) <= _MAX_RECORD:
        raise NetworkConflict("gateway_network_index_invalid")
    try:
        document = json.loads(raw)
        if not isinstance(document, list) or len(document) > 64:
            raise ValueError
        by_owner: dict[str, list[Route]] = {}
        for item in document:
            if not isinstance(item, list) or len(item) != 5 or not isinstance(item[0], str):
                raise ValueError
            owner, sni, ip, port, self_steal = item
            by_owner.setdefault(owner, []).append(Route(sni, Binding("tcp", ip, port), self_steal))
        plan = build_plan((ModuleNetwork(owner, True, tuple(routes)) for owner, routes in by_owner.items()),
                          site_names=site_names)
        if encode_routes(plan.routes) != raw:
            raise ValueError
        return plan
    except (ValueError, RecursionError) as exc:
        raise NetworkConflict("gateway_network_index_invalid") from exc


def read_routes(config: bytes, *, site_names: tuple[str, ...]) -> NetworkPlan:
    lines = config.split(b"\n", 2)
    if len(lines) > 1 and lines[1].startswith(HEADER):
        return decode_routes(lines[1][len(HEADER):], site_names=site_names)
    if STREAM_MODULE.encode("ascii") in config:
        raise NetworkConflict("gateway_network_index_missing")
    return NetworkPlan((), (), ())
