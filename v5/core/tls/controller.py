"""Применение пары с согласованным индексом в том же nginx.conf."""

from collections.abc import Callable
import json
from pathlib import Path
import re

from v5.core.network.gateway_state import HEADER as NETWORK_HEADER, decode_routes, encode_routes, read_routes
from v5.core.network.plan import NetworkPlan

from .gateway import render_gateway
from .identity import TLSIdentity
from .transaction import CertificateStore, StoredPair, publish_gateway, read_gateway_config


_HEADER = b"# kvn-v5-tls-index "
_DIGEST = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


def _index(config: bytes) -> dict[str, str]:
    if not config.startswith(_HEADER):
        return {}
    try:
        data = json.loads(config.split(b"\n", 1)[0][len(_HEADER):])
    except (ValueError, RecursionError) as exc:
        raise ValueError("Не читается индекс TLS шлюза") from exc
    if (not isinstance(data, dict) or len(data) > 32
            or any(not isinstance(digest, str) or not _DIGEST.fullmatch(digest) for digest in data.values())):
        raise ValueError("Не читается индекс TLS шлюза")
    return data


class GatewayController:
    def __init__(self, config: Path, store: CertificateStore, identities: tuple[TLSIdentity, ...], *, ipv6: bool):
        self.config = config
        self.store = store
        self.identities = identities
        self.ipv6 = ipv6

    @property
    def site_names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.identities if not item.is_ip)

    def _snapshot(self) -> tuple[bytes, dict[str, str], NetworkPlan]:
        current = read_gateway_config(self.config)
        records = _index(current)
        if not set(records).issubset(item.slot for item in self.identities):
            raise ValueError("В индексе TLS есть незарегистрированное имя")
        return current, records, read_routes(current, site_names=self.site_names)

    def _pairs(self, records: dict[str, str]) -> tuple[StoredPair, ...]:
        return tuple(self.store.load(item, records[item.slot]) for item in self.identities if item.slot in records)

    def _render(self, records: dict[str, str], network: NetworkPlan, active: tuple[StoredPair, ...]) -> bytes:
        metadata = _HEADER + json.dumps(records, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        if network.routes:
            metadata += NETWORK_HEADER + encode_routes(network.routes) + b"\n"
        return metadata + render_gateway(self.identities, ipv6=self.ipv6, pairs=active,
                                         network=network).encode("utf-8")

    def active(self) -> tuple[StoredPair, ...]:
        _, records, _ = self._snapshot()
        return self._pairs(records)

    def generation(self, identity: TLSIdentity) -> str | None:
        _, records, _ = self._snapshot()
        return records.get(identity.slot)

    def network_routes(self) -> NetworkPlan:
        return self._snapshot()[2]

    def preview_routes(self, plan: NetworkPlan) -> bytes:
        network = decode_routes(encode_routes(plan.routes), site_names=self.site_names)
        _, records, _ = self._snapshot()
        return self._render(records, network, self._pairs(records))

    def replace_routes(self, plan: NetworkPlan, *, check: Callable[[Path], None], reload: Callable[[], None],
                       verify_live: Callable[[], None], verify_restored: Callable[[], None],
                       verify_loaded: Callable[[bytes], None] = lambda _: None,
                       reconcile: bool = False) -> None:
        """Изменить маршруты по CAS, сохранив поколения TLS без отдельного файла состояния."""
        network = decode_routes(encode_routes(plan.routes), site_names=self.site_names)
        current, records, previous = self._snapshot()
        if network == previous and not reconcile:
            verify_loaded(current)
            verify_live()
            return
        candidate = self._render(records, network, self._pairs(records))

        def live() -> None:
            verify_loaded(candidate)
            verify_live()

        def restored() -> None:
            verify_loaded(current)
            verify_restored()

        publish_gateway(self.config, candidate, check=check, reload=reload, verify_live=live,
                        verify_restored=restored, expected=current)

    def activate(self, identity: TLSIdentity, chain: bytes, key: bytes, *, check: Callable[[Path], None],
                 reload: Callable[[], None], verify_live: Callable[[StoredPair], None],
                 verify_restored: Callable[[], None]) -> StoredPair:
        if identity not in self.identities:
            raise ValueError("Имя не зарегистрировано на этом шлюзе")
        current, records, network = self._snapshot()
        stored = self.store.stage(identity, chain, key)
        if records.get(identity.slot) == stored.chain.parent.name:
            verify_live(stored)
            return stored
        records[identity.slot] = stored.chain.parent.name
        active = tuple(stored if item == identity else self.store.load(item, records[item.slot])
                       for item in self.identities if item.slot in records)
        config = self._render(records, network, active)
        publish_gateway(self.config, config, check=check, reload=reload, verify_live=lambda: verify_live(stored),
                        verify_restored=verify_restored, expected=current)
        return stored
