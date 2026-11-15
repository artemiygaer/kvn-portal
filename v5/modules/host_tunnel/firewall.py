"""Собственная nftables-таблица для пересылки пакетов каждого туннеля."""

import re

from v5.core.network.nft import Nftables, NftPlan

from .config import AWG, WG, Settings, Tunnel


class TunnelFirewall(Nftables):
    def __init__(self, spec: Tunnel):
        if spec not in (WG, AWG):
            raise ValueError("Неизвестный владелец правил туннеля")
        self.spec = spec
        self.table = f"kvn_v5_{spec.module}"
        self.owner = f"kvn-v5:{spec.module}:"
        self.marker = re.compile(re.escape(self.owner) + r"[0-9a-f]{64}")

    def compile(self, settings: Settings | None) -> NftPlan:
        if settings is None:
            return NftPlan((), 0, self.table, self.owner)
        prefix = f"inet {self.table}"
        interface = self.spec.interface
        chains = [f"add chain {prefix} forward {{ type filter hook forward priority 0; policy accept; }}"]
        rules = []
        if settings.egress:
            ext, subnet = settings.egress, settings.subnet
            chains.append(f"add chain {prefix} source_nat {{ type nat hook postrouting priority 100; policy accept; }}")
            rules.extend((f'add rule {prefix} forward iifname "{interface}" oifname "{ext}" ip saddr {subnet} accept',
                          f'add rule {prefix} forward oifname "{interface}" iifname "{ext}" '
                          f'ip daddr {subnet} ct state established,related accept',
                          f'add rule {prefix} source_nat iifname "{interface}" oifname "{ext}" '
                          f'ip saddr {subnet} masquerade'))
        # Не превращать VPN в неявный транзит, когда IPv4 forwarding включён для другой задачи.
        rules.extend((f'add rule {prefix} forward iifname "{interface}" drop',
                      f'add rule {prefix} forward oifname "{interface}" drop'))
        return NftPlan(tuple(chains + rules), len(rules), self.table, self.owner)
