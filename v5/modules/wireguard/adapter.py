"""Отдельный systemd-адаптер WireGuard."""

from v5.modules.host_tunnel.adapter import TunnelAdapter
from v5.modules.host_tunnel.config import WG


def wireguard_adapter(context):
    return TunnelAdapter(context, WG)
