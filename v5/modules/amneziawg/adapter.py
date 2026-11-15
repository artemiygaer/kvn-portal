"""Отдельный systemd-адаптер AmneziaWG."""

from v5.modules.host_tunnel.adapter import TunnelAdapter
from v5.modules.host_tunnel.config import AWG


def amneziawg_adapter(context):
    return TunnelAdapter(context, AWG)
