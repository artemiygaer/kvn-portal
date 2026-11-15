"""Отдельный WireGuard; конфигурации AmneziaWG сюда не передаются."""

from v5.modules.host_tunnel.config import WG, render_client, render_server


def server(settings) -> bytes:
    return render_server(WG, settings)


def client(settings, peer, **options) -> bytes:
    return render_client(WG, settings, peer, **options)
