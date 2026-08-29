"""Команды настройки и диагностики протоколов."""

from .implementation import cmd_amneziawg, cmd_mtproto, cmd_sni_routes, cmd_wireguard

__all__ = ["cmd_amneziawg", "cmd_mtproto", "cmd_sni_routes", "cmd_wireguard"]
