"""Встроенный адаптер MTG, не зависит от наличия Telemt."""

from v5.modules.mtproto_common.adapter import MTProtoAdapter

from .settings import MODULE, Settings, render_server, restore_seed


def mtg_adapter(context, **kwargs):
    return MTProtoAdapter(context, MODULE, Settings, render_server, restore_seed=restore_seed, **kwargs)
