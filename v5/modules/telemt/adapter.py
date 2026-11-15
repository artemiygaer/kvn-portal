"""Встроенный адаптер Telemt, не зависит от наличия MTG."""

from v5.modules.mtproto_common.adapter import MTProtoAdapter

from .idle import idle_secret
from .settings import MODULE, Settings, render_server
from .users import restore_seed


class TelemtAdapter(MTProtoAdapter):
    def __init__(self, context, **kwargs):
        super().__init__(context, MODULE, Settings, self._render, restore_seed=restore_seed, **kwargs)

    def _render(self, settings, cover):
        idle = None if any(item.enabled for item in settings.accounts) else idle_secret(self.root)
        return render_server(settings, cover, idle=idle)


def telemt_adapter(context, **kwargs):
    return TelemtAdapter(context, **kwargs)
