"""RPC session-bound root shell без чтения или журналирования содержимого."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    return MappingProxyType({
        "shell.open": HandlerSpec(
            dispatcher._shell_open,
            True,
            frozenset({"root_password", "session_owner", "rows", "cols"}),
        ),
        "shell.read": HandlerSpec(dispatcher._shell_read, False, frozenset({"shell_id", "session_owner"})),
        "shell.write": HandlerSpec(dispatcher._shell_write, True, frozenset({"shell_id", "session_owner", "data"})),
        "shell.resize": HandlerSpec(
            dispatcher._shell_resize,
            True,
            frozenset({"shell_id", "session_owner", "rows", "cols"}),
        ),
        "shell.close": HandlerSpec(dispatcher._shell_close, True, frozenset({"shell_id", "session_owner"})),
    })
