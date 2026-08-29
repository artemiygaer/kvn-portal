"""RPC пользователей KVN, Linux и безопасного экспорта."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    control = dispatcher._control
    return MappingProxyType({
        "state.users": HandlerSpec(lambda _p: control().list_users(), False, frozenset()),
        "state.user": HandlerSpec(lambda p: control().get_user(p.get("name", "")), False, frozenset({"name"})),
        "system.users": HandlerSpec(dispatcher._system_users, False, frozenset()),
        "system.user.create": HandlerSpec(dispatcher._system_user_create, True, frozenset({"username", "password"})),
        "user.activity": HandlerSpec(dispatcher._user_activity, False, frozenset({"name"})),
        "user.file": HandlerSpec(
            lambda p: control().read_user_file(p.get("name", ""), p.get("filename", "")),
            False,
            frozenset({"name", "filename"}),
        ),
        "user.export": HandlerSpec(dispatcher._user_export, False, frozenset({"name", "address_mode"})),
        "state.apply": HandlerSpec(dispatcher._state_apply, True, frozenset({"action", "revision", "fields"})),
        "state.reconcile": HandlerSpec(dispatcher._state_reconcile, True, frozenset()),
        "client.export.settings": HandlerSpec(dispatcher._client_export_settings, False, frozenset()),
        "client.export.update": HandlerSpec(
            dispatcher._client_export_update,
            True,
            frozenset({"revision", "address_mode", "public_ip", "include_alternate"}),
        ),
        "portal.credentials": HandlerSpec(dispatcher._portal_credentials, True, frozenset({"password_hash"})),
        "portal.performance.update": HandlerSpec(
            dispatcher._portal_performance_update,
            True,
            frozenset({"revision", "profile", "monitoring", "background_refresh"}),
        ),
    })
