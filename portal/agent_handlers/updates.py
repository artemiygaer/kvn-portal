"""RPC проверки, загрузки и применения обновлений."""

from types import MappingProxyType

from .contract import HandlerSpec


def handlers(dispatcher):
    return MappingProxyType({
        "project.update.inspect": HandlerSpec(dispatcher._project_update_inspect, False, frozenset({"archive"})),
        "project.release.settings": HandlerSpec(dispatcher._project_release_settings, False, frozenset()),
        "project.release.check": HandlerSpec(dispatcher._project_release_check, False, frozenset()),
        "project.release.prepare": HandlerSpec(
            dispatcher._project_release_prepare,
            True,
            frozenset({"release_id", "asset_id", "asset_sha256"}),
        ),
        "project.update": HandlerSpec(
            dispatcher._project_update,
            True,
            frozenset({"archive", "root_password", "session_owner", "mode", "expected_sha256"}),
        ),
    })
