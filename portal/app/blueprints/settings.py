"""Маршруты группированных настроек без update-команд."""

from flask import Blueprint

from .common import register_group_routes


SETTINGS_ENDPOINTS = frozenset({"settings_view"})


def create_blueprint() -> Blueprint:
    result = Blueprint("settings", __name__)
    result.record_once(lambda state: register_group_routes(
        state,
        group="settings",
        endpoints=SETTINGS_ENDPOINTS,
    ))
    return result


blueprint = create_blueprint()
