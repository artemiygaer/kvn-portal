"""Двухфазные маршруты проверки, подготовки и запуска обновления."""

from flask import Blueprint

from .common import register_group_routes


UPDATE_ENDPOINTS = frozenset({
    "project_update_prepare",
    "project_release_check",
    "project_release_prepare",
    "project_update_start",
    "project_update_discard",
})


def create_blueprint() -> Blueprint:
    result = Blueprint("updates", __name__)
    result.record_once(lambda state: register_group_routes(
        state,
        group="settings",
        endpoints=UPDATE_ENDPOINTS,
    ))
    return result


blueprint = create_blueprint()
