"""Маршруты мониторинга, логов, аудита и внутренних проверок."""

from flask import Blueprint

from .common import register_group_routes


def create_blueprint() -> Blueprint:
    result = Blueprint("diagnostics", __name__)
    result.record_once(lambda state: register_group_routes(state, group="diagnostics"))
    return result


blueprint = create_blueprint()
