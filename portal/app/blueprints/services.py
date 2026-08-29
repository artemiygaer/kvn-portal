"""Маршруты управления сервисами и host-agent операциями."""

from flask import Blueprint

from .common import register_group_routes


def create_blueprint() -> Blueprint:
    result = Blueprint("services", __name__)
    result.record_once(lambda state: register_group_routes(state, group="services"))
    return result


blueprint = create_blueprint()
