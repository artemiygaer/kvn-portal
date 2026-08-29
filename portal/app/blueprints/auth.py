"""Маршруты входа и выхода."""

from flask import Blueprint

from .common import register_group_routes


def create_blueprint() -> Blueprint:
    result = Blueprint("auth", __name__)
    result.record_once(lambda state: register_group_routes(state, group="auth"))
    return result


blueprint = create_blueprint()
