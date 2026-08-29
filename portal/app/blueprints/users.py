"""Маршруты пользователей и их артефактов."""

from flask import Blueprint

from .common import register_group_routes


def create_blueprint() -> Blueprint:
    result = Blueprint("users", __name__)
    result.record_once(lambda state: register_group_routes(state, group="users"))
    return result


blueprint = create_blueprint()
