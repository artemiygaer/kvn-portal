"""Регистрация модульных HTTP-границ портала."""

from __future__ import annotations

from flask import Flask

from .auth import blueprint as auth_blueprint
from .diagnostics import blueprint as diagnostics_blueprint
from .services import blueprint as services_blueprint
from .settings import blueprint as settings_blueprint
from .users import blueprint as users_blueprint


BLUEPRINTS = (
    auth_blueprint,
    users_blueprint,
    services_blueprint,
    diagnostics_blueprint,
    settings_blueprint,
)


def register_blueprints(app: Flask) -> None:
    """Подключает все группы ровно один раз."""

    for blueprint in BLUEPRINTS:
        app.register_blueprint(blueprint)
