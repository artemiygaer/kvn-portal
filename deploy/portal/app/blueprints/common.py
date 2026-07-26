"""Общая безопасная регистрация совместимых portal routes."""

from __future__ import annotations

from flask import Blueprint

from .catalog import ROUTES


def make_compat_blueprint(group: str) -> Blueprint:
    """Создаёт Blueprint, сохраняющий исторические endpoint names.

    Flask обычно добавляет к endpoint имя Blueprint. Портал давно использует
    непредварённые имена в шаблонах и интеграционных тестах, поэтому Blueprint
    регистрирует правила через application setup state с прежними именами.
    """

    blueprint = Blueprint(group, __name__)

    @blueprint.record_once
    def register_routes(state) -> None:
        app = state.app
        views = app.extensions["kvn_portal_views"]
        portal_path = app.config["PORTAL_PATH"]
        for spec in ROUTES:
            if spec.group != group:
                continue
            app.add_url_rule(
                spec.rule.format(portal=portal_path),
                endpoint=spec.endpoint,
                view_func=views[spec.endpoint],
                methods=spec.methods,
            )

    return blueprint
