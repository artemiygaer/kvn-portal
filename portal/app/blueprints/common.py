"""Общие безопасные примитивы регистрации portal routes."""

from __future__ import annotations

from .catalog import ROUTES


def register_group_routes(state, *, group: str, endpoints: frozenset[str] | None = None) -> None:
    """Регистрирует профильную группу, сохраняя исторические endpoint names."""
    app = state.app
    views = app.extensions["kvn_portal_views"]
    portal_path = app.config["PORTAL_PATH"]
    for spec in ROUTES:
        if spec.group != group or endpoints is not None and spec.endpoint not in endpoints:
            continue
        app.add_url_rule(
            spec.rule.format(portal=portal_path),
            endpoint=spec.endpoint,
            view_func=views[spec.endpoint],
            methods=spec.methods,
        )
