"""Единый каталог совместимых HTTP-маршрутов портала.

Blueprint-модули используют этот каталог для регистрации старых endpoint names
без дублирования URL и без изменения внешнего HTTP-контракта.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteSpec:
    """Описание одного маршрута, независимое от runtime portal path."""

    group: str
    rule: str
    endpoint: str
    methods: tuple[str, ...]


ROUTES = (
    RouteSpec("auth", "{portal}/login", "login", ("GET", "POST")),
    RouteSpec("auth", "{portal}/logout", "logout", ("POST",)),
    RouteSpec("services", "{portal}/", "dashboard", ("GET",)),
    RouteSpec("services", "{portal}/network", "network_view", ("GET",)),
    RouteSpec("services", "{portal}/network.json", "network_json", ("GET",)),
    RouteSpec("services", "{portal}/network/protocol/apply", "network_protocol_apply", ("POST",)),
    RouteSpec("services", "{portal}/network/sni/apply", "network_sni_apply", ("POST",)),
    RouteSpec("diagnostics", "{portal}/dashboard.json", "dashboard_json", ("GET",)),
    RouteSpec("diagnostics", "{portal}/metrics/history.json", "metrics_history_json", ("GET",)),
    RouteSpec("settings", "{portal}/settings/update/prepare", "project_update_prepare", ("POST",)),
    RouteSpec("settings", "{portal}/settings/update/github/check", "project_release_check", ("POST",)),
    RouteSpec("settings", "{portal}/settings/update/github/prepare", "project_release_prepare", ("POST",)),
    RouteSpec("settings", "{portal}/settings/update/start", "project_update_start", ("POST",)),
    RouteSpec("settings", "{portal}/settings/update/discard", "project_update_discard", ("POST",)),
    RouteSpec("services", "{portal}/terminal/shell/open", "terminal_shell_open", ("POST",)),
    RouteSpec("services", "{portal}/terminal/shell/read", "terminal_shell_read", ("POST",)),
    RouteSpec("services", "{portal}/terminal/shell/write", "terminal_shell_write", ("POST",)),
    RouteSpec("services", "{portal}/terminal/shell/resize", "terminal_shell_resize", ("POST",)),
    RouteSpec("services", "{portal}/terminal/shell/close", "terminal_shell_close", ("POST",)),
    RouteSpec("services", "{portal}/shell", "root_shell_view", ("GET",)),
    RouteSpec("users", "{portal}/users", "users_list", ("GET",)),
    RouteSpec("services", "{portal}/services", "services_list", ("GET",)),
    RouteSpec("services", "{portal}/services/<service>/action", "service_action", ("POST",)),
    RouteSpec("diagnostics", "{portal}/logs", "logs_view", ("GET",)),
    RouteSpec("diagnostics", "{portal}/logs.json", "logs_json", ("GET",)),
    RouteSpec("services", "{portal}/terminal", "terminal_view", ("GET", "POST")),
    RouteSpec("services", "{portal}/certificates", "certificates_view", ("GET",)),
    RouteSpec("services", "{portal}/certificates/action", "certificate_action", ("POST",)),
    RouteSpec("diagnostics", "{portal}/health", "health_view", ("GET",)),
    RouteSpec("diagnostics", "{portal}/audit", "audit_view", ("GET",)),
    RouteSpec("diagnostics", "{portal}/audit/export.csv", "audit_export", ("GET",)),
    RouteSpec("services", "{portal}/backups", "backups_view", ("GET", "POST")),
    RouteSpec("services", "{portal}/backups/files/<filename>", "backup_download", ("GET",)),
    RouteSpec("services", "{portal}/project", "project_info", ("GET",)),
    RouteSpec("users", "{portal}/users/new", "user_create", ("GET", "POST")),
    RouteSpec("users", "{portal}/users/<name>", "user_detail", ("GET",)),
    RouteSpec("users", "{portal}/users/<name>/activity.json", "user_activity_json", ("GET",)),
    RouteSpec("users", "{portal}/users/<name>/edit", "user_edit", ("GET", "POST")),
    RouteSpec("users", "{portal}/users/<name>/action", "user_action", ("POST",)),
    RouteSpec("users", "{portal}/users/<name>/toggle", "user_toggle", ("POST",)),
    RouteSpec("users", "{portal}/reconcile", "reconcile_state", ("POST",)),
    RouteSpec("settings", "{portal}/settings", "settings_view", ("GET", "POST")),
    RouteSpec("users", "{portal}/users/<name>/export.zip", "user_export_zip", ("GET",)),
    RouteSpec("users", "{portal}/users/<name>/export.txt", "user_export_text", ("GET",)),
    RouteSpec("users", "{portal}/users/<name>/files/<filename>", "user_download", ("GET",)),
    RouteSpec("users", "{portal}/users/<name>/files/<filename>/inline", "user_inline_file", ("GET",)),
    RouteSpec("users", "{portal}/users/<name>/files/<filename>/view", "user_file_preview", ("GET",)),
    RouteSpec("diagnostics", "/internal/hysteria/auth", "hysteria_auth", ("POST",)),
    RouteSpec("diagnostics", "/internal/health", "internal_health", ("GET",)),
)

ROUTE_ENDPOINTS = frozenset(spec.endpoint for spec in ROUTES)
