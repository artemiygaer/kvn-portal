"""Единая модель desktop/mobile/command navigation портала."""

from __future__ import annotations


NAVIGATION_ITEMS = (
    {
        "endpoint": "dashboard",
        "label": "dashboard",
        "description": "overview_subtitle",
        "keywords": "dashboard status metrics сводка метрики",
        "primary": True,
        "active": ("dashboard", "dashboard_json", "metrics_history_json"),
    },
    {
        "endpoint": "users_list",
        "label": "users",
        "description": "manage_users",
        "keywords": "users пользователи клиенты",
        "primary": True,
        "active_prefixes": ("user",),
        "active": ("reconcile_state",),
    },
    {
        "endpoint": "services_list",
        "label": "services",
        "description": "service_actions",
        "keywords": "services сервисы apply restart wireguard amneziawg",
        "primary": True,
        "active_prefixes": ("service",),
    },
    {
        "endpoint": "settings_view",
        "label": "settings",
        "description": "settings_hint",
        "keywords": "settings настройки sni update portal",
        "primary": True,
        "active": (
            "settings_view",
            "project_update_prepare",
            "project_release_check",
            "project_release_prepare",
            "project_update_start",
            "project_update_discard",
        ),
    },
    {
        "endpoint": "network_view",
        "label": "network",
        "description": "network_hint",
        "keywords": "network сеть topology ingress routing protocols sni ports",
        "primary": False,
        "active_prefixes": ("network_",),
        "active": ("network_view", "network_json"),
    },
    {
        "endpoint": "logs_view",
        "label": "logs",
        "description": "log_diagnostics",
        "keywords": "logs логи journal docker",
        "primary": False,
        "active": ("logs_view", "logs_json"),
    },
    {
        "endpoint": "root_shell_view",
        "label": "root_shell_nav",
        "description": "root_shell_hint",
        "keywords": "shell root консоль terminal pty",
        "primary": False,
        "active_prefixes": ("terminal_shell_",),
        "active": ("root_shell_view",),
    },
    {
        "endpoint": "terminal_view",
        "label": "terminal",
        "description": "terminal_hint",
        "keywords": "commands console команды обслуживание maintenance",
        "primary": False,
        "active": ("terminal_view",),
    },
    {
        "endpoint": "certificates_view",
        "label": "certificates",
        "description": "certificates_hint",
        "keywords": "certificates сертификаты letsencrypt tls",
        "primary": False,
        "active_prefixes": ("certificate",),
    },
    {
        "endpoint": "health_view",
        "label": "health",
        "description": "health_checks",
        "keywords": "health диагностика check",
        "primary": False,
        "active": ("health_view",),
    },
    {
        "endpoint": "audit_view",
        "label": "audit",
        "description": "audit",
        "keywords": "audit аудит events security",
        "primary": False,
        "active_prefixes": ("audit",),
    },
    {
        "endpoint": "backups_view",
        "label": "backups",
        "description": "backups_hint",
        "keywords": "backup бэкап archive restore",
        "primary": False,
        "active_prefixes": ("backup",),
    },
    {
        "endpoint": "project_info",
        "label": "project",
        "description": "project_hint",
        "keywords": "project docs commands deploy",
        "primary": False,
        "active": ("project_info",),
    },
)


def navigation_active(item: dict, endpoint: str | None) -> bool:
    """Проверяет активный пункт без логики в трёх шаблонных списках."""

    if not endpoint:
        return False
    if endpoint in item.get("active", ()):
        return True
    return any(endpoint.startswith(prefix) for prefix in item.get("active_prefixes", ()))


def navigation_group_active(
    items: tuple[dict, ...], endpoint: str | None, *, primary: bool
) -> bool:
    return any(
        item.get("primary") is primary and navigation_active(item, endpoint)
        for item in items
    )
