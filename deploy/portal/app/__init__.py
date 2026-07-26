"""Flask application factory портала KVN VPN."""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

from flask import Flask, Request as FlaskRequest

from .agent_facade import AgentFacade
from .boundary import PortalBoundary
from .hysteria_auth import HysteriaUserCache
from .cache import WidgetCache
from .navigation import NAVIGATION_ITEMS, navigation_active, navigation_group_active
from .service_catalog import (
    FILE_KIND_CATALOG,
    GUIDANCE_TOPICS,
    MANAGED_SERVICE_CATALOG,
    MANAGED_SERVICE_ORDER,
    SERVICE_CATALOG,
    SYSTEM_CATALOG,
    client_file_group,
    is_qr_file,
    service_guide,
    system_label,
)
from .storage import PortalStorage


BUILD_ID = "dev"
MANAGED_SERVICES = list(MANAGED_SERVICE_ORDER)
LOG_CONTENT_LIMIT = 256 * 1024
DOCKER_DASHBOARD_SERVICES = [
    guide.key for guide in MANAGED_SERVICE_CATALOG if guide.docker_dashboard
]
PROTOCOL_DASHBOARD_SERVICES = [
    guide.key for guide in MANAGED_SERVICE_CATALOG if guide.protocol_dashboard
]
SERVICE_ACTIONS = {
    action
    for guide in MANAGED_SERVICE_CATALOG
    for action in guide.actions
}
CONFIRMED_SERVICE_ACTIONS = {"stop", "restart", "disable", "apply"}
QR_FILE_KINDS = {
    kind for kind, guide in FILE_KIND_CATALOG.items() if guide.qr
}
USER_SNI_OVERRIDE_SYSTEMS = {
    guide.key for guide in SYSTEM_CATALOG if guide.user_sni
}
BACKUP_FILENAME_RE = re.compile(r"^kvn-vpn-backup-[A-Za-z0-9_.-]+\.tar$")
SYSTEM_LABELS = {
    guide.key: guide.label for guide in SYSTEM_CATALOG
}
USER_ACTIVITY_STATUSES = {"active", "observed", "idle", "stale", "disabled", "unsupported", "unavailable"}
USER_ACTIVITY_SOURCES = {
    "xray-stats", "hysteria-api", "telemt-metrics", "awg-dump", "wg-dump", "occtl",
    "mtg-shared-secret", "xray", "hysteria", "telemt", "mtg", "amneziawg", "wireguard", "ocserv",
}
USER_ACTIVITY_REASON_RE = re.compile(r"^[a-z0-9_-]{0,64}$")
# Render, host sync и controlled restart могут занять больше socket-default 10 с.
# Таймаут остаётся ограниченным и меньше Gunicorn/proxy timeout портала.
STATE_MUTATION_TIMEOUT_SECONDS = 300

def system_labels(systems: list[str]) -> str:
    return ", ".join(system_label(system) for system in systems)

TRANSLATIONS = {
    "ru": {
        "skip": "К основному содержимому",
        "panel": "Панель управления",
        "dashboard": "Сводка",
        "network": "Сеть",
        "network_hint": "Входные порты, маршрутизация и протоколы",
        "users": "Пользователи",
        "services": "Сервисы",
        "logs": "Логи",
        "terminal": "Команды",
        "root_shell_nav": "Консоль",
        "certificates": "Сертификаты",
        "health": "Диагностика",
        "audit": "Аудит",
        "backups": "Бэкапы",
        "project": "Проект",
        "settings": "Настройки",
        "logout": "Выйти",
        "theme": "Тема",
        "login_ip": "IP входа",
        "build": "Сборка",
        "menu": "Меню",
        "advanced": "Дополнительно",
        "command_palette": "Команды",
        "command_hint": "Быстрый переход по разделам",
        "quick_actions": "Быстрые действия",
        "search_command": "Найти раздел",
        "search_command_placeholder": "Пользователи, логи, бэкап...",
        "command_empty": "Ничего не найдено.",
        "confirm_required": "Требуется подтверждение",
        "confirm_action": "Подтвердите действие",
        "cancel": "Отмена",
        "confirm": "Подтвердить",
        "portal_settings": "Настройки портала",
        "language": "Язык интерфейса",
        "russian": "Русский",
        "english": "English",
        "save_language": "Сохранить язык",
        "admin_password": "Пароль администратора",
        "current_password": "Текущий пароль",
        "new_password": "Новый пароль",
        "repeat_password": "Повторите пароль",
        "change_password": "Сменить пароль",
        "password_changed": "Пароль изменён. Войдите заново.",
        "language_saved": "Язык сохранён.",
        "wrong_current_password": "Текущий пароль указан неверно.",
        "passwords_do_not_match": "Новые пароли не совпадают.",
        "password_policy": "Минимум 12 символов.",
        "go_home": "На главную",
        "overview_subtitle": "Нагрузка, доступность и сроки в одном месте",
        "manage_users": "Управлять пользователями",
        "add_user": "Добавить пользователя",
        "create_user_hint": "Создать профиль и выдать доступы",
        "current_status": "Состояние сейчас",
        "refresh_every": "Обновление каждые 20 секунд",
        "load_history": "История нагрузки",
        "history_retention": "Хранится на сервере не более 72 часов",
        "period": "Период",
        "step": "Шаг",
        "one_hour": "1 час",
        "six_hours": "6 часов",
        "twenty_four_hours": "24 часа",
        "three_days": "3 дня",
        "auto": "Авто",
        "one_minute": "1 минута",
        "five_minutes": "5 минут",
        "fifteen_minutes": "15 минут",
        "cpu": "Процессор",
        "memory": "Память",
        "disk": "Диск",
        "network_in": "Входящий трафик",
        "server": "Сервер",
        "containers": "Контейнеры",
        "protocols": "Протоколы",
        "containers_attention": "Требуют внимания",
        "containers_from_health": "По состоянию сервисов",
        "protocol_services_active": "Работающие сервисы протоколов",
        "service_actions": "Запуск, остановка, перечитывание и применение",
        "log_diagnostics": "Диагностика по сервисам",
        "health_checks": "Проверки и рекомендации",
        "certificates_hint": "Выпуск, перевыпуск и проверка TLS",
        "backups_hint": "Архивы проекта и контейнеров",
        "project_hint": "Описание, команды и регламент",
        "settings_hint": "SNI, обновления и параметры портала",
        "terminal_hint": "Root-команды обслуживания из фиксированного списка",
        "terminal_title": "Команды обслуживания",
        "terminal_intro": "Быстрые команды выполняются из фиксированного списка host-agent, без произвольного shell-ввода.",
        "terminal_run": "Выполнить",
        "terminal_confirm": "Выполнить команду обслуживания",
        "terminal_output": "Результат выполнения",
        "terminal_command": "Команда",
        "terminal_no_output": "Команда завершилась без вывода.",
        "terminal_empty": "Команды обслуживания недоступны. Проверьте host-agent.",
        "root_shell_title": "Root shell",
        "root_shell_hint": "Нужен системный пароль root, не пароль админки портала. Сессия привязана к текущему входу.",
        "root_password": "Пароль root",
        "root_connect": "Подключиться",
        "root_disconnect": "Закрыть shell",
        "root_shell_status": "Статус shell",
        "root_shell_output": "Вывод root shell",
        "root_shell_input": "Команда",
        "root_shell_keyboard_hint": "Кликните по окну терминала и вводите команды как в обычной SSH-консоли. Поддерживаются Enter, Tab, стрелки, Backspace, Ctrl+C/Ctrl+D и вставка.",
        "root_shell_warning": "Команды выполняются на сервере от root. Вывод и введённые команды не пишутся в аудит портала.",
        "service_management_hint": "Точечные действия с проверкой результата",
        "filter_services": "Фильтр сервисов",
        "service_search": "Поиск",
        "service_state": "Состояние",
        "service_kind": "Тип",
        "all": "Все",
        "host_service": "Host-служба",
        "docker_service": "Контейнер",
        "service_filters_empty": "Под выбранные фильтры сервисов нет.",
        "running": "работает",
        "stopped": "остановлен",
        "start": "Запустить",
        "reload": "Перечитать",
        "restart": "Перезапустить",
        "stop": "Остановить",
        "enable": "Включить постоянно",
        "disable": "Отключить постоянно",
        "apply": "Применить конфиг",
        "actual": "актуально",
        "unavailable": "недоступно",
        "stale": "устарело",
        "check": "проверьте",
        "no_data": "нет данных",
        },
    "en": {
        "skip": "Skip to main content",
        "panel": "Control panel",
        "dashboard": "Dashboard",
        "network": "Network",
        "network_hint": "Ingress ports, routing, and protocols",
        "users": "Users",
        "services": "Services",
        "logs": "Logs",
        "terminal": "Commands",
        "root_shell_nav": "Shell",
        "certificates": "Certificates",
        "health": "Diagnostics",
        "audit": "Audit",
        "backups": "Backups",
        "project": "Project",
        "settings": "Settings",
        "logout": "Log out",
        "theme": "Theme",
        "login_ip": "Login IP",
        "build": "Build",
        "menu": "Menu",
        "advanced": "Advanced",
        "command_palette": "Commands",
        "command_hint": "Quick section navigation",
        "quick_actions": "Quick actions",
        "search_command": "Find a section",
        "search_command_placeholder": "Users, logs, backup...",
        "command_empty": "Nothing found.",
        "confirm_required": "Confirmation required",
        "confirm_action": "Confirm action",
        "cancel": "Cancel",
        "confirm": "Confirm",
        "portal_settings": "Portal settings",
        "language": "Interface language",
        "russian": "Русский",
        "english": "English",
        "save_language": "Save language",
        "admin_password": "Administrator password",
        "current_password": "Current password",
        "new_password": "New password",
        "repeat_password": "Repeat password",
        "change_password": "Change password",
        "password_changed": "Password changed. Sign in again.",
        "language_saved": "Language saved.",
        "wrong_current_password": "Current password is incorrect.",
        "passwords_do_not_match": "New passwords do not match.",
        "password_policy": "At least 12 characters.",
        "go_home": "Back to dashboard",
        "overview_subtitle": "Load, availability, and expiry dates in one place",
        "manage_users": "Manage users",
        "add_user": "Add user",
        "create_user_hint": "Create a profile and issue access",
        "current_status": "Current status",
        "refresh_every": "Refresh every 20 seconds",
        "load_history": "Load history",
        "history_retention": "Stored on the server for up to 72 hours",
        "period": "Period",
        "step": "Step",
        "one_hour": "1 hour",
        "six_hours": "6 hours",
        "twenty_four_hours": "24 hours",
        "three_days": "3 days",
        "auto": "Auto",
        "one_minute": "1 minute",
        "five_minutes": "5 minutes",
        "fifteen_minutes": "15 minutes",
        "cpu": "CPU",
        "memory": "Memory",
        "disk": "Disk",
        "network_in": "Inbound traffic",
        "server": "Server",
        "containers": "Containers",
        "protocols": "Protocols",
        "containers_attention": "Need attention",
        "containers_from_health": "From service health",
        "protocol_services_active": "Running protocol services",
        "service_actions": "Start, stop, reload, and apply",
        "log_diagnostics": "Service diagnostics",
        "health_checks": "Checks and recommendations",
        "certificates_hint": "Issue, renew, and check TLS",
        "backups_hint": "Project and container archives",
        "project_hint": "Description, commands, and runbook",
        "settings_hint": "SNI, updates, and portal parameters",
        "terminal_hint": "Root maintenance commands from a fixed allowlist",
        "terminal_title": "Maintenance commands",
        "terminal_intro": "Quick commands run from a fixed host-agent allowlist without arbitrary shell input.",
        "terminal_run": "Run",
        "terminal_confirm": "Run maintenance command",
        "terminal_output": "Execution result",
        "terminal_command": "Command",
        "terminal_no_output": "Command completed without output.",
        "terminal_empty": "Maintenance commands are unavailable. Check the host-agent.",
        "root_shell_title": "Root shell",
        "root_shell_hint": "Use the system root password, not the portal admin password. The session is bound to this login.",
        "root_password": "Root password",
        "root_connect": "Connect",
        "root_disconnect": "Close shell",
        "root_shell_status": "Shell status",
        "root_shell_output": "Root shell output",
        "root_shell_input": "Command",
        "root_shell_keyboard_hint": "Click the terminal and type as in a regular SSH console. Enter, Tab, arrows, Backspace, Ctrl+C/Ctrl+D, and paste are supported.",
        "root_shell_warning": "Commands run on the server as root. Output and typed commands are not written to the portal audit.",
        "service_management_hint": "Targeted actions with result checks",
        "filter_services": "Filter services",
        "service_search": "Search",
        "service_state": "State",
        "service_kind": "Type",
        "all": "All",
        "host_service": "Host service",
        "docker_service": "Container",
        "service_filters_empty": "No services match the selected filters.",
        "running": "running",
        "stopped": "stopped",
        "start": "Start",
        "reload": "Reload",
        "restart": "Restart",
        "stop": "Stop",
        "enable": "Enable permanently",
        "disable": "Disable permanently",
        "apply": "Apply config",
        "actual": "current",
        "unavailable": "unavailable",
        "stale": "stale",
        "check": "check",
        "no_data": "no data",
    },
}
SERVICE_UI_ACTIONS = {
    guide.key: list(guide.actions)
    for guide in MANAGED_SERVICE_CATALOG
}


def _load_runtime_config(users_file: Path) -> dict:
    state = json.loads(users_file.read_text(encoding="utf-8"))
    portal = state.get("portal", {})
    if not portal.get("enabled"):
        raise RuntimeError("Портал не включён в users.json.")
    return portal


def create_app(test_config: dict | None = None) -> Flask:
    users_file = Path(os.environ.get("KVN_USERS_FILE", "/project/users.json"))
    runtime = {} if test_config is not None else _load_runtime_config(users_file)
    configured_path = test_config.get("PORTAL_PATH") if test_config else None
    portal_path = (configured_path or runtime.get("path") or "/admin").rstrip("/")
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
        static_url_path=f"{portal_path}/static",
    )
    app.config.update(
        USERS_FILE=users_file,
        DATABASE=Path(os.environ.get("KVN_PORTAL_DB", "/data/portal.db")),
        PORTAL_PATH=portal_path,
        PORTAL_NAME=runtime.get("name", "KVN VPN"),
        ADMIN_LOGIN=runtime.get("login", ""),
        ADMIN_PASSWORD_HASH=runtime.get("password_hash", ""),
        PROXY_SECRET=runtime.get("proxy_secret", ""),
        HYSTERIA_SECRET=runtime.get("hysteria_secret", ""),
        BUILD_ID=os.environ.get("KVN_BUILD_ID", BUILD_ID),
        SESSION_COOKIE_NAME="kvn_portal_session",
        SESSION_COOKIE_SECURE=True,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024 * 1024 + 1024 * 1024,
        NOW_PROVIDER=time.time,
        AGENT_CLIENT=None,
        AGENT_SOCKET=Path("/run/kvn-portal/control.sock"),
        AGENT_SECRET_FILE=Path("/run/secrets/agent-token"),
        UPDATE_UPLOAD_DIR=Path("/data/updates"),
        UPDATE_UPLOAD_RELATIVE_DIR="portal-data/updates",
        UPDATE_UPLOAD_MAX_FILES=6,
        UPDATE_UPLOAD_RETENTION_SECONDS=7 * 24 * 60 * 60,
        UPDATE_UPLOAD_MIN_AGE_SECONDS=24 * 60 * 60,
        UPDATE_UPLOAD_MAX_BYTES=2 * 1024 * 1024 * 1024,
        UPDATE_UPLOAD_DISK_RESERVE_BYTES=512 * 1024 * 1024,
        UPDATE_RPC_TIMEOUT_SECONDS=30 * 60,
        BACKUP_DIR=Path(os.environ.get("KVN_BACKUP_DIR", "/backup")),
        STORAGE_CLEANUP_INTERVAL=5 * 60,
    )
    if test_config:
        app.config.update(test_config)
    app.config["PORTAL_PATH"] = app.config["PORTAL_PATH"].rstrip("/")

    upload_temp_dir = Path(app.config["UPDATE_UPLOAD_DIR"])

    class PortalRequest(FlaskRequest):
        """Размещает multipart-файлы на диске, а не в ограниченном tmpfs контейнера."""

        def _get_file_stream(
            self,
            total_content_length,
            content_type,
            filename=None,
            content_length=None,
        ):
            upload_temp_dir.mkdir(parents=True, exist_ok=True)
            return tempfile.SpooledTemporaryFile(
                max_size=512 * 1024,
                mode="w+b",
                dir=upload_temp_dir,
            )

    app.request_class = PortalRequest
    storage = PortalStorage(Path(app.config["DATABASE"]))
    hysteria_users = HysteriaUserCache(Path(app.config["USERS_FILE"]))
    app.extensions["kvn_storage"] = storage
    app.extensions["kvn_hysteria_users"] = hysteria_users
    app.extensions["kvn_widget_cache"] = WidgetCache()
    app.extensions["kvn_cleanup_lock"] = threading.Lock()
    app.extensions["kvn_next_cleanup"] = 0
    app.jinja_env.globals["system_label"] = system_label
    app.jinja_env.filters["system_labels"] = system_labels
    app.jinja_env.globals["service_catalog"] = SERVICE_CATALOG
    app.jinja_env.globals["system_catalog"] = SYSTEM_CATALOG
    app.jinja_env.globals["managed_service_catalog"] = MANAGED_SERVICE_CATALOG
    app.jinja_env.globals["service_guide"] = service_guide
    app.jinja_env.globals["guidance_topics"] = GUIDANCE_TOPICS
    app.jinja_env.globals["client_file_group"] = client_file_group
    app.jinja_env.globals["is_qr_file"] = is_qr_file
    app.jinja_env.globals["navigation_items"] = NAVIGATION_ITEMS
    app.jinja_env.globals["navigation_active"] = navigation_active
    app.jinja_env.globals["navigation_group_active"] = navigation_group_active

    app.jinja_env.globals["build_id"] = app.config["BUILD_ID"]

    agent_facade = AgentFacade(app)
    boundary = PortalBoundary(
        app,
        storage,
        agent_facade,
        translations=TRANSLATIONS,
        system_labels=SYSTEM_LABELS,
        activity_statuses=USER_ACTIVITY_STATUSES,
        activity_sources=USER_ACTIVITY_SOURCES,
        activity_reason_re=USER_ACTIVITY_REASON_RE,
        system_label=system_label,
    )
    boundary.install()
    app.extensions["kvn_agent_facade"] = agent_facade
    app.extensions["kvn_boundary"] = boundary

    from .blueprints import register_blueprints
    from .blueprints.views import build_views

    app.extensions["kvn_portal_views"] = build_views(
        app=app,
        storage=storage,
        hysteria_users=hysteria_users,
        now=boundary.now,
        agent_client=agent_facade.client,
        current_portal_performance=boundary.current_portal_performance,
        current_admin_login=boundary.current_admin_login,
        current_admin_password_hash=boundary.current_admin_password_hash,
        public_user_activity=boundary.public_user_activity,
        public_url=boundary.public_url,
        translate=boundary.translate,
        require_session=boundary.require_session,
        constants={
            "BACKUP_FILENAME_RE": BACKUP_FILENAME_RE,
            "CONFIRMED_SERVICE_ACTIONS": CONFIRMED_SERVICE_ACTIONS,
            "DOCKER_DASHBOARD_SERVICES": DOCKER_DASHBOARD_SERVICES,
            "LOG_CONTENT_LIMIT": LOG_CONTENT_LIMIT,
            "MANAGED_SERVICES": MANAGED_SERVICES,
            "PROTOCOL_DASHBOARD_SERVICES": PROTOCOL_DASHBOARD_SERVICES,
            "QR_FILE_KINDS": QR_FILE_KINDS,
            "SERVICE_ACTIONS": SERVICE_ACTIONS,
            "SERVICE_UI_ACTIONS": SERVICE_UI_ACTIONS,
            "STATE_MUTATION_TIMEOUT_SECONDS": STATE_MUTATION_TIMEOUT_SECONDS,
            "TRANSLATIONS": TRANSLATIONS,
            "USER_SNI_OVERRIDE_SYSTEMS": USER_SNI_OVERRIDE_SYSTEMS,
        },
    )
    register_blueprints(app)
    app.register_error_handler(404, app.extensions["kvn_portal_views"]["not_found"])
    app.register_error_handler(500, app.extensions["kvn_portal_views"]["internal_error"])
    return app
