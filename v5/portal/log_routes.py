"""Административный журнал без фонового опроса и выдачи текста служб."""

from flask import abort, redirect, render_template, request, session, url_for

from v5.core.audit import SOURCES

from .rpc import AgentUnavailable

SOURCE_LABELS = {
    "operations": "Операции панели", "gateway": "HTTPS-шлюз", "agent": "Локальный агент",
    "web": "Веб-портал", "tls": "Выпуск сертификатов", "amneziawg": "AmneziaWG", "wireguard": "WireGuard",
    "xray": "Xray", "hysteria": "Hysteria2", "mtg": "MTG", "telemt": "Telemt",
}
OPERATION_LABELS = {
    "package.upload": "Проверка архива", "package.github": "Загрузка пакета с GitHub",
    "package.install": "Установка пакета", "package.rollback": "Откат пакета", "package.remove": "Удаление пакета",
    "lifecycle.enable": "Включение модуля", "lifecycle.disable": "Отключение модуля",
    "lifecycle.upgrade": "Обновление модуля", "lifecycle.initialize": "Начальная настройка туннеля",
    "lifecycle.initialize_xray": "Начальная настройка Xray", "lifecycle.add_xray": "Добавление профиля Xray",
    "lifecycle.replace_xray": "Изменение профиля Xray", "lifecycle.remove_xray": "Удаление профиля Xray",
    "lifecycle.initialize_hysteria": "Начальная настройка Hysteria2",
    "lifecycle.initialize_mtproto": "Начальная настройка MTProto",
    "lifecycle.change_mtproto": "Изменение настроек MTProto",
    "users.create": "Создание пользователя",
    "users.grant": "Изменение доступа", "users.retry": "Повторное применение доступа",
    "users.rotate": "Смена ссылки подписки", "users.revoke": "Отзыв доступа",
    "migration.preview": "Проверка архива переноса", "migration.commit": "Импорт пользователей",
    "migration.rollback": "Откат импорта", "migration.export": "Экспорт пользователей",
    "tls.issue": "Постановка задачи TLS", "site.publish": "Публикация страницы", "site.reset": "Возврат страницы",
    "maintenance.backup": "Приватная копия ядра", "maintenance.reset_admin": "Восстановление доступа через SSH",
    "maintenance.core_update": "Обновление ядра", "maintenance.core_recover": "Откат ядра",
    "provision.prepare": "Подготовка зависимостей",
    "core.forwarding_enable": "Включение пересылки IPv4",
    "lifecycle.change_tunnel": "Изменение настройки туннеля",
    "lifecycle.change_hysteria": "Изменение настройки Hysteria2",
    "console.authorize": "Повторная аутентификация консоли", "console.attach": "Открытие консоли",
}
PRIORITY_LABELS = ("Авария", "Тревога", "Критическое", "Ошибка", "Предупреждение", "Замечание", "Информация", "Отладка")


def register_logs(app, backend):
    @app.get("/logs")
    def logs():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        if set(request.args) - {"source"} or len(request.args.getlist("source")) > 1:
            abort(400)
        source = request.args.get("source", "operations")
        if source not in SOURCES:
            abort(400)
        try:
            rows = backend.journal_recent(source)["entries"]
        except (AgentUnavailable, KeyError):
            rows = None
        return render_template("logs.html", source=source, sources=SOURCE_LABELS, rows=rows,
                               operations=OPERATION_LABELS, priorities=PRIORITY_LABELS), 503 if rows is None else 200
