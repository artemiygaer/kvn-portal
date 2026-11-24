"""Управление обновлениями Debian через фиксированные операции локального агента."""

from flask import abort, flash, redirect, render_template, request, session, url_for

from .rpc import AgentRejected, AgentUnavailable

MESSAGES = {
    "system_busy": "Уже выполняется системная операция.",
    "system_plan_changed": "План изменился или устарел. Проверьте обновления заново.",
    "system_reboot_not_required": "Необходимость перезагрузки не подтверждена.",
    "system_dpkg_incomplete": "В dpkg есть незавершённые операции. Проверьте сервер по SSH.",
    "system_failed": "Debian не подтвердил выполнение. Проверьте системный журнал.",
}


def snapshot(client):
    try:
        state = client.system_status()
        return state if isinstance(state, dict) else None
    except (AgentUnavailable, AttributeError):
        return None


def register_system_updates(app, client, csrf_token, require_csrf, verify_admin):
    @app.get("/maintenance/system")
    def system_update_page():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        return render_template("system_updates.html", system=snapshot(client), csrf=csrf_token(), messages=MESSAGES)

    @app.post("/maintenance/system/<action>")
    def system_update_action(action):
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        if action not in ("check", "install", "reboot"):
            abort(404)
        if action != "check" and request.form.get("confirm") != "yes":
            abort(400)
        if action == "reboot" and not verify_admin(request.form.get("admin_password", "")):
            flash("Пароль администратора не принят.", "error")
            return redirect(url_for("system_update_page"), code=303)
        params = ({"plan": request.form.get("plan", ""), "confirm": "yes"} if action == "install" else
                  {"confirm": "yes"} if action == "reboot" else {})
        try:
            client.system_action(action, **params)
            flash({"check": "Проверка запущена.", "install": "Установка запущена. Перезагрузки не будет.",
                   "reboot": "Запрос на перезагрузку принят."}[action])
        except AgentRejected as exc:
            flash(MESSAGES.get(exc.code, "Операция не подтверждена."), "error")
        except AgentUnavailable:
            flash("Системная служба недоступна.", "error")
        return redirect(url_for("system_update_page"), code=303)
