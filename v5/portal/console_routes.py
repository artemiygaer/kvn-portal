"""Служебная страница консоли и повторная проверка системного пароля."""

from flask import abort, flash, jsonify, redirect, render_template, request, session, url_for

from v5.core.console.auth import MAX_PASSWORD_BYTES
from v5.core.console.protocol import token
from .rpc import AgentRejected, AgentUnavailable

PATH = "/maintenance/console"
SID = "console_sid"


def install_console_routes(app, client, csrf_token, require_csrf, csp, *, controls, verify_admin):
    def binding():
        if not client.available() or session.get("admin") is not True or not token(session.get(SID)):
            abort(404)
        return session[SID]

    @app.get(PATH)
    def console_page():
        if session.get("admin") is not True:
            abort(404)
        available = client.available()
        authenticated = token(session.get(SID))
        response = app.make_response(render_template(
            "console.html", csrf=csrf_token(), available=available, authenticated=authenticated))
        if not available or not authenticated:
            return response
        # xterm формирует стили сетки и символов на лету. Исключение только для CSS этой страницы.
        response.headers["Content-Security-Policy"] = (
            csp.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
            + "; script-src 'self'; connect-src 'self'"
        )
        return response

    @app.post(PATH + "/authorize")
    def console_authorize():
        sid = binding()
        require_csrf()
        password = request.form.get("root_password", "")
        if not 0 < len(password.encode()) <= MAX_PASSWORD_BYTES or "\0" in password:
            return jsonify(error="console_auth_failed"), 403
        result = client.authorize(sid, password)
        del password
        grant = result.get("grant")
        if result.get("ok") is True and token(grant):
            return jsonify(grant=grant)
        if result.get("error") == "console_busy":
            return jsonify(error="console_busy"), 429
        if result.get("error") in ("console_auth_failed", "console_session_revoked"):
            return jsonify(error="console_auth_failed"), 403
        return jsonify(error="console_unavailable"), 503

    @app.post(PATH + "/control")
    def console_control():
        if session.get("admin") is not True or not token(session.get(SID)):
            abort(404)
        require_csrf()
        action = request.form.get("action")
        if action not in ("enable", "disable") or request.form.get("confirm") != "yes":
            abort(400)
        if not verify_admin(request.form.get("admin_password", "")):
            flash("Пароль администратора не принят.", "error")
        else:
            try:
                controls.shell_control(action)
                flash(("Включение" if action == "enable" else "Отключение")
                      + " запрошено. Через несколько секунд обновите страницу; при установке зависимости может потребоваться больше времени.")
            except AgentRejected:
                flash("Не удалось поставить задачу. Возможно, уже выполняется операция Shell или обновление.", "error")
            except AgentUnavailable:
                flash("Служба управления недоступна.", "error")
        return redirect(url_for("console_page"), code=303)
