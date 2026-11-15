"""Служебная страница консоли и повторная проверка системного пароля."""

from flask import abort, jsonify, render_template, request, session

from v5.core.console.auth import MAX_PASSWORD_BYTES
from v5.core.console.protocol import token

PATH = "/maintenance/console"
SID = "console_sid"


def install_console_routes(app, client, csrf_token, require_csrf, csp):
    def binding():
        if not client.available() or session.get("admin") is not True or not token(session.get(SID)):
            abort(404)
        return session[SID]

    @app.get(PATH)
    def console_page():
        binding()
        response = app.make_response(render_template("console.html", csrf=csrf_token()))
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
