"""Доступ к наблюдению только в административном сеансе."""

from datetime import datetime, timezone

from flask import abort, flash, redirect, render_template, request, session, url_for

from v5.core.observability.history import WINDOWS
from v5.core.observability.ssh import session_id

from .rpc import AgentUnavailable


def _date(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def register_observability(app, client, lifecycle, csrf_token, require_csrf):
    @app.get("/observability")
    def observability():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        if set(request.args) - {"session"} or len(request.args.getlist("session")) > 1:
            abort(400)
        selected = request.args.get("session")
        if selected is not None and not session_id(selected):
            abort(400)
        try:
            snapshot = client.observe_live(selected)
        except AgentUnavailable:
            return render_template("observability/live.html", data=None, selected=selected), 503
        return render_template("observability/live.html", data=snapshot, selected=selected, date=_date)

    @app.get("/observability/history")
    def observation_history():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        if set(request.args) - {"hours"} or len(request.args.getlist("hours")) > 1:
            abort(400)
        hours = request.args.get("hours", "1")
        if hours not in {str(item) for item in WINDOWS}:
            abort(400)
        try:
            state = lifecycle.history_status()
            data = client.observe_history(int(hours))
        except AgentUnavailable:
            return render_template("observability/history.html", state=None, data=None, hours=int(hours),
                                   windows=WINDOWS, date=_date, csrf=csrf_token()), 503
        return render_template("observability/history.html", state=state, data=data, hours=int(hours),
                               windows=WINDOWS, date=_date, csrf=csrf_token())

    @app.post("/observability/history")
    def observation_history_change():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        action = request.form.get("action")
        if action not in ("enable", "disable") or (action == "disable" and request.form.get("confirm") != "yes"):
            abort(400)
        try:
            lifecycle.history_configure(action == "enable")
            flash("Сбор истории включён." if action == "enable" else "Сбор выключен, история удалена.")
        except AgentUnavailable:
            flash("Не удалось подтвердить изменение. Проверьте состояние службы.", "error")
        return redirect(url_for("observation_history"), code=303)
