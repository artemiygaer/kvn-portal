"""Карточка VPN-пользователя и выдача уже подтверждённых профилей."""

import re
import subprocess

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, session, url_for

from v5.core.users.model import SubscriptionToken

from .rpc import AgentRejected, AgentUnavailable

_LABELS = {"xray": "Xray", "hysteria": "Hysteria2", "wireguard": "WireGuard",
           "amneziawg": "AmneziaWG", "telemt": "Telemt", "mtg": "MTG"}
_STATUS = {"not_granted": "Нет права", "revoked": "Отозвано", "revoking": "Отзыв ожидает применения",
           "awaiting_install": "Ожидает установки", "disabled": "Модуль выключен", "pending": "Ожидает применения",
           "active": "Активно", "error": "Не подтверждено", "unsupported": "Модуль ещё не выдаёт профили через карточку"}
_ERRORS = {"invalid_user_request": "Некорректные данные, имя уже занято или карточка устарела.",
           "user_apply_failed": "Не удалось подтвердить применение. Проверьте статус и повторите сверку.",
           "user_recovery_required": "Нужно восстановить незавершённую операцию через SSH.",
           "module_operation_busy": "Другая операция с модулем ещё выполняется."}


def qr_png(uri: str) -> bytes:
    if not uri.isascii() or not 1 <= len(uri) <= 2048:
        abort(422)
    try:
        result = subprocess.run(["/usr/bin/qrencode", "-t", "PNG", "-o", "-", "-s", "5"],
                                input=uri.encode("ascii"), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=3, check=True)
    except (OSError, subprocess.SubprocessError):
        abort(503)
    if not result.stdout.startswith(b"\x89PNG\r\n\x1a\n") or len(result.stdout) > 256 * 1024:
        abort(503)
    return result.stdout


def register_users(app, client, csrf_token, require_csrf):
    pages = Blueprint("vpn_users", __name__)

    @pages.before_request
    def require_admin():
        if request.endpoint != "vpn_users.subscription" and session.get("admin") is not True:
            return redirect(url_for("login"), code=303)

    @pages.get("/users")
    def index():
        offset = request.args.get("offset", "0")
        if not re.fullmatch(r"[0-9]{1,3}", offset) or int(offset) > 512:
            abort(404)
        try:
            result = client.users("list", offset=int(offset))
        except AgentUnavailable:
            return render_template("users/list.html", data=None, offset=int(offset), csrf=csrf_token()), 503
        return render_template("users/list.html", data=result, offset=int(offset), csrf=csrf_token())

    @pages.post("/users")
    def create():
        require_csrf()
        try:
            created = client.users("create", name=request.form.get("name", ""))
        except AgentRejected as exc:
            flash(_ERRORS.get(exc.code, "Не удалось создать пользователя."))
        except AgentUnavailable:
            flash("Служба пользователей недоступна.")
        else:
            return redirect(url_for("vpn_users.detail", user_id=created["id"]), code=303)
        return redirect(url_for("vpn_users.index"), code=303)

    def detail_data(user_id):
        try:
            return client.users("detail", id=user_id)
        except AgentRejected as exc:
            abort(404 if exc.code in {"user_not_found", "invalid_user_request"} else 503)
        except AgentUnavailable:
            abort(503)

    @pages.get("/users/<user_id>")
    def detail(user_id):
        return render_template("users/detail.html", user=detail_data(user_id), labels=_LABELS,
                               statuses=_STATUS, csrf=csrf_token())

    @pages.post("/users/<user_id>/<any(grant,retry,rotate,revoke):action>")
    def action(user_id, action):
        require_csrf()
        revision = request.form.get("revision", "")
        if not re.fullmatch(r"[1-9][0-9]{0,14}", revision):
            abort(400)
        params = {"id": user_id, "revision": int(revision)}
        if action in {"grant", "retry"}:
            params["module"] = request.form.get("module", "")
        if action == "grant":
            enabled = request.form.get("enabled")
            if enabled not in {"yes", "no"}:
                abort(400)
            params["enabled"] = enabled == "yes"
        try:
            result = client.users(action, **params)
        except AgentRejected as exc:
            flash(_ERRORS.get(exc.code, "Операция отклонена."))
        except AgentUnavailable:
            flash("Ответ не получен. Проверьте состояние карточки, прежде чем повторять операцию.")
        else:
            if action == "rotate":
                link = "https://" + request.host.lower() + url_for("vpn_users.subscription", token=result["token"])
                return render_template("users/token.html", link=link, user_id=user_id)
            flash("Запрос сохранён. Актуальное состояние указано рядом с модулем." if action in {"grant", "retry"}
                  else "Токен отозван.")
        return redirect(url_for("vpn_users.detail", user_id=user_id), code=303)

    def profiles(user_id):
        try:
            return client.users("profiles", id=user_id)["profiles"]
        except AgentRejected as exc:
            abort(404 if exc.code == "user_not_found" else 503)
        except AgentUnavailable:
            abort(503)

    @pages.get("/users/<user_id>/profiles")
    def profile_page(user_id):
        return render_template("users/profiles.html", profiles=profiles(user_id), user_id=user_id)

    @pages.get("/users/<user_id>/profiles.txt")
    def download(user_id):
        values = profiles(user_id)
        response = Response("\n".join(values) + ("\n" if values else ""), content_type="text/plain; charset=utf-8")
        response.headers["Content-Disposition"] = 'attachment; filename="vpn-profiles.txt"'
        return response

    @pages.get("/users/<user_id>/qr/<int:index>")
    def qr(user_id, index):
        values = profiles(user_id)
        if index >= len(values):
            abort(404)
        return Response(qr_png(values[index]), mimetype="image/png")

    def tunnel_config(user_id, module):
        try:
            return client.users("config", id=user_id, module=module)["config"]
        except AgentRejected as exc:
            abort(404 if exc.code in {"user_not_found", "user_config_unavailable"} else 503)
        except AgentUnavailable:
            abort(503)

    @pages.get("/users/<user_id>/files/<any(wireguard,amneziawg):module>.conf")
    def client_conf(user_id, module):
        response = Response(tunnel_config(user_id, module), content_type="text/plain; charset=utf-8")
        response.headers["Content-Disposition"] = f'attachment; filename="{module}.conf"'
        return response

    @pages.get("/users/<user_id>/files/<any(wireguard,amneziawg):module>.png")
    def client_qr(user_id, module):
        return Response(qr_png(tunnel_config(user_id, module)), mimetype="image/png")

    @pages.get("/sub/<token>")
    def subscription(token):
        try:
            SubscriptionToken(token)
            body = client.users("subscription", token=token)["body"]
        except (AgentUnavailable, ValueError, KeyError):
            abort(404)
        return Response(body, content_type="text/plain; charset=utf-8")

    app.register_blueprint(pages)
