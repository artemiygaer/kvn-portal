"""Общие session/CSRF/security/audit helpers HTTP-границы портала."""

from __future__ import annotations

import hmac
import json
from functools import wraps
from pathlib import Path

from flask import g, make_response, redirect, render_template, request, url_for

from .security import (
    canonical_ip,
    login_csrf,
    verify_login_csrf,
)


class PortalBoundary:
    """Собирает security policy и безопасный runtime-контекст приложения."""

    def __init__(
        self,
        app,
        storage,
        agent_facade,
        *,
        translations,
        system_labels,
        activity_statuses,
        activity_sources,
        activity_reason_re,
        system_label,
    ) -> None:
        self.app = app
        self.storage = storage
        self.agent_facade = agent_facade
        self.translations = translations
        self.system_labels = system_labels
        self.activity_statuses = activity_statuses
        self.activity_sources = activity_sources
        self.activity_reason_re = activity_reason_re
        self.system_label = system_label

    def install(self) -> None:
        """Подключает boundary hooks и общие template helpers."""

        self.app.before_request(self.protect)
        self.app.after_request(self.security_headers)
        self.app.jinja_env.globals["public_url"] = self.public_url
        self.app.jinja_env.globals["t"] = self.translate

    def now(self) -> int:
        return int(self.app.config["NOW_PROVIDER"]())

    def client_ip(self) -> str:
        return canonical_ip(request.headers.get("X-Real-IP", ""))

    def current_portal_runtime(self) -> dict:
        try:
            state = json.loads(
                Path(self.app.config["USERS_FILE"]).read_text(encoding="utf-8")
            )
        except (OSError, ValueError, TypeError):
            return {}
        portal = state.get("portal", {})
        return portal if isinstance(portal, dict) else {}

    def current_portal_performance(self) -> dict:
        """Читает только безопасные feature flags; старый state — standard."""

        portal = self.current_portal_runtime()
        features = portal.get("features", {})
        if not isinstance(features, dict):
            features = {}
        monitoring = features.get("monitoring", True)
        background_refresh = features.get("background_refresh", True)
        monitoring = monitoring if isinstance(monitoring, bool) else True
        background_refresh = (
            background_refresh if isinstance(background_refresh, bool) else True
        )
        if monitoring and background_refresh:
            profile = "standard"
        elif not monitoring and not background_refresh:
            profile = "light"
        else:
            profile = "custom"
        return {
            "profile": profile,
            "features": {
                "monitoring": monitoring,
                "background_refresh": background_refresh,
            },
        }

    def current_admin_login(self) -> str:
        login_value = self.current_portal_runtime().get(
            "login", self.app.config["ADMIN_LOGIN"]
        )
        if isinstance(login_value, str) and login_value:
            self.app.config["ADMIN_LOGIN"] = login_value
        return self.app.config["ADMIN_LOGIN"]

    def current_admin_password_hash(self) -> str:
        password_hash = self.current_portal_runtime().get(
            "password_hash", self.app.config["ADMIN_PASSWORD_HASH"]
        )
        if isinstance(password_hash, str) and password_hash.startswith("scrypt$"):
            self.app.config["ADMIN_PASSWORD_HASH"] = password_hash
        return self.app.config["ADMIN_PASSWORD_HASH"]

    def public_user_activity(self, data: dict) -> dict:
        """Повторно ограничивает host-agent ответ перед отправкой браузеру."""

        systems = data.get("systems")
        rows = []
        for raw in systems[:16] if isinstance(systems, list) else []:
            if not isinstance(raw, dict):
                continue
            system = raw.get("system")
            status = raw.get("status")
            source = raw.get("source")
            reason = raw.get("reason", "")
            if (
                system not in self.system_labels
                or status not in self.activity_statuses
                or source not in self.activity_sources
                or not isinstance(reason, str)
                or not self.activity_reason_re.fullmatch(reason)
            ):
                continue
            row = {
                "system": system,
                "label": self.system_label(system),
                "status": status,
                "source": source,
                "reason": reason,
            }
            for key in (
                "last_activity",
                "uplink_bytes",
                "downlink_bytes",
                "rx_bytes",
                "tx_bytes",
                "connections",
            ):
                value = raw.get(key)
                if (
                    isinstance(value, int)
                    and not isinstance(value, bool)
                    and 0 <= value <= 2**63 - 1
                ):
                    row[key] = value
            if isinstance(raw.get("online"), bool):
                row["online"] = raw["online"]
            rows.append(row)
        generated_at = data.get("generated_at", 0)
        return {
            "generated_at": generated_at if isinstance(generated_at, int) else 0,
            "privacy": {
                "client_endpoints": "hidden",
                "raw_logs": "excluded",
            },
            "systems": rows,
        }

    @staticmethod
    def public_url(endpoint: str, **values) -> str:
        return url_for(endpoint, **values)

    def translate(self, key: str) -> str:
        lang = getattr(g, "lang", "ru")
        table = self.translations.get(lang, self.translations["ru"])
        return table.get(key, self.translations["ru"].get(key, key))

    def require_session(self, view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if g.session is None:
                return redirect(self.public_url("login"))
            return view(*args, **kwargs)

        return wrapper

    def protect(self):
        g.lang = request.cookies.get("kvn_lang", "ru")
        if g.lang not in self.translations:
            g.lang = "ru"
        timestamp = self.now()
        if timestamp >= self.app.extensions["kvn_next_cleanup"]:
            cleanup_lock = self.app.extensions["kvn_cleanup_lock"]
            if cleanup_lock.acquire(blocking=False):
                try:
                    if timestamp >= self.app.extensions["kvn_next_cleanup"]:
                        self.storage.cleanup(timestamp)
                        self.app.extensions["kvn_next_cleanup"] = (
                            timestamp
                            + int(self.app.config["STORAGE_CLEANUP_INTERVAL"])
                        )
                finally:
                    cleanup_lock.release()
        if request.path.startswith("/internal/"):
            return None
        prefix = self.app.config["PORTAL_PATH"]
        if request.path != prefix and not request.path.startswith(prefix + "/"):
            return make_response("Не найдено", 404)
        supplied = request.headers.get("X-KVN-Proxy-Secret", "")
        expected = self.app.config["PROXY_SECRET"]
        if not expected or not hmac.compare_digest(supplied, expected):
            return make_response("Не найдено", 404)
        if request.headers.get("X-Forwarded-Proto") != "https":
            return make_response("Требуется HTTPS", 400)
        try:
            g.client_ip = self.client_ip()
        except ValueError:
            return make_response("Некорректный адрес клиента", 400)
        if request.endpoint is None:
            return make_response("Не найдено", 404)
        if request.endpoint == "login":
            retry_after = self.storage.lock_status(g.client_ip, self.now())
            if retry_after:
                response = make_response(
                    render_template(
                        "login.html",
                        error=(
                            "Слишком много попыток. "
                            "Доступ временно заблокирован."
                        ),
                        csrf_token="",
                    ),
                    429,
                )
                response.headers["Retry-After"] = str(retry_after)
                return response
        token = request.cookies.get(self.app.config["SESSION_COOKIE_NAME"], "")
        g.session_token = token
        g.session = self.storage.get_session(
            token,
            self.now(),
            ip=g.client_ip,
            user_agent=request.headers.get("User-Agent", ""),
        )
        if request.method in {"POST", "PATCH", "DELETE"}:
            # Заголовок первым: raw-upload не разбирается как multipart/form-data.
            csrf_token = (
                request.headers.get("X-CSRF-Token", "")
                or request.form.get("csrf_token", "")
            )
            if request.endpoint == "login":
                if not verify_login_csrf(
                    csrf_token,
                    self.app.config["PROXY_SECRET"],
                    g.client_ip,
                    self.now(),
                ):
                    return (
                        render_template(
                            "error.html",
                            code=403,
                            message="Проверка формы не пройдена.",
                        ),
                        403,
                    )
            elif g.session is None or not hmac.compare_digest(
                csrf_token, g.session["csrf_token"]
            ):
                return (
                    render_template(
                        "error.html",
                        code=403,
                        message="Проверка формы не пройдена.",
                    ),
                    403,
                )
        return None

    @staticmethod
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'; object-src 'none'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if request.headers.get("X-Forwarded-Proto") == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response
