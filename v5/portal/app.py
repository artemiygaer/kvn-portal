"""Первый вход и компактная сводка без Docker, VPN и фоновой истории."""

import hmac
from io import BytesIO
import json
import os
from pathlib import Path
import secrets
import threading
import time
from datetime import timedelta

from flask import Flask, Request, Response, abort, flash, make_response, redirect, render_template, request, session, url_for

from v5.core.contracts import CORE_API_VERSION, MODULE_IDS
from v5.core.credentials import verify_admin_password
from v5.core.lifecycle import LIFECYCLE_SOCKET
from v5.core.migration import MAX_MIGRATION_FORM
from v5.core.maintenance import UPDATE_SOCKET
from v5.core.maintenance.core_bundle import MAX_BUNDLE
from v5.core.packages import PACKAGE_SOCKET
from v5.core.packages.manifest import MAX_PACKAGE
from v5.core.release import installed_version
from v5.core.site.document import MAX_HTML_BYTES, MAX_SITE_FORM, SITE_CSP, UnsafeDocument, validate_html
from v5.core.tls.certificates import MAX_CHAIN_BYTES, MAX_KEY_BYTES

from .rpc import AgentRejected, AgentUnavailable, CoreUpdateClient, HostClient, LifecycleClient, PackageClient, UsersClient
from .core_update_routes import register_core_update
from .console_client import ConsoleClient
from .console_routes import SID as CONSOLE_SID, install_console_routes
from .migration_client import MigrationClient
from .migration_routes import register_migration
from .log_routes import register_logs
from .observability_routes import register_observability
from .security import LoginBudget
from .user_routes import register_users

PORTAL_CSP = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

TLS_MESSAGES = {
    "active": "Сертификат применён", "unchanged": "Продление пока не требуется",
    "staging_issued": "Проверочный сертификат получен, но не применён",
    "certbot_missing": "Certbot не установлен", "certbot_old": "Нужен Certbot версии 5.4.0 или новее",
    "dns_failed": "DNS не подтвердился. Проверьте A/AAAA и их доступность.",
    "challenge_failed": "Проверка HTTP-01 не прошла. Проверьте TCP/80 и DNS.",
    "rate_limited": "Сработал лимит CA. Повторите позже.", "acme_timeout": "CA не ответил вовремя",
    "acme_failed": "Ошибка выпуска ACME", "lineage_invalid": "Недопустимое хранилище Certbot",
    "lineage_missing": "Certbot не сохранил пару", "san_mismatch": "Сертификат выпущен для другого имени или IP",
    "invalid_certificate": "Цепочка сертификатов повреждена или имеет неверный формат",
    "invalid_key": "Нужен корректный незашифрованный закрытый ключ PEM",
    "openssl_failed": "Не удалось проверить сертификат средствами OpenSSL",
    "untrusted_chain": "Цепочка сертификата не доверена", "key_mismatch": "Ключ не соответствует сертификату",
    "expires_too_soon": "Сертификат просрочен или скоро истекает", "not_yet_valid": "Срок действия ещё не начался",
    "config_invalid": "Конфигурация nginx не прошла проверку", "apply_rolled_back": "Прежняя конфигурация восстановлена",
    "rollback_unconfirmed": "Не удалось подтвердить откат. Проверьте службы через SSH.",
    "tls_state_error": "Ошибка состояния TLS", "revision_changed": "Конфигурация уже изменилась; повторите операцию",
}

PACKAGE_MESSAGES = {
    "publisher_not_configured": "Ключ издателя ещё не настроен. Для установки нужен доверенный ключ.",
    "insecure_publisher_pin": "Недопустимые права или формат файла доверия.",
    "github_unavailable": "GitHub недоступен. Можно загрузить штатный архив вручную.",
    "github_asset_not_found": "В выбранном релизе нет этой версии модуля.",
    "github_asset_missing_digest": "GitHub не вернул SHA-256 файла. Используйте проверенный локальный архив.",
    "invalid_github_release": "Укажите стабильный релиз v5 с этим пакетом.",
    "invalid_package_signature": "Подпись не совпадает с доверенным ключом издателя.",
    "package_expired": "Срок действия подписанного пакета истёк.",
    "incompatible_package": "Пакет несовместим с этой версией ядра.",
    "archive_hash_mismatch": "SHA-256 архива не совпадает.",
    "resource_hash_mismatch": "Содержимое пакета не совпадает с подписью.",
    "package_prepare_busy": "Другой архив уже проверяется.",
    "prepared_package_limit": "Лимит подготовленных архивов достигнут. Записи действуют сутки.",
    "package_disk_space": "На диске не хватает места для безопасной проверки архива.",
    "unknown_prepared_package": "Подготовленный пакет не найден или устарел.",
    "package_downgrade": "Старая версия не устанавливается поверх новой. Используйте откат.",
    "module_version_conflict": "Та же версия уже зарегистрирована с другим содержимым.",
    "module_must_be_disabled": "Сначала отключите модуль.",
    "module_reconcile_required": "Сначала восстановите незавершённую сетевую операцию.",
    "no_rollback_package": "Предыдущий пакет для отката не сохранён.",
    "module_not_installed": "Сначала установите подписанный пакет модуля.",
    "module_must_be_enabled": "Для выключенного модуля используйте обычную установку пакета.",
    "module_operation_busy": "Модуль уже выполняет другую операцию. Повторите позже.",
    "adapter_unavailable": "В этой версии ядра ещё нет адаптера модуля.",
    "xray_profiles_required": "Для Xray сначала создайте начальный профиль на странице модулей.",
    "xray_already_configured": "Настройки Xray уже существуют; данные и ключи не изменены.",
    "xray_settings_invalid": "Проверьте режим, адрес SNI, цель и путь Xray.",
    "xray_profile_conflict": "Такой протокол или SNI уже используется профилем Xray.",
    "xray_profile_changed": "Профиль уже изменился. Обновите страницу и повторите действие.",
    "xray_profile_in_use": "Профиль назначен пользователям. Сначала отзовите соответствующий доступ.",
    "xray_tls_required": "Для выбранного TLS-профиля нужен действующий сертификат.",
    "docker_unavailable": "Docker CLI или служба Docker недоступны.",
    "provision_busy": "Другая системная операция ещё выполняется. Дождитесь её завершения.",
    "provision_index_failed": "Не удалось проверить индексы Debian. Проверьте сеть и время сервера.",
    "provision_simulation_failed": "Зависимости несовместимы или отсутствуют заголовки текущего ядра; установка не начиналась.",
    "provision_install_incomplete": "Установка пакетов завершилась с ошибкой. Проверьте состояние dpkg через SSH до повторной попытки.",
    "provision_timeout_check_dpkg": "Время ожидания истекло. Проверьте состояние dpkg через SSH до повторной попытки.",
    "provision_existing_tools": "Обнаружена нестандартная установка; портал не будет её заменять.",
    "provision_unconfirmed": "Результат фоновой задачи не подтверждён. Проверьте состояние dpkg через SSH.",
    "unsupported_debian": "Автоматическая подготовка поддерживает только Debian 12 и 13.",
    "docker_pull_failed": "Образ по закреплённому digest недоступен. Проверьте сеть или загрузите офлайн-пакет.",
    "docker_load_failed": "Docker не смог загрузить проверенный образ из архива.",
    "network_apply_rolled_back": "Модуль не прошёл проверку; прежнее состояние восстановлено.",
    "module_upgrade_rolled_back": "Новая версия не прошла проверку; рабочая версия восстановлена.",
    "module_upgrade_rollback_unconfirmed": "Откат не подтверждён. Проверьте состояние через SSH.",
    "publication_port_unavailable": "Порт модуля уже занят другой службой.",
    "sni_conflict": "Такое имя SNI уже используется другой службой или страницей.",
    "publication_conflict": "Настройки модулей требуют одну и ту же несовместимую привязку порта.",
    "mtproto_settings_required": "Сначала создайте настройки MTProto на странице модуля.",
    "mtproto_already_configured": "MTProto уже настроен; существующие пользователи и секреты не изменены.",
    "mtproto_settings_invalid": "Проверьте имя SNI, режим сайта и способ подключения MTProto.",
    "mtproto_settings_changed": "Настройки уже изменились. Обновите страницу и повторите действие.",
    "hysteria_settings_changed": "Настройки Hysteria2 изменились. Обновите страницу и повторите действие.",
    "forwarding_egress_required": "Сначала создайте настройки туннеля с интерфейсом выхода в интернет.",
    "forwarding_enable_unconfirmed": "Не удалось подтвердить включение пересылки. Проверьте её состояние на странице.",
    "forwarding_state_unavailable": "Состояние пересылки IPv4 недоступно.",
    "hysteria_settings_required": "Сначала создайте настройки Hysteria2 на странице модуля.",
    "hysteria_already_configured": "Hysteria2 уже настроен; существующие ключи и пользователи не изменены.",
    "hysteria_settings_invalid": "Проверьте адрес и порт Hysteria2.",
    "hysteria_tls_identity_unregistered": "Сначала добавьте это имя или IP в настройках HTTPS портала.",
    "tunnel_configuration_required": "Сначала создайте настройки туннеля на странице модуля.",
    "tunnel_configuration_changed": "Настройки туннеля изменились. Обновите страницу и повторите действие.",
    "tunnel_configuration_invalid": "Некорректная версия настроек. Обновите страницу.",
    "tunnel_already_configured": "Туннель уже настроен; существующие ключи и параметры не изменены.",
    "tunnel_key_generation_failed": "Не удалось создать ключ туннеля. Проверьте инструменты и их доступность.",
    "wireguard_tools_missing": "Не установлены инструменты wireguard-tools.",
    "wireguard_kernel_missing": "В текущем ядре недоступен модуль WireGuard.",
    "amneziawg_tools_missing": "Не установлены или недоступны инструменты AmneziaWG.",
    "amneziawg_kernel_missing": "Для текущего ядра не установлен модуль AmneziaWG.",
    "amneziawg_kernel_headers_missing": "Модуль AmneziaWG не найден, заголовки текущего ядра отсутствуют.",
    "amneziawg_profile_unsupported": "Текущая пара kernel/tools не поддерживает выбранный профиль AWG.",
    "tunnel_subnet_conflict": "Подсеть туннеля пересекается с существующей сетью.",
    "tunnel_interface_already_exists": "Имя интерфейса уже занято. Существующий интерфейс не изменён.",
    "tunnel_egress_unavailable": "Выбранный исходящий интерфейс не найден.",
    "tunnel_egress_invalid": "Укажите корректное имя исходящего интерфейса, например eth0.",
    "tunnel_ipv4_forwarding_required": "Для выхода через туннель нужно включить пересылку IPv4 на хосте.",
    "nft_apply_failed": "Не удалось проверить или применить правила nftables.",
}


class PortalRequest(Request):
    max_form_memory_size = 128 * 1024
    max_form_parts = 16

    def _get_file_stream(self, total_content_length, content_type, filename=None, content_length=None):
        if self.path == "/settings/tls/import":
            # Закрытый ключ не сбрасывается файловым парсером во временный каталог web.
            return BytesIO()
        return super()._get_file_stream(total_content_length, content_type, filename, content_length)

    @property
    def max_content_length(self):
        if self.path == "/settings/tls/import":
            return MAX_CHAIN_BYTES + MAX_KEY_BYTES + 32 * 1024
        if self.path in ("/settings/site/preview", "/settings/site/publish"):
            return MAX_SITE_FORM
        if self.path == "/modules/upload":
            return MAX_PACKAGE + 128 * 1024
        if self.path == "/maintenance/update/upload":
            return MAX_BUNDLE + 128 * 1024
        if self.path == "/users/migration/preview":
            return MAX_MIGRATION_FORM
        return 4096


class StatusCache:
    def __init__(self, client, clock=time.monotonic):
        self.client = client
        self.clock = clock
        self.lock = threading.Lock()
        self.until = float("-inf")
        self.status = None

    def get(self):
        with self.lock:
            if self.clock() >= self.until:
                try:
                    self.status = self.client.status()
                except AgentUnavailable:
                    self.status = None
                self.until = self.clock() + 3
            return self.status


def create_app(config=None, *, client=None, login_budget=None, package_client=None, lifecycle_client=None,
               users_client=None, migration_client=None, console_client=None, core_update_client=None):
    if config is None:
        path = Path(os.environ.get("KVN_V5_WEB_CONFIG", "/etc/kvn-v5/web/config.json"))
        config = json.loads(path.read_text(encoding="utf-8"))
    app = Flask(__name__)
    # Прокси очищает пользовательский заголовок и задаёт собственный префикс.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=0, x_proto=0, x_host=0, x_port=0, x_prefix=1)
    app.request_class = PortalRequest
    app.config.update(
        SECRET_KEY=config["session_key"],
        SESSION_COOKIE_NAME="__Host-kvn-v5",
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_PATH="/",
        SESSION_REFRESH_EACH_REQUEST=False,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        MAX_CONTENT_LENGTH=4096,
    )
    hosts = frozenset(config["allowed_hosts"])
    budget = login_budget if login_budget is not None else LoginBudget()
    backend = client if client is not None else HostClient(Path(config["agent_socket"]))
    packages = package_client if package_client is not None else PackageClient(PACKAGE_SOCKET, timeout=345)
    lifecycle = (lifecycle_client if lifecycle_client is not None
                 else LifecycleClient(LIFECYCLE_SOCKET, timeout=346))
    core_updates = core_update_client if core_update_client is not None else CoreUpdateClient(UPDATE_SOCKET)
    users = users_client if users_client is not None else UsersClient(LIFECYCLE_SOCKET)
    migration = migration_client if migration_client is not None else MigrationClient()
    status_packages = packages.status if package_client is not None else getattr(backend, "package_status", packages.status)
    package_slot = threading.Lock()
    cache = StatusCache(backend)
    console = console_client if console_client is not None else ConsoleClient()

    @app.before_request
    def check_host_and_origin():
        if request.host.lower() not in hosts:
            abort(400)
        if request.method == "POST" and request.headers.get("Origin") != "https://" + request.host.lower():
            abort(403)
        if request.content_length is not None and request.content_length > request.max_content_length:
            abort(413)

    @app.after_request
    def harden(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        # no-referrer превращает Origin штатной HTML-формы в null.
        # same-origin сохраняет строгую проверку POST без Referer на чужих сайтах.
        response.headers["Referrer-Policy"] = ("no-referrer" if request.path.startswith("/sub/")
                                              or request.path == "/settings/site/preview" else "same-origin")
        response.headers.setdefault("Content-Security-Policy", PORTAL_CSP)
        return response

    def csrf_token():
        return session.setdefault("csrf", secrets.token_urlsafe(24))

    def require_csrf():
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(token.encode(), request.form.get("csrf", "").encode()):
            abort(403)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            require_csrf()
            # Unix upstream доступен только TLS-шлюзу; клиентский заголовок шлюз перезаписывает.
            address = request.headers.get("X-KVN-Client-IP", request.remote_addr or "local")
            if not budget.allow(address) or not budget.scrypt_slot.acquire(blocking=False):
                return render_template("login.html", csrf=csrf_token(), error="Слишком много попыток. Повторите позже."), 429
            try:
                password_ok = verify_admin_password(request.form.get("password", ""), config["password_hash"])
            finally:
                budget.scrypt_slot.release()
            user_ok = hmac.compare_digest(request.form.get("login", "").encode(), config["login"].encode())
            if not (password_ok and user_ok):
                return render_template("login.html", csrf=csrf_token(), error="Неверный логин или пароль."), 401
            budget.clear(address)
            session.clear()
            session.permanent = True
            session["admin"] = True
            session[CONSOLE_SID] = secrets.token_urlsafe(24)
            return redirect(url_for("dashboard"), code=303)
        return render_template("login.html", csrf=csrf_token(), error=None)

    @app.get("/")
    def dashboard():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        installed, status_error = package_snapshot()
        return render_template("dashboard.html", status=cache.get(), csrf=csrf_token(),
                               modules_total=len(MODULE_IDS), installed=installed, package_error=status_error)

    @app.route("/settings/tls", methods=["GET", "POST"])
    def tls_settings():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        if request.method == "POST":
            require_csrf()
            try:
                backend.tls_issue(request.form.get("name", ""), request.form.get("mode", ""), request.form.get("email", ""))
                flash("Задача поставлена в очередь. Обновите страницу, чтобы увидеть результат.")
            except AgentRejected as exc:
                flash({"tls_busy": "Уже выполняется задача TLS.", "invalid_request": "Проверьте имя, режим и email."}
                      .get(exc.code, "Служба TLS недоступна."))
            except AgentUnavailable:
                flash("Служба TLS недоступна.")
            return redirect(url_for("tls_settings"), code=303)
        try:
            tls = backend.tls_status()
        except AgentUnavailable:
            tls = None
        return render_template("tls/settings.html", tls=tls, messages=TLS_MESSAGES, csrf=csrf_token())

    @app.post("/settings/tls/import")
    def tls_import():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        if request.form.get("confirm") != "yes":
            flash("Подтвердите импорт сертификата.")
            return redirect(url_for("tls_settings"), code=303)
        try:
            chain_file, key_file = request.files.get("chain"), request.files.get("key")
            chain = chain_file.stream.read(MAX_CHAIN_BYTES + 1) if chain_file else b""
            key = key_file.stream.read(MAX_KEY_BYTES + 1) if key_file else b""
            if not 1 <= len(chain) <= MAX_CHAIN_BYTES or not 1 <= len(key) <= MAX_KEY_BYTES:
                flash("Выберите цепочку PEM и закрытый ключ допустимого размера.")
            else:
                backend.tls_import(request.form.get("name", ""), chain, key)
                flash("Сертификат передан на проверку. Обновите страницу для результата.")
        except AgentRejected as exc:
            flash("Уже выполняется задача TLS." if exc.code == "tls_busy" else "Не удалось передать сертификат на проверку.")
        except AgentUnavailable:
            flash("Служба TLS недоступна.")
        return redirect(url_for("tls_settings"), code=303)

    @app.post("/settings/tls/diagnose")
    def tls_diagnose():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        try:
            backend.tls_diagnose(request.form.get("name", ""))
            flash("Проверка DNS запущена. Обновите страницу для результата.")
        except AgentRejected as exc:
            flash("Уже выполняется задача TLS." if exc.code == "tls_busy" else "Выберите зарегистрированное DNS-имя.")
        except AgentUnavailable:
            flash("Служба TLS недоступна.")
        return redirect(url_for("tls_settings"), code=303)

    @app.post("/settings/tls/prepare")
    def tls_prepare():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        try:
            backend.tls_prepare()
            flash("Подготовка HTTPS-шлюза запущена. Обновите страницу для проверки результата.")
        except AgentRejected as exc:
            flash("Дождитесь завершения обновления ядра или операции TLS."
                  if exc.code in ("tls_busy", "core_update_busy") else "Не удалось подготовить HTTPS-шлюз.")
        except AgentUnavailable:
            flash("Служба TLS недоступна.")
        return redirect(url_for("tls_settings"), code=303)

    @app.get("/settings/site")
    def site_settings():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        try:
            site = backend.site_status()
        except AgentUnavailable:
            site = None
        return render_template("tls/site.html", site=site, csrf=csrf_token())

    @app.post("/settings/site/<any(preview,publish,reset):action>")
    def site_action(action):
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        try:
            if action == "reset":
                if request.form.get("confirm") != "yes":
                    flash("Подтвердите возврат стандартной страницы.")
                else:
                    backend.site_reset()
                    flash("Стандартная страница восстановлена.")
            else:
                uploaded = request.files.get("html")
                content = uploaded.stream.read(MAX_HTML_BYTES + 1) if uploaded else b""
                validated = validate_html(content)
                if action == "preview":
                    response = Response(validated, content_type="text/html; charset=utf-8")
                    response.headers["Content-Security-Policy"] = SITE_CSP + "; frame-ancestors 'none'"
                    return response
                backend.site_publish(content)
                flash("Публичная страница заменена.")
        except UnsafeDocument as exc:
            flash(str(exc))
        except AgentRejected as exc:
            flash("Служба отклонила HTML." if exc.code == "site_invalid" else "Не удалось применить изменение сайта.")
        except AgentUnavailable:
            flash("Не удалось применить изменение сайта.")
        return redirect(url_for("site_settings"), code=303)

    @app.post("/logout")
    def logout():
        require_csrf()
        if isinstance(session.get(CONSOLE_SID), str):
            console.revoke(session[CONSOLE_SID])
        session.clear()
        return redirect(url_for("login"), code=303)

    def package_snapshot():
        try:
            installed = status_packages()["installed"]
            if not isinstance(installed, (list, tuple)):
                raise AgentUnavailable("invalid_package_status")
            return installed, None
        except AgentRejected as exc:
            return [], PACKAGE_MESSAGES.get(exc.code, "Служба пакетов недоступна.")
        except (AgentUnavailable, KeyError):
            return [], "Служба пакетов недоступна."

    def package_page(prepared=None, diagnostics=None, network_plan=None, busy=False):
        installed, status_error = ([], None) if busy else package_snapshot()
        xray_profiles, xray_error = [], None
        mtproto_profiles, mtproto_errors = {}, set()
        tunnel_profiles, tunnel_errors = {}, set()
        hysteria_profile, hysteria_error = None, False
        known = {'xray', 'wireguard', 'amneziawg', 'hysteria', 'telemt', 'mtg'}
        selected = list(dict.fromkeys(item.get('module') for item in installed
                                      if item.get('module') in known))
        if selected:
            try:
                result = lifecycle.settings_snapshot(selected)
                if (not isinstance(result, dict) or not isinstance(result.get('settings'), dict)
                        or not isinstance(result.get('errors'), list)
                        or any(item not in selected for item in result['errors'])):
                    raise AgentUnavailable('invalid_module_settings')
                values, errors = result['settings'], set(result['errors'])
                for module in selected:
                    value = values.get(module)
                    if module not in values or (value is not None and not isinstance(value, list if module == 'xray' else dict)):
                        errors.add(module)
                xray_profiles = values.get('xray') or []
                if 'xray' in errors:
                    xray_profiles, xray_error = [], 'Не удалось прочитать профили Xray.'
                for module in ('telemt', 'mtg'):
                    if module in errors:
                        mtproto_errors.add(module)
                    elif module in selected:
                        mtproto_profiles[module] = values[module]
                for module in ('wireguard', 'amneziawg'):
                    if module in errors:
                        tunnel_errors.add(module)
                    elif module in selected:
                        tunnel_profiles[module] = values[module]
                if 'hysteria' in selected:
                    hysteria_error = 'hysteria' in errors
                    hysteria_profile = None if hysteria_error else values['hysteria']
            except (AgentUnavailable, AgentRejected, AttributeError):
                xray_error = 'Не удалось прочитать профили Xray.' if 'xray' in selected else None
                mtproto_errors.update(set(selected) & {'telemt', 'mtg'})
                tunnel_errors.update(set(selected) & {'wireguard', 'amneziawg'})
                hysteria_error = 'hysteria' in selected
        provision_job, provision_error = None, None
        forwarding_status, forwarding_error = None, None
        if any(item.get('module') in ('wireguard', 'amneziawg') for item in installed):
            try:
                result = core_updates.forwarding_status()
                if (not isinstance(result, dict) or type(result.get('active')) is not bool
                        or type(result.get('persistent')) is not bool):
                    raise AgentUnavailable('invalid_forwarding_status')
                forwarding_status = result
            except (AgentUnavailable, AttributeError):
                forwarding_error = 'Состояние пересылки IPv4 недоступно.'
        if installed:
            try:
                provision_job = core_updates.provision_status().get("job")
            except (AgentUnavailable, AgentRejected, AttributeError):
                provision_error = "Состояние подготовки зависимостей недоступно."
        response = make_response(render_template("modules.html", installed=installed, status_error=status_error,
                                 prepared=prepared, diagnostics=diagnostics, messages=PACKAGE_MESSAGES,
                                 modules=sorted(MODULE_IDS), csrf=csrf_token(), network_plan=network_plan, busy=busy,
                                 provision_job=provision_job, provision_error=provision_error,
                                 xray_profiles=xray_profiles, xray_error=xray_error,
                                 mtproto_profiles=mtproto_profiles, mtproto_errors=mtproto_errors,
                                 forwarding_status=forwarding_status, forwarding_error=forwarding_error,
                                 tunnel_profiles=tunnel_profiles, tunnel_errors=tunnel_errors,
                                 hysteria_profile=hysteria_profile, hysteria_error=hysteria_error,
                                 prepared_active=bool(prepared and any(item['enabled'] and item['module'] == prepared['module']
                                                                      for item in installed))), 409 if busy else 200)
        response.headers["Content-Security-Policy"] = PORTAL_CSP + "; script-src 'self'"
        return response

    @app.get("/modules")
    def modules_page():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        return package_page()

    @app.get("/maintenance")
    def maintenance():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        try:
            version = installed_version()
        except (OSError, ValueError):
            version = None
        return render_template("maintenance.html", core_api=CORE_API_VERSION, version=version,
                               console_available=console.available() and bool(session.get(CONSOLE_SID)))

    @app.post("/modules/<any(upload,github,install,rollback,remove,enable,disable,upgrade,diagnostics,plan,initialize,change_tunnel,initialize_xray,remove_xray,initialize_hysteria,change_hysteria,initialize_mtproto,change_mtproto,provision,forwarding):action>")
    def module_action(action):
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        if not package_slot.acquire(blocking=False):
            return package_page(busy=True)
        try:
            if action == "upload":
                uploaded = request.files.get("package")
                if not uploaded:
                    flash("Выберите подписанный архив модуля.")
                else:
                    size = uploaded.stream.seek(0, os.SEEK_END)
                    uploaded.stream.seek(0)
                    if not 0 < size <= MAX_PACKAGE:
                        abort(413)
                    return package_page(packages.upload(uploaded.stream, size))
            elif action == "github":
                return package_page(packages.github(request.form.get("module", ""), request.form.get("version", ""),
                                                    request.form.get("tag") or None))
            elif action == "install":
                packages.install(request.form.get("ticket", ""))
                flash("Модуль установлен и выключен.")
            elif action == "diagnostics":
                return package_page(diagnostics=lifecycle.diagnostics(request.form.get("module", "")))
            elif action == "plan":
                return package_page(network_plan=lifecycle.plan(request.form.get("module", "")))
            elif request.form.get("confirm") != "yes":
                flash("Подтвердите операцию.")
            elif action == "provision":
                core_updates.provision_start(request.form.get("module", ""))
                flash("Подготовка зависимостей запущена. Обновите страницу для проверки результата.")
            elif action == "forwarding":
                core_updates.forwarding_enable(request.form.get("module", ""))
                flash("Пересылка IPv4 включена и настроена после перезагрузки.")
            elif action == "initialize":
                result = lifecycle.initialize_tunnel(request.form.get("module", ""), request.form.get("egress", "").strip() or None)
                flash("Начальные настройки созданы. Модуль остаётся выключенным." if result.get("internet_requested")
                      else "Настройки созданы только для подсети туннеля; выход в интернет не настроен.")
            elif action == "change_tunnel":
                lifecycle.change_tunnel(request.form.get("module", ""), request.form.get("egress", "").strip() or None,
                                        request.form.get("revision", ""))
                flash("Настройки сохранены. Повторно передайте конфигурации пользователям.")
            elif action == "initialize_xray":
                kind = request.form.get("kind", "")
                reality = request.form.get("reality", "") if kind != "tls" else None
                external = request.form.get("external_host", "").strip() if reality == "external" else None
                path = request.form.get("path", "").strip() if kind == "reality-xhttp" else None
                operation = request.form.get("profile_action", "initial")
                if operation not in ("initial", "add", "replace"):
                    abort(400)
                arguments = dict(kind=kind, exposure=request.form.get("exposure", ""),
                                 sni=request.form.get("sni", "").strip(), reality=reality,
                                 external_host=external, path=path)
                if operation == "add":
                    arguments["add"] = True
                elif operation == "replace":
                    arguments["revision"] = request.form.get("revision", "")
                lifecycle.initialize_xray(**arguments)
                flash("Профиль Xray сохранён. Модуль остаётся выключенным.")
            elif action == "remove_xray":
                lifecycle.remove_xray(request.form.get("kind", ""), request.form.get("revision", ""))
                flash("Профиль Xray удалён. Остальные настройки и ключи сохранены.")
            elif action in ("initialize_hysteria", "change_hysteria"):
                raw_port = request.form.get("port", "")
                if not raw_port.isascii() or not raw_port.isdecimal() or len(raw_port) > 5:
                    abort(400)
                arguments = (request.form.get("identity", "").strip(), int(raw_port),
                             request.form.get("salamander") == "yes")
                if action == 'change_hysteria':
                    lifecycle.change_hysteria(*arguments, request.form.get('revision', ''))
                    flash("Настройки Hysteria2 сохранены. Повторно передайте конфигурации пользователям.")
                else:
                    lifecycle.initialize_hysteria(*arguments)
                    flash("Начальные настройки Hysteria2 созданы. Модуль остаётся выключенным.")
            elif action == "initialize_mtproto":
                lifecycle.initialize_mtproto(request.form.get("module", ""), request.form.get("sni", "").strip(),
                                             request.form.get("mode", ""), request.form.get("exposure", ""))
                flash("Начальные настройки MTProto созданы. Модуль остаётся выключенным.")
            elif action == "change_mtproto":
                lifecycle.change_mtproto(request.form.get("module", ""), request.form.get("sni", "").strip(),
                                         request.form.get("mode", ""), request.form.get("exposure", ""),
                                         request.form.get("revision", ""))
                flash("Настройки MTProto сохранены. Модуль остаётся выключенным.")
            elif action in ("enable", "disable"):
                result = lifecycle.set_enabled(request.form.get("module", ""), action == "enable")
                flash("Модуль включён." if result.get("enabled") else "Модуль выключен. Настройки сохранены.")
            elif action == "upgrade":
                lifecycle.upgrade(request.form.get("module", ""), request.form.get("ticket", ""))
                flash("Модуль обновлён и прошёл проверку.")
            elif action == "rollback":
                packages.rollback(request.form.get("module", ""))
                flash("Предыдущая версия восстановлена. Модуль выключен.")
            else:
                result = packages.remove(request.form.get("module", ""))
                flash("Пакет удалён. Настройки сохранены.")
                if result.get("cleanup_pending"):
                    flash("Неиспользуемые файлы будут очищены при следующей подготовке пакета.")
        except AgentRejected as exc:
            flash(PACKAGE_MESSAGES.get(exc.code, "Пакет или операция отклонены проверкой."), "error")
        except AgentUnavailable:
            flash("Не удалось подтвердить результат операции. Обновите страницу и проверьте состояние.", "error")
        finally:
            package_slot.release()
        return redirect(url_for("modules_page"), code=303)

    register_users(app, users, csrf_token, require_csrf)
    register_migration(app, migration, csrf_token, require_csrf)
    register_logs(app, backend)
    register_observability(app, backend, lifecycle, csrf_token, require_csrf)
    register_core_update(app, core_updates, csrf_token, require_csrf, PORTAL_CSP)
    install_console_routes(app, console, csrf_token, require_csrf, PORTAL_CSP)
    return app
