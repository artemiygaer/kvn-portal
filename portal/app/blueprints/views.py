"""Реализации portal views, сгруппированные Blueprints по HTTP-границам."""

from __future__ import annotations

import base64
import csv
import hmac
import io
import ipaddress
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from flask import Response, g, jsonify, make_response, redirect, render_template, request, send_file

try:
    from portal.agent_client import AgentClientError
except ModuleNotFoundError:
    from agent_client import AgentClientError

from ..security import hash_password, login_csrf, token_hash, verify_password
from .catalog import ROUTE_ENDPOINTS


def build_views(
    *,
    app,
    storage,
    hysteria_users,
    now,
    agent_client,
    current_portal_performance,
    current_admin_login,
    current_admin_password_hash,
    public_user_activity,
    public_url,
    translate,
    require_session,
    constants,
) -> dict[str, object]:
    """Создаёт view-функции с явными зависимостями application factory."""

    BACKUP_FILENAME_RE = constants["BACKUP_FILENAME_RE"]
    CONFIRMED_SERVICE_ACTIONS = constants["CONFIRMED_SERVICE_ACTIONS"]
    DOCKER_DASHBOARD_SERVICES = constants["DOCKER_DASHBOARD_SERVICES"]
    LOG_CONTENT_LIMIT = constants["LOG_CONTENT_LIMIT"]
    MANAGED_SERVICES = constants["MANAGED_SERVICES"]
    PROTOCOL_DASHBOARD_SERVICES = constants["PROTOCOL_DASHBOARD_SERVICES"]
    QR_FILE_KINDS = constants["QR_FILE_KINDS"]
    SERVICE_ACTIONS = constants["SERVICE_ACTIONS"]
    SERVICE_UI_ACTIONS = constants["SERVICE_UI_ACTIONS"]
    STATE_MUTATION_TIMEOUT_SECONDS = constants["STATE_MUTATION_TIMEOUT_SECONDS"]
    TRANSLATIONS = constants["TRANSLATIONS"]
    USER_SNI_OVERRIDE_SYSTEMS = constants["USER_SNI_OVERRIDE_SYSTEMS"]
    EXPORT_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")
    EXPORT_LIMITS = {"zip": 192 * 1024, "text": 64 * 1024}

    def validated_export_ipv4(value: str, *, required: bool) -> str:
        candidate = value.strip()
        if not candidate:
            if required:
                raise ValueError("Укажите публичный IPv4 для IP-экспорта.")
            return ""
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError(
                "Введите IPv4 без порта и маски, например 8.8.4.4.",
            ) from exc
        if (
            not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError(
                "Нужен публичный глобальный IPv4; частные и служебные адреса запрещены.",
            )
        return str(address)

    def login():
        if g.session is not None:
            return redirect(public_url("dashboard"))
        if request.method == "POST":
            login_value = request.form.get("login", "")
            password = request.form.get("password", "")
            admin_login = current_admin_login()
            password_ok = verify_password(password, current_admin_password_hash())
            login_ok = hmac.compare_digest(login_value, admin_login)
            if not (login_ok and password_ok):
                retry_after = storage.record_failure(g.client_ip, now())
                storage.audit("anonymous", g.client_ip, "login", "blocked" if retry_after else "denied", now=now())
                response = make_response(
                    render_template(
                        "login.html",
                        error="Неверный логин или пароль.",
                        csrf_token=login_csrf(app.config["PROXY_SECRET"], g.client_ip, now()),
                    ),
                    429 if retry_after else 401,
                )
                if retry_after:
                    response.headers["Retry-After"] = str(retry_after)
                return response
            storage.clear_failures(g.client_ip)
            storage.invalidate_session(g.session_token)
            session_token, _csrf = storage.create_session(
                g.client_ip,
                request.headers.get("User-Agent", ""),
                now(),
            )
            storage.audit(admin_login, g.client_ip, "login", "success", now=now())
            response = redirect(public_url("dashboard"))
            response.set_cookie(
                app.config["SESSION_COOKIE_NAME"],
                session_token,
                secure=app.config["SESSION_COOKIE_SECURE"],
                httponly=True,
                samesite="Strict",
                path=app.config["PORTAL_PATH"] + "/",
                max_age=8 * 60 * 60,
            )
            return response
        return render_template(
            "login.html",
            error="",
            notice=translate("password_changed") if request.args.get("changed") == "1" else "",
            csrf_token=login_csrf(app.config["PROXY_SECRET"], g.client_ip, now()),
        )

    @require_session
    def dashboard():
        widgets = empty_dashboard_widgets()
        return render_template(
            "dashboard.html",
            portal_name=app.config["PORTAL_NAME"],
            summary=dashboard_summary(widgets),
            performance=current_portal_performance(),
            csrf_token=g.session["csrf_token"],
        )

    def empty_dashboard_widgets(error: str = "") -> dict:
        return {
            name: {
                "data": None, "collected_at": 0, "age_seconds": None,
                "stale": True, "error": error,
            }
            for name in (
                "host", "metrics", "containers", "protocols",
                "health_summary", "certificates",
            )
        }

    def dashboard_snapshot() -> dict:
        try:
            payload = agent_client().call("dashboard.snapshot", {})
        except AgentClientError:
            return {
                "sources": empty_dashboard_widgets("Источник временно недоступен."),
                "generated_at": now(), "refreshing": False,
                "stale": True, "status": "unavailable",
            }
        sources = payload.get("sources") if isinstance(payload.get("sources"), dict) else {}
        return {
            "sources": {**empty_dashboard_widgets(), **sources},
            "generated_at": payload.get("generated_at", now()),
            "refreshing": bool(payload.get("refreshing")),
            "stale": bool(payload.get("stale")),
            "status": payload.get("status", "stale"),
        }

    def network_snapshot() -> dict:
        """Объединяет безопасную топологию с уже кешированным dashboard snapshot."""
        topology_error = ""
        try:
            topology = agent_client().call("network.topology", {})
        except AgentClientError:
            topology = {"revision": "", "ingress": [], "routes": [], "protocols": [], "infrastructure": []}
            topology_error = "Host-agent временно недоступен. Топология будет обновлена автоматически."

        snapshot = dashboard_snapshot()
        sources = snapshot.get("sources", {}) if isinstance(snapshot.get("sources"), dict) else {}
        health_widget = sources.get("health_summary", {}) if isinstance(sources.get("health_summary"), dict) else {}
        health_data = health_widget.get("data", {}) if isinstance(health_widget.get("data"), dict) else {}
        services = health_data.get("services", {}) if isinstance(health_data.get("services"), dict) else {}
        protocol_widget = sources.get("protocols", {}) if isinstance(sources.get("protocols"), dict) else {}
        protocol_data = protocol_widget.get("data", {}) if isinstance(protocol_widget.get("data"), dict) else {}
        collectors = protocol_data.get("collectors", {}) if isinstance(protocol_data.get("collectors"), dict) else {}
        certificate_widget = sources.get("certificates", {}) if isinstance(sources.get("certificates"), dict) else {}
        certificate_data = certificate_widget.get("data", {}) if isinstance(certificate_widget.get("data"), dict) else {}
        certificates = certificate_data.get("certificates", []) if isinstance(certificate_data.get("certificates"), list) else []
        certificate_by_target = {item.get("target"): item for item in certificates if isinstance(item, dict)}
        counter_keys = {
            "xray": {"counters", "total"}, "hysteria": {"users", "online", "tx", "rx"},
            "telemt": {"samples", "total"}, "mtg": set(), "ocserv": {"numeric_values", "total"},
            "amneziawg": {"peers", "recent_handshakes", "rx", "tx"},
            "wireguard": {"peers", "recent_handshakes", "rx", "tx"},
        }
        change_endpoints = {
            "tls": "network_view", "reality-xhttp": "network_view", "reality-tcp": "network_view",
            "hysteria": "users_list", "telemt": "settings_view", "mtg": "settings_view",
            "amneziawg": "services_list", "wireguard": "services_list", "ocserv": "settings_view",
        }

        protocols = []
        for source in topology.get("protocols", []):
            if not isinstance(source, dict):
                continue
            item = dict(source)
            service = str(item.get("service", ""))
            health = services.get(service, {}) if isinstance(services.get(service), dict) else {}
            collector = collectors.get(service, {}) if isinstance(collectors.get(service), dict) else {}
            stale = bool(snapshot.get("stale") or health_widget.get("stale") or protocol_widget.get("stale"))
            if snapshot.get("status") == "unavailable" or health_widget.get("error"):
                runtime_status, runtime_label = "down", translate("unavailable")
            elif stale:
                runtime_status, runtime_label = "stale", translate("stale")
            elif isinstance(health.get("active"), bool):
                runtime_status = "ok" if health["active"] else "down"
                runtime_label = translate("running") if health["active"] else translate("stopped")
            elif isinstance(collector.get("available"), bool):
                runtime_status = "ok" if collector["available"] else "down"
                runtime_label = translate("actual") if collector["available"] else translate("unavailable")
            else:
                runtime_status, runtime_label = "stale", translate("no_data")
            values = collector.get("values", {}) if isinstance(collector.get("values"), dict) else {}
            safe_counters = {
                key: value for key, value in values.items()
                if key in counter_keys.get(service, set()) and isinstance(value, (int, float))
            }
            certificate_target = item.get("facts", {}).get("certificate_target") if isinstance(item.get("facts"), dict) else None
            certificate = certificate_by_target.get(certificate_target, {}) if certificate_target else {}
            item["runtime"] = {
                "status": runtime_status, "label": runtime_label, "stale": stale,
                "counters": safe_counters,
                "certificate": {
                    "target": certificate_target or "", "expiry": certificate.get("expiry", "unknown"),
                    "expires_days": certificate.get("expires_days"), "source": certificate.get("source", ""),
                } if certificate_target else None,
            }
            item["change_url"] = public_url(change_endpoints[item.get("system", "tls")])
            item["links"] = [
                {"label": translate("users"), "url": public_url("users_list")},
                {"label": translate("services"), "url": public_url("services_list")},
                {"label": translate("health"), "url": public_url("health_view")},
            ]
            if certificate_target:
                item["links"].append({"label": translate("certificates"), "url": public_url("certificates_view")})
            protocols.append(item)

        return {
            "revision": topology.get("revision", ""),
            "ingress": topology.get("ingress", []),
            "routes": topology.get("routes", []),
            "protocols": protocols,
            "infrastructure": topology.get("infrastructure", []),
            "generated_at": snapshot.get("generated_at", now()),
            "refreshing": bool(snapshot.get("refreshing")),
            "stale": bool(snapshot.get("stale")),
            "status": "unavailable" if topology_error else snapshot.get("status", "stale"),
            "error": topology_error,
        }

    @require_session
    def network_view():
        zone = request.args.get("zone", "").strip()
        advice = None
        advice_error = ""
        if zone:
            try:
                advice = agent_client().call("domain.advice", {"zone": zone})
            except AgentClientError as exc:
                code = str(exc).partition(":")[0]
                advice_error = "DNS-зона отклонена проверкой." if code in {"invalid_params", "validation_error"} else "Советник доменов временно недоступен."
        return render_template(
            "network.html", data=network_snapshot(), domain_advice=advice,
            domain_advice_error=advice_error, domain_zone=zone,
            performance=current_portal_performance(),
        )

    @require_session
    def network_json():
        return jsonify(network_snapshot())

    @require_session
    def network_protocol_apply():
        result = call_agent("protocol.apply", {
            "action": "set-xhttp-mode",
            "system": "reality-xhttp",
            "mode": request.form.get("mode", ""),
            "revision": request.form.get("revision", ""),
        })
        if not isinstance(result, dict):
            return result
        apply = result.get("apply", {}) if isinstance(result.get("apply"), dict) else {}
        audit_result = "degraded" if apply.get("reconcile_required") else ("success" if result.get("changed") else "unchanged")
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "protocol.set-xhttp-mode", audit_result,
            json.dumps({"system": "reality-xhttp", "result": audit_result}, separators=(",", ":")), now(),
        )
        return render_template("protocol_result.html", result=result, action="Режим Reality xHTTP обновлён")

    @require_session
    def network_sni_apply():
        actions = {"set-default", "add-alias", "remove-alias"}
        system = request.form.get("system", "")
        action = request.form.get("action", "")
        if action not in actions or system not in {"tls", "reality-xhttp", "reality-tcp"}:
            return render_template("error.html", code=400, message="Операция Xray SNI не разрешена."), 400
        result = call_agent("sni.apply", {
            "action": action,
            "revision": request.form.get("revision", ""),
            "system": system,
            "sni": request.form.get("sni", "").strip(),
        })
        if not isinstance(result, dict):
            return result
        audit_result = "success" if result.get("changed") else "unchanged"
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, f"sni.{action}", audit_result,
            json.dumps({"system": system, "result": audit_result}, separators=(",", ":")), now(),
        )
        return render_template("protocol_result.html", result=result, action="SNI Xray обновлены")

    def format_bytes(value) -> str:
        if not isinstance(value, (int, float)):
            return translate("no_data")
        units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"]
        number = float(value)
        for unit in units:
            if abs(number) < 1024 or unit == units[-1]:
                return f"{number:.0f} {unit}" if unit == "Б" else f"{number:.1f} {unit}"
            number /= 1024
        return translate("no_data")

    def dashboard_summary(widgets: dict) -> dict:
        def source(name: str) -> tuple[dict, str, str]:
            widget = widgets.get(name, {})
            data = widget.get("data") if isinstance(widget.get("data"), dict) else {}
            if widget.get("error"):
                return data, "down", translate("unavailable")
            if widget.get("stale"):
                return data, "stale", translate("stale")
            return data, "ok", translate("actual")

        host, host_status, host_label = source("host")
        metrics, metrics_status, metrics_label = source("metrics")
        containers, containers_status, containers_label = source("containers")
        protocols, protocols_status, protocols_label = source("protocols")
        health_summary, health_summary_status, health_summary_label = source("health_summary")
        certificates, certificates_status, certificates_label = source("certificates")
        sample = metrics.get("sample") if metrics.get("available") and isinstance(metrics.get("sample"), dict) else {}
        uptime = host.get("uptime", {}) if isinstance(host.get("uptime"), dict) else {}
        uptime_text = str(uptime.get("stdout", "")).strip().removeprefix("up ") or translate("no_data")
        load = sample.get("load1")
        container_rows = containers.get("containers", []) if isinstance(containers.get("containers"), list) else []
        running = sum(1 for item in container_rows if str(item.get("state", "")).lower() == "running")
        def needs_attention(item: dict) -> bool:
            state = str(item.get("state", "")).lower()
            health = str(item.get("health", "none")).lower()
            # Исторический restart после штатного update не означает текущую аварию.
            return state != "running" or health not in {"none", "healthy"}

        unhealthy = sum(1 for item in container_rows if needs_attention(item))
        services_health = health_summary.get("services", {}) if isinstance(health_summary.get("services"), dict) else {}
        if container_rows:
            container_total = len(container_rows)
            container_running = running
            container_detail = f"{translate('containers_attention')}: {unhealthy}"
            container_status = "stale" if unhealthy and containers_status == "ok" else containers_status
            container_status_label = translate("check") if unhealthy and containers_status == "ok" else containers_label
            if running == 0 and services_health:
                fallback_running = sum(
                    1 for service in DOCKER_DASHBOARD_SERVICES
                    if isinstance(services_health.get(service), dict) and services_health[service].get("active")
                )
                if fallback_running:
                    container_running = fallback_running
                    container_total = len(DOCKER_DASHBOARD_SERVICES)
                    container_detail = translate("containers_from_health")
                    container_status = "ok" if container_running == container_total else "stale"
                    container_status_label = translate("actual") if container_status == "ok" else translate("check")
        elif services_health:
            container_total = len(DOCKER_DASHBOARD_SERVICES)
            container_running = sum(
                1 for service in DOCKER_DASHBOARD_SERVICES
                if isinstance(services_health.get(service), dict) and services_health[service].get("active")
            )
            container_detail = translate("containers_from_health")
            container_status = "ok" if container_running == container_total else "stale"
            container_status_label = translate("actual") if container_status == "ok" else translate("check")
        else:
            container_total = 0
            container_running = 0
            container_detail = "No data yet" if g.lang == "en" else "Данных пока нет"
            container_status = containers_status
            container_status_label = containers_label
        collectors = protocols.get("collectors", {}) if isinstance(protocols.get("collectors"), dict) else {}
        if services_health:
            protocol_total = len(PROTOCOL_DASHBOARD_SERVICES)
            available_protocols = sum(
                1 for service in PROTOCOL_DASHBOARD_SERVICES
                if isinstance(services_health.get(service), dict) and services_health[service].get("active")
            )
            protocol_detail = translate("protocol_services_active")
            protocol_status = "ok" if available_protocols == protocol_total else "stale"
            protocol_status_label = translate("actual") if protocol_status == "ok" else translate("check")
        else:
            protocol_total = len(collectors)
            available_protocols = sum(1 for item in collectors.values() if isinstance(item, dict) and item.get("available"))
            protocol_detail = "Active protocol collectors" if g.lang == "en" and collectors else (
                "Активные сборщики протоколов" if collectors else ("No data yet" if g.lang == "en" else "Данных пока нет")
            )
            protocol_status = protocols_status
            protocol_status_label = protocols_label
        cert_rows = certificates.get("certificates", []) if isinstance(certificates.get("certificates"), list) else []
        expiring = min(
            (item for item in cert_rows if isinstance(item.get("expires_days"), int)),
            key=lambda item: item["expires_days"],
            default=None,
        )

        def percent_card(identifier: str, label: str, key: str, detail: str, status: str, status_label: str) -> dict:
            value = sample.get(key)
            return {
                "id": identifier,
                "label": label,
                "value": f"{float(value):.1f}%" if isinstance(value, (int, float)) else "—",
                "detail": detail,
                "status": status,
                "status_label": status_label,
            }

        cards = [
            {
                "id": "server", "label": translate("server"), "value": uptime_text,
                "detail": f"Load: {float(load):.2f}" if g.lang == "en" and isinstance(load, (int, float)) else (
                    f"Нагрузка: {float(load):.2f}" if isinstance(load, (int, float)) else f"Нагрузка: {translate('no_data')}"
                ),
                "status": "down" if host_status == "down" and metrics_status == "down" else metrics_status,
                "status_label": translate("unavailable") if host_status == "down" and metrics_status == "down" else metrics_label,
            },
            percent_card("cpu", translate("cpu"), "cpu_percent", "Average CPU load" if g.lang == "en" else "Средняя загрузка CPU", metrics_status, metrics_label),
            percent_card(
                "memory", translate("memory"), "memory_percent",
                f"{format_bytes(sample.get('memory_used'))} {'of' if g.lang == 'en' else 'из'} {format_bytes(sample.get('memory_total'))}",
                metrics_status, metrics_label,
            ),
            percent_card(
                "disk", translate("disk"), "disk_percent",
                f"{format_bytes(sample.get('disk_used'))} {'of' if g.lang == 'en' else 'из'} {format_bytes(sample.get('disk_total'))}",
                metrics_status, metrics_label,
            ),
            {
                "id": "network", "label": "Network" if g.lang == "en" else "Сеть",
                "value": f"↓ {format_bytes(sample.get('rx_bytes_per_second'))}{'/s' if g.lang == 'en' else '/с'}",
                "detail": f"↑ {format_bytes(sample.get('tx_bytes_per_second'))}{'/s' if g.lang == 'en' else '/с'}",
                "status": metrics_status, "status_label": metrics_label,
            },
            {
                "id": "containers", "label": translate("containers"),
                "value": f"{container_running} {'of' if g.lang == 'en' else 'из'} {container_total}" if container_total else "—",
                "detail": container_detail,
                "status": container_status,
                "status_label": container_status_label,
            },
            {
                "id": "protocols", "label": translate("protocols"),
                "value": f"{available_protocols} {'of' if g.lang == 'en' else 'из'} {protocol_total}" if protocol_total else "—",
                "detail": protocol_detail,
                "status": protocol_status, "status_label": protocol_status_label,
            },
            {
                "id": "certificates", "label": translate("certificates"),
                "value": f"{expiring['expires_days']} {'days' if g.lang == 'en' else 'дн.'}" if expiring else (f"{len(cert_rows)} {'items' if g.lang == 'en' else 'шт.'}" if cert_rows else "—"),
                "detail": f"Next: {expiring['target']}" if g.lang == "en" and expiring else (
                    f"Ближайший: {expiring['target']}" if expiring else ("Certificate expiry" if g.lang == "en" else "Сроки сертификатов")
                ),
                "status": certificates_status, "status_label": certificates_label,
            },
        ]
        return {"cards": cards, "generated_at": now()}

    @require_session
    def dashboard_json():
        snapshot = dashboard_snapshot()
        summary = dashboard_summary(snapshot["sources"])
        summary.update({key: snapshot[key] for key in ("refreshing", "stale", "status")})
        return summary

    @require_session
    def metrics_history_json():
        try:
            range_hours = int(request.args.get("range_hours", "24"))
        except ValueError:
            return {"error": "Некорректный диапазон."}, 400
        raw_step = request.args.get("step", "auto")
        try:
            step: str | int = "auto" if raw_step == "auto" else int(raw_step)
        except ValueError:
            return {"error": "Некорректный шаг."}, 400
        allowed_ranges = {1, 6, 24, 72}
        allowed_steps = {1, 5, 15, 60}
        if range_hours not in allowed_ranges or not (step == "auto" or step in allowed_steps):
            return {"error": "Диапазон или шаг не разрешён."}, 400
        effective_step = {1: 1, 6: 1, 24: 5, 72: 5}[range_hours] if step == "auto" else step
        if range_hours * 60 / effective_step > 1500:
            return {"error": "Выбранный шаг создаёт слишком много точек."}, 400
        try:
            return agent_client().call("metrics.history", {"range_hours": range_hours, "step": step})
        except AgentClientError:
            return {"available": False, "error": "История временно недоступна.", "points": []}, 502

    def parse_user_fields() -> dict:
        fields = {
            "name": request.form.get("name", "").strip(),
            "new_name": request.form.get("new_name", "").strip(),
            "description": request.form.get("description", "").strip(),
            "systems": request.form.getlist("systems"),
            "device": request.form.get("device", "").strip(),
            "enabled": request.form.get("enabled") == "on",
            "ocserv_password": request.form.get("ocserv_password", ""),
            "uuid": request.form.get("uuid", ""),
            "hysteria_password": request.form.get("hysteria_password", ""),
            "telemt_secret": request.form.get("telemt_secret", ""),
        }
        fields["sni_overrides"] = {
            key.removeprefix("sni_"): value.strip()
            for key, value in request.form.items()
            if key.startswith("sni_")
            and key.removeprefix("sni_") in USER_SNI_OVERRIDE_SYSTEMS
            and value.strip()
        }
        return fields

    def call_agent(method: str, params: dict, *, timeout: float | None = None):
        try:
            if timeout is None:
                return agent_client().call(method, params)
            return agent_client().call(method, params, timeout=timeout)
        except AgentClientError as exc:
            message = str(exc)
            if message.startswith("revision_conflict:"):
                return render_template("conflict.html", message="Данные уже изменились. Обновите страницу и повторите операцию."), 409
            if message.startswith("not_found:"):
                return render_template("error.html", code=404, message="Объект не найден."), 404
            if message.startswith((
                "invalid_file:", "invalid_user:", "invalid_params:",
                "invalid_mode:", "validation_error:", "file_not_allowed:",
                "file_too_large:", "bundle_too_large:", "archive_too_large:",
                "text_too_large:", "too_many_files:", "unsafe_source:",
                "cross_user:",
            )):
                return render_template("error.html", code=400, message="Запрос отклонён проверкой данных."), 400
            if method == "project.update" and message.startswith("root_password_denied:"):
                return render_template("error.html", code=403, message="Подтверждение root-паролем не прошло."), 403
            if method == "project.update" and message.startswith(("root_password_blocked:", "root_password_unavailable:")):
                return render_template("error.html", code=409, message="Подтверждение root-паролем временно недоступно."), 409
            if method == "project.update" and message.startswith("invalid_archive:"):
                detail = message.partition(":")[2].strip()[:512]
                recovery = "Пересоберите архив командой: bash tools/build-deploy.sh"
                return render_template(
                    "error.html", code=400,
                    message=f"Архив отклонён: {detail}. {recovery}",
                ), 400
            return render_template("error.html", code=502, message="Host-agent недоступен или отклонил операцию."), 502

    def parse_logs_params():
        service = request.args.get("service", "nginx")
        try:
            tail = int(request.args.get("tail", "200"))
            since = int(request.args.get("since", "60"))
        except ValueError:
            return None, "Некорректные границы логов."
        text_filter = request.args.get("filter", "")
        if service not in MANAGED_SERVICES or not 50 <= tail <= 2000 or not 1 <= since <= 10080 or len(text_filter) > 64:
            return None, "Запрос логов вне допустимых границ."
        return {"service": service, "tail": tail, "since": since, "filter": text_filter}, ""

    def logs_error(message: str, *, as_json: bool = False):
        if as_json:
            return jsonify({"ok": False, "error": message}), 400
        return render_template("error.html", code=400, message=message), 400

    def logs_payload(params: dict):
        data = call_agent("logs.tail", {"service": params["service"], "tail": params["tail"], "since_minutes": params["since"]})
        if not isinstance(data, dict):
            return data
        command = data.get("command", {}) if isinstance(data.get("command"), dict) else {}
        content = str(command.get("stdout", ""))
        if params["filter"]:
            needle = params["filter"].lower()
            content = "\n".join(line for line in content.splitlines() if needle in line.lower())
        truncated = len(content) > LOG_CONTENT_LIMIT
        content = content[:LOG_CONTENT_LIMIT]
        cursor = int(data.get("cursor") or int(time.time() * 1000))
        generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cursor / 1000))
        return {
            "service": params["service"],
            "tail": params["tail"],
            "since": params["since"],
            "filter": params["filter"],
            "cursor": cursor,
            "generated_at": generated_at,
            "content": content,
            "truncated": truncated,
            "command": {
                "ok": command.get("returncode") == 0,
                "returncode": command.get("returncode"),
                "duration_ms": command.get("duration_ms"),
                "source": "journalctl" if params["service"] in {"amneziawg", "wireguard", "agent"} else "docker compose logs",
            },
        }

    def render_terminal(result: dict | None = None):
        data = call_agent("maintenance.commands", {})
        if not isinstance(data, dict):
            return data
        groups: dict[str, list[dict]] = {}
        confirmations = {}
        for command in data.get("commands", []):
            if not isinstance(command, dict) or not isinstance(command.get("id"), str):
                continue
            group = str(command.get("group") or "KVN")
            groups.setdefault(group, []).append(command)
            if command.get("requires_confirmation"):
                confirmations[command["id"]] = storage.create_confirmation(
                    g.session_token, "maintenance.run", command["id"], now()
                )
        return render_template(
            "terminal.html",
            groups=groups,
            confirmations=confirmations,
            result=result,
            csrf_token=g.session["csrf_token"],
        )

    def shell_session_owner() -> str:
        return token_hash(g.session_token)

    def cleanup_update_uploads(directory: Path, timestamp: int) -> bool:
        """Удаляет только старые неисполняемые upload-архивы и сообщает о свободном лимите."""
        try:
            directory.mkdir(parents=True, exist_ok=True)
            files = [
                item for pattern in ("kvn-vpn-deploy-*.tar.gz", "kvn-vpn-release-linux-amd64-*.tar.gz")
                for item in directory.glob(pattern) if item.is_file() and not item.is_symlink()
            ]
        except OSError:
            return False
        retention = int(app.config["UPDATE_UPLOAD_RETENTION_SECONDS"])
        min_age = int(app.config["UPDATE_UPLOAD_MIN_AGE_SECONDS"])
        for item in sorted(files, key=lambda candidate: candidate.stat().st_mtime):
            try:
                age = timestamp - int(item.stat().st_mtime)
                marker = item.with_name(item.name + ".running")
                if age >= retention and age >= min_age and not marker.exists():
                    item.unlink()
                    relative = f"{app.config['UPDATE_UPLOAD_RELATIVE_DIR'].strip('/')}/{item.name}"
                    storage.remove_prepared_update_by_archive(relative)
            except OSError:
                continue
        try:
            retained = [
                item for pattern in ("kvn-vpn-deploy-*.tar.gz", "kvn-vpn-release-linux-amd64-*.tar.gz")
                for item in directory.glob(pattern) if item.is_file() and not item.is_symlink()
            ]
        except OSError:
            return False
        return len(retained) < int(app.config["UPDATE_UPLOAD_MAX_FILES"])

    def remove_update_archive(record: dict | None) -> None:
        """Удаляет только созданный порталом архив, если он сейчас не исполняется."""
        if not record:
            return
        archive = str(record.get("archive", ""))
        relative_root = app.config["UPDATE_UPLOAD_RELATIVE_DIR"].strip("/") + "/"
        if not archive.startswith(relative_root):
            return
        filename = archive.removeprefix(relative_root)
        if not re.fullmatch(
            r"kvn-vpn-(?:deploy|release-linux-amd64)-(?:[0-9]+-[0-9a-f]{12}|github-[0-9a-f]{12})\.tar\.gz",
            filename,
        ):
            return
        path = Path(app.config["UPDATE_UPLOAD_DIR"]) / filename
        if path.is_symlink() or path.with_name(path.name + ".running").exists():
            return
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def save_update_upload(upload_stream, destination: Path) -> int:
        """Пишет upload ограниченными блоками и публикует только после fsync/rename."""
        maximum = int(app.config["UPDATE_UPLOAD_MAX_BYTES"])
        reserve = int(app.config["UPDATE_UPLOAD_DISK_RESERVE_BYTES"])
        expected = max(0, int(request.content_length or 0))
        if expected > maximum + 1024 * 1024:
            raise ValueError("Архив превышает допустимый размер.")
        if shutil.disk_usage(destination.parent).free < expected + reserve:
            raise ValueError("Недостаточно свободного места для загрузки и проверки архива.")
        temporary = destination.with_name(destination.name + f".part-{uuid.uuid4().hex}")
        total = 0
        try:
            with temporary.open("xb") as output:
                while True:
                    chunk = upload_stream.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > maximum:
                        raise ValueError("Архив превышает допустимый размер.")
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            temporary.chmod(0o600)
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return total

    def update_wants_json() -> bool:
        return (
            request.headers.get("X-Requested-With") == "XMLHttpRequest"
            or request.accept_mimetypes.best == "application/json"
        )

    def update_error(message: str, status: int, code: str):
        if update_wants_json():
            return jsonify({"ok": False, "code": code, "error": message}), status
        return render_template("error.html", code=status, message=message), status

    def update_agent_error_details(exc: AgentClientError) -> tuple[str, int, str]:
        """Возвращает безопасные code/status/message без исходного текста agent."""
        raw_code = str(exc).partition(":")[0]
        code = raw_code if re.fullmatch(r"[a-z0-9_.-]+", raw_code) else "agent_error"
        status, message = {
            "invalid_params": (400, "Параметры обновления отклонены."),
            "invalid_archive": (400, "Архив отклонён проверкой. Пересоберите его штатным build-скриптом."),
            "not_found": (404, "Архив обновления не найден."),
            "policy_denied": (403, "Путь архива запрещён политикой host-agent."),
            "insufficient_disk": (409, "На сервере недостаточно места для проверки обновления."),
            "archive_changed": (409, "Архив изменился после проверки. Загрузите его заново."),
            "root_password_denied": (403, "Подтверждение root-паролем не прошло."),
            "root_password_blocked": (429, "Проверка root-пароля временно заблокирована."),
            "root_password_unavailable": (409, "Проверка root-пароля временно недоступна."),
            "github_updates_disabled": (409, "GitHub-обновления отключены. Используйте CLI или ручную загрузку."),
            "release_not_found": (404, "Release не опубликован или недоступен. Используйте ручную загрузку."),
            "github_rate_limited": (429, "GitHub ограничил запросы. Повторите позже или загрузите архив вручную."),
            "github_timeout": (504, "GitHub не ответил вовремя. Проверьте сеть или загрузите архив вручную."),
            "github_unavailable": (502, "GitHub недоступен с сервера. Проверьте DNS/маршрут или загрузите архив вручную."),
            "asset_not_found": (404, "В Release нет штатного архива. Используйте проверенный архив вручную."),
            "asset_too_large": (409, "Asset Release превышает лимит. Используйте штатный архив вручную."),
            "invalid_asset": (409, "Metadata asset отклонены. Не запускайте его; используйте штатный архив."),
            "invalid_response": (502, "GitHub вернул несогласованные metadata. Используйте ручную загрузку."),
            "digest_mismatch": (409, "SHA-256 загрузки не совпал с GitHub API. Архив удалён; загрузите его вручную."),
            "size_mismatch": (409, "Размер загрузки не совпал с GitHub API. Архив удалён; используйте ручную загрузку."),
            "credential_insecure": (409, "Credential GitHub имеет небезопасные права. Исправьте root-only файл или загрузите архив вручную."),
            "credential_invalid": (409, "Credential GitHub не принят. Настройте CLI или используйте ручную загрузку."),
            "release_changed": (409, "Release изменился. Нажмите «Проверить GitHub» ещё раз."),
            "redirect_denied": (409, "GitHub вернул небезопасный redirect. Загрузка остановлена; используйте ручной архив."),
        }.get(code, (
            502,
            "Host-agent недоступен или отклонил операцию. Проверьте kvn-portal-agent.service или используйте ручную загрузку.",
        ))
        return code, int(status), message

    def update_agent_error(exc: AgentClientError):
        code, status, message = update_agent_error_details(exc)
        return update_error(message, status, code)

    def public_prepared_update(record: dict) -> dict:
        return {
            key: record[key]
            for key in (
                "id",
                "archive_name",
                "archive_size",
                "archive_sha256",
                "archive_kind",
                "metadata",
                "status",
                "created_at",
                "updated_at",
            )
            if key in record
        }

    def public_github_release(result: dict) -> dict:
        """Строго ограничивает GitHub metadata перед HTML/JSON-ответом."""
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ValueError("GitHub Release не подтверждён.")
        repository = result.get("repository")
        channel = result.get("channel")
        tag = result.get("tag")
        release_id = result.get("release_id")
        selected = result.get("asset")
        assets = result.get("assets")
        if (
            repository != "artemiygaer/kvn-portal"
            or channel not in {"stable", "tag"}
            or not isinstance(tag, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", tag) is None
            or not isinstance(release_id, int)
            or release_id <= 0
            or not isinstance(selected, dict)
            or not isinstance(assets, list)
        ):
            raise ValueError("GitHub Release содержит некорректные metadata.")

        def safe_asset(item: dict) -> dict:
            if not isinstance(item, dict):
                raise ValueError("Некорректный asset.")
            name = item.get("name")
            kind = item.get("kind")
            asset_id = item.get("id")
            size = item.get("size")
            sha256 = item.get("sha256")
            expected = {
                "release": "kvn-vpn-release-linux-amd64.tar.gz",
                "deploy": "kvn-vpn-deploy.tar.gz",
            }
            if (
                kind not in expected
                or name != expected[kind]
                or not isinstance(asset_id, int)
                or asset_id <= 0
                or not isinstance(size, int)
                or size < 1024
                or not isinstance(sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
            ):
                raise ValueError("Asset Release отклонён.")
            return {
                "id": asset_id,
                "name": name,
                "kind": kind,
                "size": size,
                "sha256": sha256,
            }

        safe_assets = [safe_asset(item) for item in assets[:2]]
        safe_selected = safe_asset(selected)
        if safe_selected not in safe_assets:
            raise ValueError("Выбранный asset отсутствует в разрешённом списке.")
        notes = result.get("notes", "")
        if not isinstance(notes, str):
            notes = ""
        notes = notes[:4002]
        release_name = str(result.get("release_name") or tag)[:160]
        published_at = str(result.get("published_at") or "")[:40]
        current_build = str(app.config["BUILD_ID"])
        return {
            "repository": repository,
            "channel": channel,
            "tag": tag,
            "release_id": release_id,
            "release_name": release_name,
            "published_at": published_at,
            "notes": notes,
            "assets": safe_assets,
            "asset": safe_selected,
            "up_to_date": current_build in {tag, tag.removeprefix("v")},
        }

    def upload_update_archive():
        if request.mimetype == "application/octet-stream":
            original_name = Path(request.headers.get("X-KVN-Archive-Name", "")).name
            upload_stream = request.stream
        else:
            upload = request.files.get("archive")
            if upload is None or not upload.filename:
                return None, update_error("Выберите full release или source deploy архив.", 400, "archive_required")
            original_name = Path(upload.filename).name
            upload_stream = upload.stream
        allowed_names = {"kvn-vpn-deploy.tar.gz", "kvn-vpn-release-linux-amd64.tar.gz"}
        if original_name not in allowed_names:
            return None, update_error("Имя архива не соответствует штатному deploy/release.", 400, "invalid_archive_name")
        upload_dir = Path(app.config["UPDATE_UPLOAD_DIR"])
        if not cleanup_update_uploads(upload_dir, now()):
            return None, update_error(
                "Достигнут лимит архивов. Дождитесь завершения обновления или удалите подготовленный архив.",
                409,
                "upload_limit",
            )
        prefix = original_name.removesuffix(".tar.gz")
        filename = f"{prefix}-{now()}-{uuid.uuid4().hex[:12]}.tar.gz"
        upload_path = upload_dir / filename
        try:
            size = save_update_upload(upload_stream, upload_path)
            with upload_path.open("rb") as handle:
                magic = handle.read(2)
        except (OSError, ValueError) as exc:
            upload_path.unlink(missing_ok=True)
            return None, update_error(str(exc), 400, "upload_failed")
        if magic != b"\x1f\x8b" or not (1024 <= size <= int(app.config["UPDATE_UPLOAD_MAX_BYTES"])):
            upload_path.unlink(missing_ok=True)
            return None, update_error("Архив повреждён или имеет недопустимый размер.", 400, "invalid_archive")
        relative = f"{app.config['UPDATE_UPLOAD_RELATIVE_DIR'].strip('/')}/{filename}"
        return {"path": upload_path, "relative": relative, "size": size}, None

    @require_session
    def project_update_prepare():
        uploaded, error_response = upload_update_archive()
        if error_response is not None:
            return error_response
        try:
            inspected = agent_client().call(
                "project.update.inspect",
                {"archive": uploaded["relative"]},
                timeout=float(app.config["UPDATE_RPC_TIMEOUT_SECONDS"]),
            )
        except AgentClientError as exc:
            uploaded["path"].unlink(missing_ok=True)
            storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "project.update.prepare", "failed", now=now())
            return update_agent_error(exc)
        try:
            if (
                not isinstance(inspected, dict)
                or inspected.get("ok") is not True
                or inspected.get("archive") != uploaded["relative"]
                or int(inspected.get("archive_size", -1)) != uploaded["size"]
                or not re.fullmatch(r"[0-9a-fA-F]{64}", str(inspected.get("archive_sha256", "")))
                or inspected.get("archive_kind") not in {"deploy", "release"}
            ):
                raise ValueError("Host-agent вернул несогласованные метаданные архива.")
            inspected["source"] = "upload"
            published = storage.publish_prepared_update(inspected, now())
        except (KeyError, TypeError, ValueError, OSError):
            uploaded["path"].unlink(missing_ok=True)
            storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "project.update.prepare", "failed", now=now())
            return update_error("Проверка архива вернула некорректный результат.", 502, "invalid_inspection")
        prepared = published["update"]
        for replaced in published["replaced"]:
            if replaced.get("archive") != prepared.get("archive"):
                remove_update_archive(replaced)
        storage.audit(
            app.config["ADMIN_LOGIN"],
            g.client_ip,
            "project.update.prepare",
            "success",
            json.dumps({
                "id": prepared["id"],
                "name": prepared["archive_name"],
                "sha256": prepared["archive_sha256"],
            }, separators=(",", ":")),
            now(),
        )
        if update_wants_json():
            return jsonify({"ok": True, "prepared": public_prepared_update(prepared)}), 201
        return redirect(public_url("settings_view", prepared="1"))

    @require_session
    def project_release_check():
        try:
            result = agent_client().call("project.release.check", {}, timeout=30.0)
            release = public_github_release(result)
        except AgentClientError as exc:
            code, status, message = update_agent_error_details(exc)
            storage.audit(
                app.config["ADMIN_LOGIN"], g.client_ip, "project.release.check", "failed",
                json.dumps({"code": code}, separators=(",", ":")), now(),
            )
            if update_wants_json():
                return jsonify({
                    "ok": False,
                    "code": code,
                    "error": message,
                    "manual_fallback": True,
                }), status
            return render_settings_page(github_error=message, github_error_code=code), status
        except (KeyError, TypeError, ValueError):
            storage.audit(
                app.config["ADMIN_LOGIN"], g.client_ip, "project.release.check", "failed",
                json.dumps({"code": "invalid_response"}, separators=(",", ":")), now(),
            )
            return update_error(
                "GitHub вернул несогласованные metadata. Используйте ручную загрузку.",
                502,
                "invalid_response",
            )
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "project.release.check", "success",
            json.dumps({
                "repository": release["repository"],
                "tag": release["tag"],
                "up_to_date": release["up_to_date"],
            }, separators=(",", ":")),
            now(),
        )
        if update_wants_json():
            return jsonify({"ok": True, "release": release})
        return render_settings_page(github_release=release)

    @require_session
    def project_release_prepare():
        try:
            release_id = int(request.form.get("release_id", ""))
            asset_id = int(request.form.get("asset_id", ""))
        except (TypeError, ValueError):
            return update_error("Идентификаторы Release недопустимы.", 400, "invalid_params")
        asset_sha256 = request.form.get("asset_sha256", "")
        if (
            release_id <= 0
            or asset_id <= 0
            or re.fullmatch(r"[0-9a-f]{64}", asset_sha256) is None
        ):
            return update_error("Параметры Release отклонены.", 400, "invalid_params")
        try:
            prepared_result = agent_client().call(
                "project.release.prepare",
                {
                    "release_id": release_id,
                    "asset_id": asset_id,
                    "asset_sha256": asset_sha256,
                },
                timeout=float(app.config["UPDATE_RPC_TIMEOUT_SECONDS"]),
            )
        except AgentClientError as exc:
            safe_code, status, message = update_agent_error_details(exc)
            storage.audit(
                app.config["ADMIN_LOGIN"], g.client_ip, "project.release.prepare", "failed",
                json.dumps({"code": safe_code}, separators=(",", ":")), now(),
            )
            if update_wants_json():
                return update_error(message, status, safe_code)
            return render_settings_page(
                github_error=message,
                github_error_code=safe_code,
            ), status
        try:
            if (
                not isinstance(prepared_result, dict)
                or prepared_result.get("ok") is not True
                or prepared_result.get("ready") is not True
                or prepared_result.get("repository") != "artemiygaer/kvn-portal"
                or prepared_result.get("release_id") != release_id
                or prepared_result.get("asset_id") != asset_id
                or prepared_result.get("archive_sha256") != asset_sha256
                or prepared_result.get("archive_kind") not in {"deploy", "release"}
                or not isinstance(prepared_result.get("archive_size"), int)
                or int(prepared_result["archive_size"]) < 1024
                or not isinstance(prepared_result.get("archive"), str)
                or not prepared_result["archive"].startswith(
                    app.config["UPDATE_UPLOAD_RELATIVE_DIR"].strip("/") + "/"
                )
            ):
                raise ValueError("Host-agent вернул несогласованный prepared artifact.")
            prepared_result["source"] = "github"
            published = storage.publish_prepared_update(prepared_result, now())
        except (KeyError, TypeError, ValueError, OSError):
            storage.audit(
                app.config["ADMIN_LOGIN"], g.client_ip, "project.release.prepare", "failed",
                json.dumps({"code": "invalid_inspection"}, separators=(",", ":")), now(),
            )
            message = "GitHub artifact подготовлен, но metadata проверки несогласованы. Используйте ручную загрузку."
            if update_wants_json():
                return update_error(message, 502, "invalid_inspection")
            return render_settings_page(
                github_error=message,
                github_error_code="invalid_inspection",
            ), 502
        if published.get("busy"):
            message = "Этот GitHub artifact уже запускается. Дождитесь завершения unit и повторите проверку."
            if update_wants_json():
                return update_error(message, 409, "update_starting")
            return render_settings_page(
                github_error=message,
                github_error_code="update_starting",
            ), 409
        prepared = published["update"]
        for replaced in published["replaced"]:
            if replaced.get("archive") != prepared.get("archive"):
                remove_update_archive(replaced)
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "project.release.prepare", "success",
            json.dumps({
                "id": prepared["id"],
                "tag": str(prepared_result.get("tag", ""))[:80],
                "sha256": prepared["archive_sha256"],
            }, separators=(",", ":")),
            now(),
        )
        if update_wants_json():
            return jsonify({"ok": True, "prepared": public_prepared_update(prepared)}), 201
        return redirect(public_url("settings_view", prepared="github"))

    @require_session
    def project_update_start():
        update_id = request.form.get("prepared_id", "")
        mode = request.form.get("update_mode", "full")
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", update_id) or mode not in {"full", "bootstrap-only"}:
            return update_error("Подготовленное обновление или режим не разрешены.", 400, "invalid_params")
        prepared = storage.claim_prepared_update(update_id, now())
        if prepared is None:
            return update_error("Обновление уже запущено, удалено или заменено.", 409, "update_not_ready")
        try:
            result = agent_client().call(
                "project.update",
                {
                    "archive": prepared["archive"],
                    "expected_sha256": prepared["archive_sha256"],
                    "mode": mode,
                    "root_password": request.form.get("root_password", ""),
                    "session_owner": shell_session_owner(),
                },
                timeout=float(app.config["UPDATE_RPC_TIMEOUT_SECONDS"]),
            )
        except AgentClientError as exc:
            storage.release_prepared_update(update_id, now())
            storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "project.update", "failed", now=now())
            return update_agent_error(exc)
        if not isinstance(result, dict) or result.get("ok") is not True:
            storage.release_prepared_update(update_id, now())
            storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "project.update", "failed", now=now())
            if update_wants_json():
                return jsonify({"ok": False, "code": "update_launch_failed"}), 502
            return render_template("update_result.html", result=result or {}, build_before=app.config["BUILD_ID"]), 502
        storage.finish_prepared_update(update_id, now())
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "project.update", "success",
            json.dumps({
                "id": update_id,
                "name": prepared["archive_name"],
                "sha256": prepared["archive_sha256"],
            }, separators=(",", ":")),
            now(), correlation_id=result.get("correlation_id", ""),
        )
        if update_wants_json():
            return jsonify({"ok": True, "result": result})
        return render_template("update_result.html", result=result, build_before=app.config["BUILD_ID"])

    @require_session
    def project_update_discard():
        update_id = request.form.get("prepared_id", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", update_id):
            return update_error("Подготовленное обновление не найдено.", 400, "invalid_params")
        prepared = storage.discard_prepared_update(update_id)
        if prepared is None:
            return update_error("Обновление уже запущено, удалено или заменено.", 409, "update_not_ready")
        remove_update_archive(prepared)
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "project.update.discard", "success",
            json.dumps({"id": update_id, "name": prepared["archive_name"]}, separators=(",", ":")),
            now(),
        )
        if update_wants_json():
            return jsonify({"ok": True})
        return redirect(public_url("settings_view", discarded="1"))

    def json_payload() -> dict:
        payload = request.get_json(silent=True)
        return payload if isinstance(payload, dict) else {}

    def shell_agent_call(method: str, params: dict):
        try:
            return agent_client().call(method, params), None
        except AgentClientError as exc:
            message = str(exc)
            if message.startswith("Host-agent недоступен"):
                return None, ("agent_unavailable", "Host-agent временно недоступен.")
            code, _separator, text = message.partition(":")
            safe_code = code if re.fullmatch(r"[a-z0-9_.-]+", code) else "agent_error"
            safe_text = text.strip() or "Host-agent отклонил shell-операцию."
            return None, (safe_code, safe_text)

    def shell_json_error(error, default_status: int = 502):
        code, message = error
        status = {
            "invalid_params": 400,
            "request_too_large": 413,
            "root_password_denied": 403,
            "root_password_blocked": 429,
            "root_password_unavailable": 409,
            "too_many_sessions": 409,
            "not_found": 404,
            "capability_unavailable": 409,
            "agent_unavailable": 503,
        }.get(code, default_status)
        return jsonify({"ok": False, "code": code, "error": message}), status

    @require_session
    def terminal_shell_open():
        payload = json_payload()
        rows = payload.get("rows", 24)
        cols = payload.get("cols", 100)
        result, error = shell_agent_call(
            "shell.open",
            {
                "root_password": payload.get("root_password", ""),
                "session_owner": shell_session_owner(),
                "rows": rows,
                "cols": cols,
            },
        )
        if error:
            storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "root_shell.open", "failed", json.dumps({"code": error[0]}, separators=(",", ":")), now())
            return shell_json_error(error)
        storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "root_shell.open", "success", now=now())
        return jsonify(result)

    @require_session
    def terminal_shell_read():
        payload = json_payload()
        result, error = shell_agent_call(
            "shell.read",
            {"shell_id": payload.get("shell_id", ""), "session_owner": shell_session_owner()},
        )
        if error:
            return shell_json_error(error)
        return jsonify(result)

    @require_session
    def terminal_shell_write():
        payload = json_payload()
        result, error = shell_agent_call(
            "shell.write",
            {
                "shell_id": payload.get("shell_id", ""),
                "session_owner": shell_session_owner(),
                "data": payload.get("data", ""),
            },
        )
        if error:
            return shell_json_error(error)
        return jsonify(result)

    @require_session
    def terminal_shell_resize():
        payload = json_payload()
        result, error = shell_agent_call(
            "shell.resize",
            {
                "shell_id": payload.get("shell_id", ""),
                "session_owner": shell_session_owner(),
                "rows": payload.get("rows", 24),
                "cols": payload.get("cols", 100),
            },
        )
        if error:
            return shell_json_error(error)
        return jsonify(result)

    @require_session
    def terminal_shell_close():
        payload = json_payload()
        result, error = shell_agent_call(
            "shell.close",
            {"shell_id": payload.get("shell_id", ""), "session_owner": shell_session_owner()},
        )
        if error:
            return shell_json_error(error)
        storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "root_shell.close", "success", now=now())
        return jsonify(result)

    @require_session
    def root_shell_view():
        return render_template("root_shell.html", csrf_token=g.session["csrf_token"])

    @require_session
    def users_list():
        data = call_agent("state.users", {})
        if not isinstance(data, dict):
            return data
        query = request.args.get("q", "").strip().lower()
        system_filter = request.args.get("system", "")
        enabled_filter = request.args.get("enabled", "")
        users = data["users"]
        if query:
            users = [user for user in users if query in user["name"].lower() or query in user["description"].lower()]
        if system_filter:
            users = [user for user in users if system_filter in user["systems"]]
        if enabled_filter in {"true", "false"}:
            users = [user for user in users if user["enabled"] is (enabled_filter == "true")]
        view = request.args.get("view", "cards")
        if view not in {"cards", "matrix"}:
            view = "cards"
        return render_template(
            "users.html", data=data, users=users, has_users=bool(data["users"]),
            view=view, csrf_token=g.session["csrf_token"],
            client_export=data.get("client_export", {}),
        )

    @require_session
    def services_list():
        services = []
        for service in MANAGED_SERVICES:
            status = call_agent("service.status", {"service": service})
            if not isinstance(status, dict):
                return status
            services.append(status)
        confirmations = {
            f"{service}:{action}": storage.create_confirmation(
                g.session_token, f"service.{action}", service, now()
            )
            for service in MANAGED_SERVICES
            for action in CONFIRMED_SERVICE_ACTIONS
        }
        return render_template(
            "services.html", services=services, confirmations=confirmations,
            service_actions=SERVICE_UI_ACTIONS, csrf_token=g.session["csrf_token"],
        )

    @require_session
    def service_action(service: str):
        action = request.form.get("action", "")
        if service not in MANAGED_SERVICES or action not in SERVICE_ACTIONS:
            return render_template("error.html", code=400, message="Операция сервиса не разрешена."), 400
        if action in CONFIRMED_SERVICE_ACTIONS:
            token = request.form.get("confirmation_token", "")
            if not storage.consume_confirmation(
                g.session_token, token, f"service.{action}", service, now()
            ):
                return render_template("error.html", code=403, message="Подтверждение недействительно или уже использовано."), 403
        result = call_agent(
            "service.action",
            {"service": service, "action": action, "request_id": uuid.uuid4().hex},
        )
        if not isinstance(result, dict):
            return result
        audit_detail = json.dumps(
            {
                "service": service,
                "action": action,
                "before": result.get("before", {}).get("active"),
                "after": result.get("after", {}).get("active"),
                "duration_ms": result.get("duration_ms"),
                "correlation_id": result.get("correlation_id", ""),
                "health": result.get("health", {}).get("ok"),
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "service.action",
            "success" if result.get("ok") else "failed", audit_detail, now(),
            correlation_id=result.get("correlation_id", ""),
        )
        return render_template("service_result.html", result=result)

    @require_session
    def logs_view():
        params, error = parse_logs_params()
        if error:
            return logs_error(error)
        payload = logs_payload(params)
        if not isinstance(payload, dict):
            return payload
        if request.args.get("download") == "1":
            response = Response(payload["content"], content_type="text/plain; charset=utf-8")
            response.headers["Content-Disposition"] = f'attachment; filename="{params["service"]}-logs.txt"'
            return response
        return render_template(
            "logs.html", services=MANAGED_SERVICES, service=params["service"], tail=params["tail"],
            since=params["since"], text_filter=params["filter"], content=payload["content"],
            cursor=payload["cursor"], generated_at=payload["generated_at"],
            truncated=payload["truncated"], command=payload["command"],
        )

    @require_session
    def logs_json():
        params, error = parse_logs_params()
        if error:
            return logs_error(error, as_json=True)
        payload = logs_payload(params)
        if not isinstance(payload, dict):
            return payload
        return jsonify(payload)

    @require_session
    def terminal_view():
        if request.method == "GET":
            return render_terminal()
        data = call_agent("maintenance.commands", {})
        if not isinstance(data, dict):
            return data
        commands = {
            item.get("id"): item
            for item in data.get("commands", [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        command_id = request.form.get("command", "")
        selected = commands.get(command_id)
        if selected is None:
            return render_template("error.html", code=400, message="Команда обслуживания не разрешена."), 400
        if selected.get("requires_confirmation"):
            token = request.form.get("confirmation_token", "")
            if not storage.consume_confirmation(g.session_token, token, "maintenance.run", command_id, now()):
                return render_template("error.html", code=403, message="Подтверждение недействительно или уже использовано."), 403
        result = call_agent("maintenance.run", {"command": command_id, "request_id": uuid.uuid4().hex})
        if not isinstance(result, dict):
            return result
        command = result.get("command", {}) if isinstance(result.get("command"), dict) else {}
        detail = json.dumps(
            {
                "command": command_id,
                "returncode": command.get("returncode"),
                "duration_ms": command.get("duration_ms"),
                "correlation_id": result.get("correlation_id", ""),
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        storage.audit(
            app.config["ADMIN_LOGIN"],
            g.client_ip,
            "maintenance.run",
            "success" if result.get("ok") else "failed",
            detail,
            now(),
            correlation_id=result.get("correlation_id", ""),
        )
        return render_terminal(result)

    @require_session
    def certificates_view():
        data = call_agent("certificates.status", {})
        if not isinstance(data, dict):
            return data
        confirmations = {
            f"{action}:{target}": storage.create_confirmation(
                g.session_token, f"certificate.{action}", target, now()
            )
            for action in ["issue-configured", "renew", "reissue", "deploy"]
            for target in ["site", "ocserv", "all"]
        }
        return render_template(
            "certificates.html", data=data, confirmations=confirmations,
            csrf_token=g.session["csrf_token"],
        )

    @require_session
    def certificate_action():
        action = request.form.get("action", "")
        target = request.form.get("target", "all")
        token = request.form.get("confirmation_token", "")
        if action not in {"issue-configured", "renew", "reissue", "deploy"} or target not in {"site", "ocserv", "all"}:
            return render_template("error.html", code=400, message="Операция сертификата не разрешена."), 400
        if not storage.consume_confirmation(
            g.session_token, token, f"certificate.{action}", target, now()
        ):
            return render_template("error.html", code=403, message="Подтверждение недействительно."), 403
        result = call_agent("certificate.action", {"action": action, "target": target})
        if not isinstance(result, dict):
            return result
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "certificate.action",
            "success" if result.get("ok") else "failed",
            json.dumps({"action": action, "target": target}, separators=(",", ":")),
            now(), correlation_id=result.get("correlation_id", ""),
        )
        return render_template("certificate_result.html", result=result)

    @require_session
    def health_view():
        data = call_agent("health.summary", {})
        if not isinstance(data, dict):
            return data
        return render_template("health.html", data=data)

    @require_session
    def audit_view():
        try:
            page = int(request.args.get("page", "1"))
        except ValueError:
            page = 1
        data = storage.list_audit(
            action=request.args.get("action", ""),
            result=request.args.get("result", ""),
            page=page,
            page_size=50,
        )
        action_labels = {
            "login": "Вход", "logout": "Выход",
            "service.action": "Управление сервисом",
            "certificate.action": "Управление сертификатом",
            "project.update": "Обновление проекта",
            "project.update.prepare": "Подготовка обновления",
            "project.update.discard": "Удаление подготовленного обновления",
            "project.backup": "Бэкап проекта",
            "state.reconcile": "Повторное применение",
            "user.create": "Создание пользователя", "user.update": "Изменение пользователя",
            "user.set-enabled": "Изменение статуса пользователя", "user.rotate": "Смена ключей пользователя",
            "user.rotate-subscription": "Смена токена подписки", "user.reset-ocserv": "Смена пароля OpenConnect",
            "user.delete": "Удаление пользователя",
        }
        result_labels = {"success": "успешно", "failed": "ошибка", "unchanged": "без изменений"}
        detail_labels = {
            "service": "сервис", "action": "действие", "target": "объект",
            "before": "до", "after": "после", "duration_ms": "время, мс",
            "correlation_id": "ID операции", "health": "проверка",
            "unit": "unit", "backup_dir": "каталог бэкапов",
            "id": "ID", "name": "архив", "sha256": "SHA-256",
        }
        value_labels = {
            "start": "запуск", "stop": "остановка", "restart": "перезапуск",
            "reload": "перечитывание", "enable": "включение", "disable": "отключение",
            True: "да", False: "нет", None: "—",
        }
        for event in data["events"]:
            event["created_at_display"] = time.strftime(
                "%d.%m.%Y %H:%M:%S UTC", time.gmtime(int(event["created_at"]))
            )
            event["action_display"] = action_labels.get(event["action"], event["action"])
            event["result_display"] = result_labels.get(event["result"], event["result"])
            detail = event.get("detail", "")
            try:
                parsed = json.loads(detail)
            except (TypeError, ValueError):
                parsed = None
            event["detail_display"] = (
                "; ".join(
                    f"{detail_labels.get(key, key)}: {value_labels.get(value, value)}"
                    for key, value in parsed.items()
                )
                if isinstance(parsed, dict) else detail
            )
        return render_template("audit.html", data=data)

    @require_session
    def audit_export():
        events = []
        for page in range(1, 11):
            batch = storage.list_audit(
                action=request.args.get("action", ""),
                result=request.args.get("result", ""),
                page=page,
                page_size=100,
            )["events"]
            events.extend(batch)
            if len(batch) < 100:
                break
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["created_at", "actor", "ip", "action", "result", "target_type", "target_name", "correlation_id", "detail"])
        for event in events[:1000]:
            writer.writerow([event[key] for key in ["created_at", "actor", "ip", "action", "result", "target_type", "target_name", "correlation_id", "detail"]])
        response = Response(output.getvalue(), content_type="text/csv; charset=utf-8")
        response.headers["Content-Disposition"] = 'attachment; filename="kvn-audit.csv"'
        return response

    def format_backup_size(size: int) -> str:
        units = ["Б", "КиБ", "МиБ", "ГиБ"]
        value = float(max(size, 0))
        unit = units[0]
        for unit in units:
            if value < 1024 or unit == units[-1]:
                break
            value /= 1024
        return f"{value:.1f} {unit}" if unit != units[0] else f"{int(value)} {unit}"

    def backup_file_path(filename: str) -> Path | None:
        if filename != Path(filename).name or not BACKUP_FILENAME_RE.fullmatch(filename):
            return None
        backup_dir = Path(app.config["BACKUP_DIR"]).resolve()
        try:
            path = (backup_dir / filename).resolve()
        except OSError:
            return None
        if path.parent != backup_dir or path.is_symlink() or not path.is_file():
            return None
        return path

    def backup_rows(data: dict) -> tuple[list[dict], bool]:
        backup_dir = Path(app.config["BACKUP_DIR"])
        try:
            mount_available = backup_dir.resolve().is_dir()
        except OSError:
            mount_available = False
        downloadable = set()
        if mount_available:
            for candidate in backup_dir.glob("kvn-vpn-backup-*.tar"):
                if backup_file_path(candidate.name) is not None:
                    downloadable.add(candidate.name)
        rows = []
        for item in data.get("backups", []):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", ""))
            if not BACKUP_FILENAME_RE.fullmatch(name):
                continue
            try:
                size = int(item.get("size", 0))
                mtime = float(item.get("mtime", 0))
            except (TypeError, ValueError):
                size = 0
                mtime = 0
            rows.append({
                "name": name,
                "size": size,
                "size_display": format_backup_size(size),
                "mtime": mtime,
                "mtime_display": time.strftime("%d.%m.%Y %H:%M:%S UTC", time.gmtime(mtime)) if mtime else "—",
                "readable": bool(item.get("readable")),
                "can_download": name in downloadable,
            })
        return rows, mount_available

    @require_session
    def backups_view():
        if request.method == "POST":
            result = call_agent("project.backup", {})
            if not isinstance(result, dict):
                return result
            storage.audit(
                app.config["ADMIN_LOGIN"], g.client_ip, "project.backup",
                "success" if result.get("ok") else "failed",
                json.dumps(
                    {"unit": result.get("unit", ""), "backup_dir": result.get("backup_dir", "")},
                    separators=(",", ":"),
                ),
                now(), correlation_id=result.get("correlation_id", ""),
            )
            return render_template("backup_result.html", result=result)
        data = call_agent("backup.list", {})
        if not isinstance(data, dict):
            return data
        rows, mount_available = backup_rows(data)
        return render_template(
            "backups.html",
            data=data,
            backups=rows,
            backup_dir=app.config["BACKUP_DIR"],
            backup_mount_available=mount_available,
            csrf_token=g.session["csrf_token"],
        )

    @require_session
    def backup_download(filename: str):
        path = backup_file_path(filename)
        if path is None:
            return render_template("error.html", code=404, message="Бэкап не найден."), 404
        return send_file(
            path,
            mimetype="application/x-tar",
            as_attachment=True,
            download_name=filename,
            max_age=0,
        )

    @require_session
    def project_info():
        return render_template("project_info.html")

    @require_session
    def user_create():
        data = call_agent("state.users", {})
        if not isinstance(data, dict):
            return data
        if request.method == "GET":
            return render_template("user_form.html", mode="create", data=data, user=None, csrf_token=g.session["csrf_token"])
        result = call_agent(
            "state.apply",
            {"action": "create", "revision": request.form.get("revision", ""), "fields": parse_user_fields()},
            timeout=STATE_MUTATION_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            return result
        target_name = str((result.get("user") or {}).get("name") or request.form.get("name", ""))
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "user.create",
            "success" if result["changed"] else "unchanged", now=now(),
            target_type="user", target_name=target_name,
        )
        return render_template("user_result.html", result=result, action="Пользователь создан")

    @require_session
    def user_detail(name: str):
        data = call_agent("state.user", {"name": name})
        if not isinstance(data, dict):
            return data
        confirmations = {
            action: storage.create_confirmation(g.session_token, action, name, now())
            for action in ["delete", "rotate", "rotate-subscription", "reset-ocserv"]
        }
        return render_template(
            "user_detail.html",
            data=data,
            confirmations=confirmations,
            csrf_token=g.session["csrf_token"],
            background_activity=current_portal_performance()["features"]["background_refresh"],
            client_export=data.get("client_export", {}),
        )

    @require_session
    def user_activity_json(name: str):
        data = call_agent("user.activity", {"name": name}, timeout=7)
        if not isinstance(data, dict):
            return data
        audit = storage.list_audit(
            target_type="user", target_name=name, page=1, page_size=20,
        )
        events = []
        for event in audit["events"]:
            action = str(event.get("action", ""))
            result = str(event.get("result", ""))
            if not re.fullmatch(r"user\.[a-z-]{1,64}(?:\.[a-z-]{1,64})?", action) or result not in {"success", "failed", "unchanged"}:
                continue
            events.append({
                "created_at": int(event["created_at"]),
                "action": action,
                "result": result,
            })
        return jsonify({"ok": True, "activity": public_user_activity(data), "events": events})

    @require_session
    def user_edit(name: str):
        data = call_agent("state.user", {"name": name})
        if not isinstance(data, dict):
            return data
        all_data = call_agent("state.users", {})
        if not isinstance(all_data, dict):
            return all_data
        if request.method == "GET":
            return render_template(
                "user_form.html",
                mode="edit",
                data={**all_data, "revision": data["revision"]},
                user=data["user"],
                csrf_token=g.session["csrf_token"],
            )
        fields = parse_user_fields()
        fields["name"] = name
        result = call_agent(
            "state.apply",
            {"action": "update", "revision": request.form.get("revision", ""), "fields": fields},
            timeout=STATE_MUTATION_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            return result
        target_name = str((result.get("user") or {}).get("name") or name)
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "user.update",
            "success" if result["changed"] else "unchanged", now=now(),
            target_type="user", target_name=target_name,
        )
        return render_template("user_result.html", result=result, action="Пользователь обновлён")

    @require_session
    def user_action(name: str):
        action = request.form.get("action", "")
        token = request.form.get("confirmation_token", "")
        if action not in {"delete", "rotate", "rotate-subscription", "reset-ocserv"}:
            return render_template("error.html", code=400, message="Операция не разрешена."), 400
        if not storage.consume_confirmation(g.session_token, token, action, name, now()):
            return render_template("error.html", code=403, message="Подтверждение недействительно или уже использовано."), 403
        data = call_agent("state.user", {"name": name})
        if not isinstance(data, dict):
            return data
        result = call_agent(
            "state.apply",
            {"action": action, "revision": data["revision"], "fields": {"name": name}},
            timeout=STATE_MUTATION_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            return result
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, f"user.{action}", "success", now=now(),
            target_type="user", target_name=name,
        )
        return render_template("user_result.html", result=result, action="Операция выполнена")

    @require_session
    def user_toggle(name: str):
        result = call_agent(
            "state.apply",
            {
                "action": "set-enabled",
                "revision": request.form.get("revision", ""),
                "fields": {"name": name, "enabled": request.form.get("enabled") == "true"},
            },
            timeout=STATE_MUTATION_TIMEOUT_SECONDS,
        )
        if not isinstance(result, dict):
            return result
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "user.set-enabled",
            "success" if result["changed"] else "unchanged", now=now(),
            target_type="user", target_name=name,
        )
        return redirect(public_url("user_detail", name=name))

    @require_session
    def reconcile_state():
        result = call_agent("state.reconcile", {}, timeout=STATE_MUTATION_TIMEOUT_SECONDS)
        if not isinstance(result, dict):
            return result
        apply = result.get("apply", {})
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "state.reconcile",
            "failed" if apply.get("outcome") == "failed" else "success",
            now=now(),
        )
        return render_template("user_result.html", result=result, action="Состояние повторно применено")

    def render_settings_page(
        *,
        notice: str = "",
        error: str = "",
        client_export_error: str = "",
        client_export_form: dict | None = None,
        sni_diagnosis: dict | None = None,
        mtproto_diagnosis: dict | None = None,
        github_release: dict | None = None,
        github_error: str = "",
        github_error_code: str = "",
    ):
        """Собирает Settings одинаково для обычного GET и GitHub check."""
        sni_data = call_agent("sni.routes", {})
        if not isinstance(sni_data, dict):
            return sni_data
        mtproto_data = call_agent("mtproto.status", {})
        if not isinstance(mtproto_data, dict):
            return mtproto_data
        performance = call_agent("portal.performance", {})
        if not isinstance(performance, dict):
            return performance
        client_export = call_agent("client.export.settings", {})
        if not isinstance(client_export, dict):
            return client_export
        if client_export_form is not None and client_export_error:
            client_export = {
                **client_export,
                **client_export_form,
            }
        github_settings_error = ""
        try:
            github_settings = agent_client().call("project.release.settings", {}, timeout=5.0)
            if (
                not isinstance(github_settings, dict)
                or github_settings.get("repository") != "artemiygaer/kvn-portal"
                or github_settings.get("channel") not in {"stable", "tag"}
                or github_settings.get("asset_preference") not in {"release", "deploy"}
                or not isinstance(github_settings.get("enabled"), bool)
            ):
                raise ValueError("invalid settings")
        except (AgentClientError, TypeError, ValueError):
            github_settings = {
                "enabled": None,
                "repository": "artemiygaer/kvn-portal",
                "channel": "unknown",
                "tag": "",
                "asset_preference": "unknown",
            }
            github_settings_error = (
                "Настройки GitHub временно недоступны. Перезапустите "
                "kvn-portal-agent.service или используйте ручную загрузку."
            )
        return render_template(
            "settings.html",
            csrf_token=g.session["csrf_token"],
            admin_login=current_admin_login(),
            notice=notice,
            error=error,
            sni_diagnosis=sni_diagnosis,
            sni_data=sni_data,
            mtproto_diagnosis=mtproto_diagnosis,
            mtproto_data=mtproto_data,
            performance=performance,
            client_export=client_export,
            client_export_error=client_export_error,
            prepared_update=(
                public_prepared_update(prepared)
                if (prepared := storage.latest_prepared_update()) is not None
                else None
            ),
            github_settings=github_settings,
            github_settings_error=github_settings_error,
            github_release=github_release,
            github_error=github_error,
            github_error_code=github_error_code,
            languages=TRANSLATIONS,
        )

    @require_session
    def settings_view():
        notice = ""
        error = ""
        client_export_error = ""
        client_export_form = None
        sni_diagnosis = None
        mtproto_diagnosis = None
        if request.method == "POST":
            action = request.form.get("action", "")
            if action == "language":
                lang = request.form.get("language", "ru")
                if lang not in TRANSLATIONS:
                    return render_template("error.html", code=400, message="Язык не разрешён."), 400
                response = redirect(public_url("settings_view", saved="1"))
                response.set_cookie(
                    "kvn_lang",
                    lang,
                    secure=app.config["SESSION_COOKIE_SECURE"],
                    httponly=True,
                    samesite="Strict",
                    path=app.config["PORTAL_PATH"] + "/",
                    max_age=365 * 24 * 60 * 60,
                )
                storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "portal.language", "success", now=now())
                return response
            if action == "performance":
                profile = request.form.get("profile", "standard")
                result = call_agent("portal.performance.update", {
                    "revision": request.form.get("revision", ""),
                    "profile": profile,
                    "monitoring": request.form.get("monitoring") == "on",
                    "background_refresh": request.form.get("background_refresh") == "on",
                })
                if not isinstance(result, dict):
                    return result
                changed_features = result.get("changed_features", [])
                storage.audit(
                    app.config["ADMIN_LOGIN"], g.client_ip, "portal.performance",
                    "success" if result.get("changed") else "unchanged",
                    json.dumps({"changed_features": changed_features}, separators=(",", ":")),
                    now(),
                )
                notice = "Режим портала обновлён без перезапуска VPN-сервисов."
            elif action == "client_export":
                address_mode = request.form.get("address_mode", "")
                public_ip_value = request.form.get("public_ip", "")
                include_alternate = (
                    request.form.get("include_alternate") == "on"
                )
                client_export_form = {
                    "address_mode": address_mode,
                    "public_ip": public_ip_value.strip(),
                    "include_alternate": include_alternate,
                }
                if address_mode not in {"server", "public-ip"}:
                    client_export_error = "Выберите основной адрес: домен или IP."
                else:
                    try:
                        public_ip_value = validated_export_ipv4(
                            public_ip_value,
                            required=(
                                address_mode == "public-ip"
                                or include_alternate
                            ),
                        )
                    except ValueError as exc:
                        client_export_error = str(exc)
                if not client_export_error:
                    result = call_agent("client.export.update", {
                        "revision": request.form.get("revision", ""),
                        "address_mode": address_mode,
                        "public_ip": public_ip_value,
                        "include_alternate": include_alternate,
                    })
                    if not isinstance(result, dict):
                        return result
                    apply = result.get("apply", {})
                    audit_result = (
                        "failed"
                        if apply.get("outcome") == "failed"
                        else (
                            "success"
                            if result.get("changed")
                            else "unchanged"
                        )
                    )
                    storage.audit(
                        app.config["ADMIN_LOGIN"], g.client_ip,
                        "client.export.settings", audit_result,
                        json.dumps(
                            {
                                "address_mode": address_mode,
                                "include_alternate": include_alternate,
                                "has_public_ip": bool(public_ip_value),
                            },
                            separators=(",", ":"),
                        ),
                        now(),
                    )
                    notice = (
                        "Настройки экспорта сохранены."
                        if result.get("changed")
                        else "Настройки экспорта уже были в нужном состоянии."
                    )
                    if apply.get("outcome") == "failed":
                        client_export_error = (
                            "Настройки сохранены, но generated-файлы применены "
                            "не полностью. Выполните согласование состояния."
                        )
            elif action == "password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                repeat_password = request.form.get("repeat_password", "")
                if not verify_password(current_password, current_admin_password_hash()):
                    error = translate("wrong_current_password")
                elif new_password != repeat_password:
                    error = translate("passwords_do_not_match")
                else:
                    try:
                        new_hash = hash_password(new_password)
                    except ValueError as exc:
                        error = str(exc)
                    else:
                        result = call_agent("portal.credentials", {"password_hash": new_hash})
                        if not isinstance(result, dict):
                            return result
                        app.config["ADMIN_PASSWORD_HASH"] = new_hash
                        storage.invalidate_all_sessions()
                        storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "portal.password", "success", now=now())
                        response = redirect(public_url("login", changed="1"))
                        response.delete_cookie(app.config["SESSION_COOKIE_NAME"], path=app.config["PORTAL_PATH"] + "/")
                        return response
            elif action == "sni_diagnose":
                result = call_agent("sni.diagnose", {"sni": request.form.get("sni", "").strip()})
                if not isinstance(result, dict):
                    return result
                sni_diagnosis = result
                storage.audit(
                    app.config["ADMIN_LOGIN"], g.client_ip, "sni.diagnose", "success",
                    json.dumps({"sni": result.get("sni", ""), "result": result.get("reason", "")}, separators=(",", ":")),
                    now(),
                )
            elif action == "mtproto_diagnose":
                system = request.form.get("system", "")
                result = call_agent("mtproto.diagnose", {"system": system})
                if not isinstance(result, dict):
                    return result
                mtproto_diagnosis = result
                storage.audit(
                    app.config["ADMIN_LOGIN"], g.client_ip, "mtproto.diagnose", "success",
                    json.dumps(
                        {"system": system, "status": result.get("status", "")},
                        separators=(",", ":"),
                    ),
                    now(),
                )
            elif action == "mtproto_origin":
                system = request.form.get("system", "")
                result = call_agent("mtproto.apply", {
                    "revision": request.form.get("revision", ""),
                    "system": system,
                    "origin": request.form.get("origin", ""),
                })
                if not isinstance(result, dict):
                    return result
                apply = result.get("apply", {})
                storage.audit(
                    app.config["ADMIN_LOGIN"], g.client_ip, "mtproto.origin",
                    "failed" if apply.get("outcome") == "failed" else (
                        "success" if result.get("changed") else "unchanged"
                    ),
                    json.dumps({"system": system}, separators=(",", ":")),
                    now(),
                )
                notice = (
                    "Режим маскировки MTProto обновлён."
                    if result.get("changed") else "Режим маскировки уже был выбран."
                )
            elif action in {"sni_add", "sni_set_default", "sni_remove_alias"}:
                sni_action = {
                    "sni_add": "add-alias",
                    "sni_set_default": "set-default",
                    "sni_remove_alias": "remove-alias",
                }[action]
                result = call_agent("sni.apply", {
                    "action": sni_action,
                    "revision": request.form.get("revision", ""),
                    "system": request.form.get("system", ""),
                    "sni": request.form.get("sni", "").strip(),
                })
                if not isinstance(result, dict):
                    return result
                storage.audit(
                    app.config["ADMIN_LOGIN"], g.client_ip, f"sni.{sni_action}",
                    "success" if result.get("changed") else "unchanged",
                    json.dumps({"system": request.form.get("system", "")}, separators=(",", ":")),
                    now(),
                )
                notice = "SNI обновлены." if result.get("changed") else "SNI уже были в нужном состоянии."
            else:
                return render_template("error.html", code=400, message="Операция настроек не разрешена."), 400
        if request.args.get("saved") == "1":
            notice = translate("language_saved")
        elif request.args.get("prepared") == "1":
            notice = "Архив проверен и готов к запуску обновления."
        elif request.args.get("prepared") == "github":
            notice = "GitHub artifact скачан, проверен и готов к отдельному запуску."
        elif request.args.get("discarded") == "1":
            notice = "Подготовленный архив удалён."
        return render_settings_page(
            notice=notice,
            error=error,
            client_export_error=client_export_error,
            client_export_form=client_export_form,
            sni_diagnosis=sni_diagnosis,
            mtproto_diagnosis=mtproto_diagnosis,
        )

    @require_session
    def user_export_zip(name: str):
        return user_export_response(name, "zip")

    @require_session
    def user_export_text(name: str):
        return user_export_response(name, "text")

    def user_export_response(name: str, export_format: str):
        if (
            not EXPORT_USER_RE.fullmatch(name)
            or set(request.args) - {"address_mode"}
        ):
            return render_template(
                "error.html", code=400, message="Запрос экспорта отклонён.",
            ), 400
        address_mode = request.args.get("address_mode", "server")
        if address_mode not in {"server", "public-ip"}:
            return render_template(
                "error.html", code=400, message="Режим адреса экспорта не разрешён.",
            ), 400
        data = call_agent(
            "user.export",
            {"name": name, "address_mode": address_mode},
        )
        if not isinstance(data, dict):
            return data

        suffix = "zip" if export_format == "zip" else "txt"
        content_type = (
            "application/zip"
            if export_format == "zip"
            else "text/plain; charset=utf-8"
        )
        expected_filename = f"kvn-{name}-{address_mode}.{suffix}"
        prefix = "archive" if export_format == "zip" else "text"
        if (
            data.get(f"{prefix}_filename") != expected_filename
            or data.get(f"{prefix}_content_type") != content_type
        ):
            return render_template(
                "error.html", code=502,
                message="Host-agent вернул некорректные метаданные экспорта.",
            ), 502
        try:
            content = base64.b64decode(
                data[f"{prefix}_base64"], validate=True,
            )
            reported_size = int(data[f"{prefix}_size"])
        except (TypeError, ValueError, KeyError):
            return render_template(
                "error.html", code=502,
                message="Host-agent вернул повреждённый экспорт.",
            ), 502
        if (
            reported_size != len(content)
            or len(content) > EXPORT_LIMITS[export_format]
        ):
            return render_template(
                "error.html", code=502,
                message="Host-agent вернул экспорт недопустимого размера.",
            ), 502

        response = Response(content, content_type=content_type)
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{expected_filename}"'
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        detail = json.dumps(
            {
                "format": export_format,
                "address_mode": address_mode,
                "size": len(content),
                "result": "success",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "user.export", "success",
            detail, now(), target_type="user", target_name=name,
        )
        return response

    @require_session
    def user_download(name: str, filename: str):
        data = call_agent("user.file", {"name": name, "filename": filename})
        if not isinstance(data, dict):
            return data
        try:
            content = base64.b64decode(data["content_base64"], validate=True)
        except (ValueError, KeyError):
            return render_template("error.html", code=502, message="Host-agent вернул повреждённый файл."), 502
        response = Response(content, content_type=data["content_type"])
        response.headers["Content-Disposition"] = f'attachment; filename="{data["filename"]}"'
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "user.link.download", "success",
            now=now(), target_type="user", target_name=name,
        )
        return response

    @require_session
    def user_inline_file(name: str, filename: str):
        data = call_agent("user.file", {"name": name, "filename": filename})
        if not isinstance(data, dict):
            return data
        if data.get("content_type") != "image/png" or data.get("kind") not in QR_FILE_KINDS:
            return render_template("error.html", code=400, message="Inline-просмотр этого файла запрещён."), 400
        try:
            content = base64.b64decode(data["content_base64"], validate=True)
        except (ValueError, KeyError):
            return render_template("error.html", code=502, message="Host-agent вернул повреждённый файл."), 502
        response = Response(content, content_type="image/png")
        response.headers["Content-Disposition"] = f'inline; filename="{data["filename"]}"'
        return response

    @require_session
    def user_file_preview(name: str, filename: str):
        data = call_agent("user.file", {"name": name, "filename": filename})
        if not isinstance(data, dict):
            return data
        try:
            content = base64.b64decode(data["content_base64"], validate=True)
        except (ValueError, KeyError):
            return render_template("error.html", code=502, message="Host-agent вернул повреждённый файл."), 502
        if data.get("content_type") == "image/png" and data.get("kind") in QR_FILE_KINDS:
            storage.audit(
                app.config["ADMIN_LOGIN"], g.client_ip, "user.link.preview", "success",
                now=now(), target_type="user", target_name=name,
            )
            return render_template(
                "file_preview.html", name=name, filename=filename, content=None,
                image_url=public_url("user_inline_file", name=name, filename=filename),
            )
        if not any(
            str(data.get("content_type", "")).startswith(prefix)
            for prefix in ["text/plain", "application/json", "application/yaml", "application/toml"]
        ):
            return render_template("error.html", code=400, message="Просмотр этого типа файла запрещён."), 400
        try:
            text_content = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return render_template("error.html", code=400, message="Файл не является корректным UTF-8 текстом."), 400
        storage.audit(
            app.config["ADMIN_LOGIN"], g.client_ip, "user.link.preview", "success",
            now=now(), target_type="user", target_name=name,
        )
        return render_template(
            "file_preview.html", name=name, filename=filename,
            content=text_content, image_url=None,
        )

    @require_session
    def logout():
        storage.invalidate_session(g.session_token)
        storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "logout", "success", now=now())
        response = redirect(public_url("login"))
        response.delete_cookie(app.config["SESSION_COOKIE_NAME"], path=app.config["PORTAL_PATH"] + "/")
        return response

    def hysteria_auth():
        supplied = request.headers.get("X-KVN-Hysteria-Secret", "") or request.args.get("token", "")
        expected = app.config["HYSTERIA_SECRET"]
        if not expected or not hmac.compare_digest(supplied, expected):
            return {"ok": False}, 403
        payload = request.get_json(silent=True) or {}
        credential = payload.get("auth", "")
        if not isinstance(credential, str):
            return {"ok": False}, 401
        user_id = hysteria_users.authenticate(credential)
        if user_id is None:
            return {"ok": False}, 401
        return {"ok": True, "id": user_id}

    def internal_health():
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return {"ok": False}, 403
        return {"ok": True}

    def not_found(_error):
        return render_template("error.html", code=404, message="Страница не найдена."), 404

    def internal_error(_error):
        return render_template("error.html", code=500, message="Внутренняя ошибка портала."), 500


    available = locals()
    exported = {endpoint: available[endpoint] for endpoint in ROUTE_ENDPOINTS}
    exported.update(not_found=not_found, internal_error=internal_error)
    return exported
