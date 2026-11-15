"""Административный интерфейс подготовки и отдельного обновления ядра."""

import os

from flask import abort, flash, make_response, redirect, render_template, request, session, url_for

from v5.core.maintenance.core_bundle import MAX_BUNDLE

from .rpc import AgentRejected, AgentUnavailable

MESSAGES = {
    "publisher_not_configured": "Не закреплён ключ издателя. Обновление отклонено.",
    "insecure_publisher_pin": "Небезопасный файл ключа издателя.",
    "invalid_package_signature": "Подпись обновления не совпадает с доверенным ключом.",
    "core_version_not_newer": "Установлена такая же или более новая версия ядра.",
    "core_github_tag": "Укажите стабильный тег v5 или оставьте поле пустым.",
    "core_github_asset_missing": "В релизе нет пакета обновления ядра.",
    "core_github_metadata": "Не найден стабильный релиз v5 с корректным пакетом.",
    "core_github_digest": "SHA-256 файла GitHub не совпал.",
    "core_github_version": "Версия пакета не совпадает с тегом релиза.",
    "core_github_timeout": "GitHub не ответил вовремя.",
    "github_unavailable": "GitHub недоступен. Можно загрузить пакет вручную.",
    "github_redirect_refused": "GitHub вернул недопустимое перенаправление.",
    "core_prepared_limit": "Сначала удалите ненужные подготовленные пакеты.",
    "core_update_busy": "Другая операция с обновлением ещё выполняется.",
    "core_not_ready": "Пакет уже запущен, устарел или больше не готов.",
    "core_start_unavailable": "Не удалось передать обновление системной службе.",
}


def register_core_update(app, client, csrf_token, require_csrf, csp):
    @app.get("/maintenance/update")
    def core_update_page():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        try:
            status = client.status()
            if not isinstance(status.get("records"), list):
                raise AgentUnavailable
        except AgentUnavailable:
            status = None
        response = make_response(render_template("core_update.html", status=status, csrf=csrf_token(), messages=MESSAGES))
        response.headers["Content-Security-Policy"] = csp + "; script-src 'self'"
        return response

    @app.post("/maintenance/update/<any(upload,github,start,discard,reconcile):action>")
    def core_update_action(action):
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        require_csrf()
        try:
            if action == "upload":
                uploaded = request.files.get("bundle")
                if not uploaded:
                    abort(400)
                size = uploaded.stream.seek(0, os.SEEK_END)
                uploaded.stream.seek(0)
                if not 0 < size <= MAX_BUNDLE:
                    abort(413)
                client.upload(uploaded.stream, size)
                flash("Пакет проверен и готов к отдельному запуску.")
            elif action == "github":
                client.github(request.form.get("tag") or None)
                flash("Пакет с GitHub проверен и готов к отдельному запуску.")
            elif action == "start":
                if request.form.get("confirm") != "yes":
                    abort(400)
                client.start(request.form.get("ticket", ""))
                flash("Обновление передано системной службе. Портал может кратко отключиться.")
            elif action == "discard":
                if request.form.get("confirm") != "yes":
                    abort(400)
                client.discard(request.form.get("ticket", ""))
                flash("Запись подготовленного обновления удалена.")
            else:
                if request.form.get("confirm") != "yes":
                    abort(400)
                client.reconcile(request.form.get("ticket", ""))
                flash("Служба не работает. Проверьте восстановление по SSH перед повторной попыткой.", "error")
        except AgentRejected as exc:
            flash(MESSAGES.get(exc.code, "Обновление отклонено проверкой. Рабочее ядро не изменено."), "error")
        except AgentUnavailable:
            flash("Результат не подтверждён. Обновите страницу и проверьте состояние по SSH.", "error")
        return redirect(url_for("core_update_page"), code=303)
