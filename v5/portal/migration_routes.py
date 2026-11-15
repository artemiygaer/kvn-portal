"""Портал не читает открытый .kvn; preview привязан к текущему сеансу."""

from hashlib import sha256
from hmac import compare_digest
from threading import Lock

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, session, url_for

from v5.core.migration import MAX_ENCRYPTED

from .rpc import AgentRejected, AgentUnavailable

_ERRORS = {
    "migration_archive_invalid": "Неверная фраза или повреждённый архив.",
    "migration_archive_size": "Размер архива должен быть от 1 байта до 8 МиБ.",
    "migration_phrase_invalid": "Введите фразу из 12–256 символов, без переноса строки.",
    "migration_archive_empty": "В архиве нет VPN-пользователей.",
    "migration_version_unsupported": "Поддерживаются архивы v4.2 и v5.",
    "migration_restore_not_empty": "Для восстановления нужна пустая цель без пользователей и настроенных модулей.",
    "migration_identity_conflict": "Имя, идентификатор или ключ уже занят. Пользователи не изменены.",
    "migration_preview_stale": "Цель изменилась. Загрузите архив для нового предпросмотра.",
    "migration_ticket_invalid": "Предпросмотр истёк или уже использован. Загрузите архив заново.",
    "migration_snapshot_missing": "Снимок больше недоступен.",
    "migration_rollback_stale": "Состояние после импорта изменилось. Автоматический откат уже небезопасен.",
    "migration_target_busy": "Сначала завершите восстановление или настройку модуля.",
    "module_operation_busy": "Другая операция уже выполняется. Повторите позже.",
}


def register_migration(app, client, csrf_token, require_csrf):
    pages = Blueprint("migration", __name__)
    slot = Lock()

    def page(*, preview=None, mode=None):
        return render_template("migration/index.html", csrf=csrf_token(), preview=preview,
                               mode=mode, can_rollback=bool(session.get("migration_snapshot")))

    @pages.before_request
    def require_admin():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)

    @pages.get("/users/migration")
    def index():
        return page()

    @pages.post("/users/migration/<any(preview,commit,rollback,export):action>")
    def submit(action):
        if action == "preview" and request.content_length is None:
            abort(411)
        if not slot.acquire(blocking=False):
            abort(429)
        try:
            require_csrf()
            owner = sha256(("kvn-v5-migration:" + csrf_token()).encode()).hexdigest()
            if action == "preview":
                archive = request.files.get("archive")
                if archive is None or not archive.filename or not archive.filename.lower().endswith(".kvn"):
                    flash("Выберите штатный архив .kvn.")
                else:
                    try:
                        data = archive.stream.read(MAX_ENCRYPTED + 1)
                    finally:
                        archive.close()
                    if not 0 < len(data) <= MAX_ENCRYPTED:
                        flash(_ERRORS["migration_archive_size"])
                    else:
                        mode = request.form.get("mode", "")
                        if mode not in {"merge", "restore"}:
                            abort(400)
                        result = client.request("preview", body=data, size=len(data), owner=owner,
                                                phrase=request.form.get("phrase", ""), mode=mode)
                        return page(preview=result, mode=mode)
            elif action == "export":
                phrase = request.form.get("phrase", "")
                if not compare_digest(phrase.encode(), request.form.get("repeat", "").encode()):
                    flash("Фразы не совпадают.")
                else:
                    encrypted = client.request("export", phrase=phrase)
                    return Response(encrypted, mimetype="application/octet-stream", headers={
                        "Content-Disposition": 'attachment; filename="kvn-users-v5.kvn"'})
            elif request.form.get("confirm") != "yes":
                flash("Подтвердите действие.")
            elif action == "commit":
                result = client.request("commit", ticket=request.form.get("ticket", ""), owner=owner)
                session["migration_snapshot"] = result["snapshot"]
                flash("Пользователи перенесены. Импорт не устанавливает и не включает модули.")
            elif not session.get("migration_snapshot"):
                flash("В этом сеансе нет снимка для отката.")
            else:
                client.request("rollback", snapshot=session["migration_snapshot"])
                session.pop("migration_snapshot", None)
                flash("Состояние до импорта восстановлено.")
        except AgentRejected as exc:
            flash(_ERRORS.get(exc.code, "Архив или состояние назначения не прошло проверку."))
        except AgentUnavailable:
            flash("Ответ службы переноса не получен. Проверьте список пользователей перед повтором.")
        finally:
            slot.release()
        return redirect(url_for("migration.index"), code=303)

    app.register_blueprint(pages)
