"""Административная страница локальных SSH-учёток."""

from flask import abort, flash, redirect, render_template, request, session, url_for

from .rpc import AgentRejected, AgentUnavailable


MESSAGES = {
    "ssh_login_invalid": "Допустимы строчные латинские буквы, цифры, дефис и подчёркивание; имя начинается с буквы.",
    "ssh_password_invalid": "Нужен пароль из 12–128 символов без двоеточия и перевода строки.",
    "ssh_key_invalid": "Вставьте одну строку публичного ключа OpenSSH Ed25519, без параметров.",
    "ssh_name_taken": "Имя, группа или домашний каталог уже существуют.",
    "ssh_limit": "Достигнут лимит учётных записей портала.",
    "ssh_account_changed": "Учётку изменили вне портала. Проверьте её по SSH.",
    "ssh_not_managed": "Этой учётной записью портал не управляет.",
    "ssh_account_disabled": "Для смены пароля сначала включите вход.",
    "ssh_disable_first": "Перед удалением заблокируйте вход.",
    "ssh_delete_failed": "Удаление не выполнено. Проверьте, что у пользователя нет запущенных процессов.",
    "ssh_key_install_failed": "Не удалось записать публичный ключ; проверьте состояние учётки по SSH.",
    "ssh_create_failed": "Система не смогла создать учётку.",
    "ssh_busy": "Другая операция выполняется. Повторите позже.",
}


def register_ssh_accounts(app, client, csrf_token, require_csrf, verify_admin):
    # В старых конфигурациях nginx /users/ уже имеет увеличенный тайм-аут.
    @app.route("/users/ssh-accounts", methods=["GET", "POST"])
    def ssh_accounts():
        if session.get("admin") is not True:
            return redirect(url_for("login"), code=303)
        if request.method == "GET":
            try:
                rows = client.ssh_accounts("list")["accounts"]
            except (AgentUnavailable, KeyError):
                rows = None
            return render_template("ssh_accounts.html", rows=rows, csrf=csrf_token())
        require_csrf()
        action = request.form.get("action")
        if action not in ("create", "password", "disable", "enable", "delete"):
            abort(400)
        if not verify_admin(request.form.get("admin_password", "")):
            flash("Пароль администратора не принят или превышен лимит попыток.", "error")
            return redirect(url_for("ssh_accounts"), code=303)
        params = {"login": request.form.get("login", "")}
        if action in ("create", "password"):
            params["password"] = request.form.get("password", "")
        if action == "create":
            params["key"] = request.form.get("key", "")
        if action == "delete" and request.form.get("confirm") != "yes":
            flash("Подтвердите удаление.", "error")
            return redirect(url_for("ssh_accounts"), code=303)
        try:
            client.ssh_accounts(action, **params)
            flash({"create": "Учётная запись создана.", "password": "Пароль изменён.",
                   "disable": "Новые входы заблокированы. Открытые сеансы не завершены.",
                   "enable": "Вход снова разрешён.", "delete": "Учётная запись удалена. Домашний каталог сохранён."}[action])
        except AgentRejected as exc:
            flash(MESSAGES.get(exc.code, "Операция не подтверждена. Обновите список и при необходимости проверьте сервер по SSH."), "error")
        except AgentUnavailable:
            flash("Служба недоступна. Обновите список перед повтором операции.", "error")
        return redirect(url_for("ssh_accounts"), code=303)
