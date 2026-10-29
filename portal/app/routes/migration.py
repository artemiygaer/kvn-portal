"""Безопасные служебные функции HTTP-мастера переноса VPN."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from pathlib import Path
from flask import g, jsonify, render_template, request, send_file

from ..agent_facade import AgentClientError
from ..security import token_hash

try:
    import fcntl
except ImportError:  # pragma: no cover — production развёрнут на Linux
    fcntl = None

_FILE_ID = re.compile(r"^[0-9a-f]{32}$")
_OWNER = re.compile(r"^[0-9a-f]{64}$")
_MAC = re.compile(r"^[0-9a-f]{64}$")
MAX_TICKET_SECONDS = 600
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_STAGED_FILES = 8
STAGED_RETENTION_SECONDS = 3600


def issue_ticket(secret: str, owner: str, file_id: str, purpose: str, *, now: int | None = None) -> str:
    """Подписывает краткоживущий доступ только для конкретной portal-сессии."""
    if (not isinstance(secret, str) or not secret or not isinstance(owner, str) or not _OWNER.fullmatch(owner)
            or not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id)
            or purpose not in {"upload", "download"}):
        raise ValueError("Некорректные параметры доступа к файлу переноса.")
    expires = int(time.time() if now is None else now) + MAX_TICKET_SECONDS
    message = f"migration:{purpose}:{owner}:{file_id}:{expires}".encode("ascii")
    mac = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{file_id}.{expires}.{mac}"


def verify_ticket(secret: str, owner: str, ticket: str, purpose: str, *, now: int | None = None) -> str:
    """Возвращает только ID; чужая сессия, цель или просроченная подпись запрещены."""
    if not isinstance(ticket, str) or len(ticket) > 128:
        raise ValueError("Доступ к файлу переноса недействителен.")
    parts = ticket.split(".")
    if (len(parts) != 3 or not _FILE_ID.fullmatch(parts[0]) or not parts[1].isdigit()
            or len(parts[1]) > 12 or not _MAC.fullmatch(parts[2])):
        raise ValueError("Доступ к файлу переноса недействителен.")
    current = int(time.time() if now is None else now)
    expires = int(parts[1])
    if expires <= current or expires > current + MAX_TICKET_SECONDS:
        raise ValueError("Срок доступа к файлу переноса истёк.")
    expected = issue_ticket(secret, owner, parts[0], purpose, now=expires - MAX_TICKET_SECONDS)
    if not hmac.compare_digest(expected, ticket):
        raise ValueError("Доступ к файлу переноса недействителен.")
    return parts[0]


def _open_directory(path: Path) -> int:
    """Открывает только приватный каталог без перехода по символьной ссылке."""
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or (os.name == "posix" and info.st_uid != os.geteuid())):
        os.close(fd)
        raise ValueError("Каталог переноса имеет небезопасные права.")
    return fd


def save_upload(directory: Path, stream) -> tuple[str, int]:
    """Принимает ограниченный ciphertext под случайным именем; plaintext не сохраняется."""
    parent = _open_directory(directory)
    name = secrets.token_hex(16)
    filename = name + ".kvn"
    created = False
    try:
        if fcntl is None:
            raise ValueError("Загрузка доступна только при поддержке блокировок Linux.")
        try:
            fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Другая загрузка уже выполняется. Повторите позже.") from exc
        cutoff = time.time() - STAGED_RETENTION_SECONDS
        for entry in os.listdir(parent):
            if not re.fullmatch(r"[0-9a-f]{32}\.kvn", entry):
                continue
            try:
                item = os.stat(entry, dir_fd=parent, follow_symlinks=False)
                if (stat.S_ISREG(item.st_mode) and item.st_uid == os.geteuid()
                        and item.st_nlink == 1 and item.st_mtime < cutoff):
                    os.unlink(entry, dir_fd=parent)
            except FileNotFoundError:
                continue
        existing = sum(1 for value in os.listdir(parent) if re.fullmatch(r"[0-9a-f]{32}\.kvn", value))
        if existing >= MAX_STAGED_FILES:
            raise ValueError("Достигнут лимит файлов переноса.")
        fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent)
        created = True
        with os.fdopen(fd, "wb") as output:
            size = 0
            while True:
                chunk = stream.read(min(65536, MAX_ARCHIVE_BYTES + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise ValueError("Файл переноса слишком велик.")
                output.write(chunk)
            if not size:
                raise ValueError("Файл переноса пуст.")
            output.flush()
            os.fsync(output.fileno())
        created = False
        return name, size
    finally:
        if created:
            os.unlink(filename, dir_fd=parent)
        os.close(parent)


def open_archive(directory: Path, file_id: str):
    """Открывает ограниченный обычный файл ciphertext для скачивания."""
    if not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id):
        raise ValueError("Некорректный файл переноса.")
    parent = _open_directory(directory)
    try:
        fd = os.open(file_id + ".kvn", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_ARCHIVE_BYTES
                or stat.S_IMODE(info.st_mode) != 0o600
                or (os.name == "posix" and info.st_uid != os.geteuid())):
            os.close(fd)
            raise ValueError("Некорректный файл переноса.")
        return os.fdopen(fd, "rb")
    finally:
        os.close(parent)


def remove_archive(directory: Path, file_id: str) -> None:
    """Удаляет только обычный приватный файл, не переходя по ссылкам."""
    if not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id) or fcntl is None:
        raise ValueError("Некорректный файл переноса.")
    parent = _open_directory(directory)
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        name = file_id + ".kvn"
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("Некорректный файл переноса.")
        os.unlink(name, dir_fd=parent)
    finally:
        os.close(parent)


def register_migration_routes(app, boundary, storage, agent_facade) -> None:
    """Регистрирует session-bound HTTP API; ключи доступны только host-agent."""
    prefix = app.config["PORTAL_PATH"] + "/migration"
    def directory() -> Path:
        return Path(app.config.get("MIGRATION_DIR", "/data/migration"))

    def owner() -> str:
        return token_hash(g.session_token)

    def payload() -> dict:
        if not request.is_json or (request.content_length is not None and request.content_length > 32768):
            return {}
        try:
            raw = request.stream.read(32769)
            if len(raw) > 32768:
                return {}
            data = json.loads(raw)
        except (UnicodeError, ValueError, RecursionError):
            return {}
        return data if isinstance(data, dict) else {}

    def audit(action: str, result: str) -> None:
        storage.audit(app.config["ADMIN_LOGIN"], g.client_ip, "migration." + action, result, now=boundary.now())

    def error(message: str, code: int = 400):
        return jsonify(ok=False, message=message), code

    def rpc(method: str, params: dict) -> dict:
        return agent_facade.client().call(method, {**params, "session_owner": owner()}, timeout=90)

    @app.get(prefix, endpoint="migration_view")
    @boundary.require_session
    def view():
        try:
            result = agent_facade.client().call("state.users", {}, timeout=10)
            users = result.get("users", []) if isinstance(result, dict) else []
        except AgentClientError:
            users = []
        names = [item["name"] for item in users if isinstance(item, dict) and isinstance(item.get("name"), str)]
        return render_template("migration.html", users=names, csrf_token=g.session["csrf_token"])

    @app.post(prefix + "/upload", endpoint="migration_upload")
    @boundary.require_session
    def upload():
        if request.mimetype != "application/octet-stream" or (request.content_length is not None and request.content_length > MAX_ARCHIVE_BYTES):
            return error("Выберите зашифрованный файл переноса размером не более 8 МиБ.")
        try:
            file_id, size = save_upload(directory(), request.stream)
            ticket = issue_ticket(app.config["PROXY_SECRET"], owner(), file_id, "upload", now=boundary.now())
        except (OSError, ValueError):
            audit("upload", "failed")
            return error("Не удалось загрузить файл переноса.")
        audit("upload", "success")
        return jsonify(ok=True, ticket=ticket, size=size)

    @app.post(prefix + "/export", endpoint="migration_export")
    @boundary.require_session
    def export():
        data = payload()
        if not isinstance(data.get("passphrase"), str) or data.get("passphrase") != data.get("passphrase_confirmation"):
            return error("Фразы шифрования не совпадают.")
        try:
            params = {"root_password": data.get("root_password", ""), "passphrase": data["passphrase"]}
            if "selected_users" in data:
                params["selected_users"] = data["selected_users"]
            result = rpc("migration.export", params)
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise ValueError("Экспорт не подтверждён агентом.")
            file_id = result.get("archive_id")
            digest, size = result.get("sha256"), result.get("size")
            if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or type(size) is not int or not 0 < size <= MAX_ARCHIVE_BYTES):
                raise ValueError("Некорректные метаданные архива.")
            ticket = issue_ticket(app.config["PROXY_SECRET"], owner(), file_id, "download", now=boundary.now())
        except (AgentClientError, ValueError):
            audit("export", "failed")
            return error("Экспорт не выполнен. Проверьте root-пароль, выбранных пользователей и GnuPG.")
        audit("export", "success")
        return jsonify(ok=True, ticket=ticket, size=size, sha256=digest)

    @app.get(prefix + "/download/<ticket>", endpoint="migration_download")
    @boundary.require_session
    def download(ticket):
        try:
            file_id = verify_ticket(app.config["PROXY_SECRET"], owner(), ticket, "download", now=boundary.now())
            stream = open_archive(directory(), file_id)
        except (ValueError, OSError):
            return error("Файл переноса недоступен или срок доступа истёк.", 404)
        return send_file(stream, mimetype="application/octet-stream", as_attachment=True,
                         download_name="kvn-vpn-migration.kvn", max_age=0)

    @app.post(prefix + "/preview", endpoint="migration_preview")
    @boundary.require_session
    def preview():
        data = payload()
        try:
            file_id = verify_ticket(app.config["PROXY_SECRET"], owner(), data.get("ticket"), "upload", now=boundary.now())
            result = rpc("migration.preview", {"archive_id": file_id, "root_password": data.get("root_password", ""),
                                                "passphrase": data.get("passphrase", ""), "mode": data.get("mode", "")})
            if (not isinstance(result, dict) or result.get("ok") is not True
                    or result.get("mode") != data.get("mode") or not isinstance(result.get("preview_id"), str)
                    or not _FILE_ID.fullmatch(result["preview_id"]) or result.get("mode") not in {"restore", "merge"}
                    or type(result.get("user_count")) is not int or not 0 <= result["user_count"] <= 2048
                    or any(type(result.get(key)) is not int or result[key] < 0 for key in ("add_count", "skip_count", "conflict_count"))
                    or result["add_count"] != result["user_count"] or result["skip_count"] != 0 or result["conflict_count"] != 0
                    or type(result.get("endpoint_changed")) is not bool):
                raise ValueError("Некорректные метаданные предварительного просмотра.")
        except AgentClientError as exc:
            audit("preview", "failed")
            if exc.code == "migration_conflict":
                return error("Конфликт с пользователями или настройками целевого сервера. Для полного восстановления нужна пустая VPN-цель; добавление не перезаписывает существующих пользователей.")
            return error("Архив не прошёл проверку или несовместим с сервером.")
        except ValueError:
            audit("preview", "failed")
            return error("Архив не прошёл проверку или несовместим с сервером.")
        safe = {key: result[key] for key in ("preview_id", "mode", "user_count", "add_count", "skip_count", "conflict_count", "endpoint_changed")}
        safe["warnings"] = ["Адрес и учётные данные целевого портала сохраняются.",
                            "Проверьте DNS и сертификаты; клиентские конфигурации может потребоваться экспортировать заново."]
        audit("preview", "success")
        return jsonify(ok=True, **safe)

    @app.post(prefix + "/commit", endpoint="migration_commit")
    @boundary.require_session
    def commit():
        data = payload()
        try:
            file_id = verify_ticket(app.config["PROXY_SECRET"], owner(), data.get("ticket"), "upload", now=boundary.now())
            result = rpc("migration.commit", {"archive_id": file_id, "root_password": data.get("root_password", ""),
                                               "preview_id": data.get("preview_id", "")})
            if (not isinstance(result, dict) or type(result.get("ok")) is not bool
                    or type(result.get("changed")) is not bool
                    or type(result.get("reconcile_required")) is not bool
                    or result.get("outcome") not in {"applied", "no-op", "fallback", "degraded"}
                    or result["ok"] == result["reconcile_required"]
                    or (result["outcome"] == "degraded") != result["reconcile_required"]
                    or not isinstance(result.get("revision"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", result["revision"])):
                raise ValueError("Некорректный результат применения.")
        except (AgentClientError, ValueError):
            audit("commit", "failed")
            return error("Не удалось подтвердить результат переноса. Проверьте пользователей и состояние сервисов перед повторной попыткой.")
        safe = {key: result[key] for key in ("ok", "changed", "revision", "outcome", "reconcile_required") if key in result}
        audit("commit", "success" if result.get("ok") else "degraded")
        if not result.get("ok"):
            safe["message"] = "Данные сохранены, но сервисы применены не полностью. Выполните reconcile и проверьте состояние сервисов."
        return jsonify(safe), 200 if result.get("ok") else 409

    @app.post(prefix + "/cancel", endpoint="migration_cancel")
    @boundary.require_session
    def cancel():
        data = payload()
        try:
            file_id = verify_ticket(app.config["PROXY_SECRET"], owner(), data.get("ticket"), "upload", now=boundary.now())
            preview_id = data.get("preview_id")
            agent_failed = False
            if preview_id:
                if not isinstance(preview_id, str) or not _FILE_ID.fullmatch(preview_id):
                    raise ValueError("Некорректный просмотр.")
                try:
                    rpc("migration.cancel", {"preview_id": preview_id})
                except AgentClientError:
                    agent_failed = True
            remove_archive(directory(), file_id)
            if agent_failed:
                raise ValueError("Не подтверждена очистка просмотра агента.")
        except (AgentClientError, OSError, ValueError):
            audit("cancel", "failed")
            return error("Не удалось подтвердить очистку; временные данные удаляются по сроку хранения.")
        audit("cancel", "success")
        return jsonify(ok=True)
