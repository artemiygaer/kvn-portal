"""Ограниченный RPC защищённого переноса через host-agent."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from portal.agent_protocol import ProtocolError
from portal.control.migration import MigrationPreviewError, MigrationPreviews
from tools.kvnlib.core.errors import StateRevisionConflict
from tools.kvnlib.core.migration import MigrationValidationError
from tools.kvnlib.exports.migration import build_migration
from tools.kvnlib.runtime.migration import MAX_ENCRYPTED_BYTES, MigrationCryptoError, commit_migration, decrypt_migration, encrypt_migration

from .contract import HandlerSpec

_ID = re.compile(r"^[0-9a-f]{32}$")


def _apply_outcome(report: object) -> tuple[str, bool]:
    """Различает успешный fallback и неполное применение без утечки деталей."""
    if not isinstance(report, dict):
        return "degraded", True
    outcome = report.get("outcome")
    degraded = (outcome not in {"applied", "no-op", "fallback"}
                or bool(report.get("reconcile_required")) or bool(report.get("failed")))
    return ("degraded" if degraded else outcome), degraded


def _identity(state: dict) -> str:
    """Контрольные данные только в памяти; в response и журнал не попадают."""
    users = []
    for user in state.get("users", []):
        users.append({key: user.get(key) for key in ("name", "uuid", "hysteria_password", "telemt_secret", "ocserv_password", "sub_token", "amneziawg", "wireguard")})
    protocols = {}
    for section, keys in {
        "reality": ("privateKey", "public_key", "short_id", "shortIds"),
        "reality_tcp": ("privateKey", "public_key", "short_id", "shortIds"),
        "amneziawg": ("private_key", "public_key", "obfuscation", "v3"),
        "wireguard": ("private_key", "public_key"),
        "mtg": ("secret16",),
    }.items():
        config = state.get(section, {})
        protocols[section] = {key: config.get(key) for key in keys}
    return json.dumps({"users": users, "protocols": protocols}, sort_keys=True, ensure_ascii=False)


class MigrationHandler:
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.previews = MigrationPreviews()

    def _auth(self, params: dict) -> str:
        owner = self.dispatcher._shell_owner(params)
        self.dispatcher._shell_auth_allowed(owner)
        if not self.dispatcher._verify_root_password(params.get("root_password", "")):
            self.dispatcher._record_shell_auth_failure(owner)
            raise ProtocolError("root_password_denied", "Пароль root указан неверно.")
        self.dispatcher._clear_shell_auth_failures(owner)
        return owner

    def _directory(self) -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        parent = os.open(self.dispatcher.project_root / "portal-data", flags)
        try:
            parent_info = os.fstat(parent)
            try:
                os.mkdir("migration", mode=0o700, dir_fd=parent)
                os.chown("migration", parent_info.st_uid, parent_info.st_gid, dir_fd=parent, follow_symlinks=False)
            except FileExistsError:
                pass
            directory = os.open("migration", flags, dir_fd=parent)
            details = os.fstat(directory)
            if details.st_uid != parent_info.st_uid or stat.S_IMODE(details.st_mode) != 0o700:
                os.close(directory)
                raise ProtocolError("migration_storage_denied", "Каталог переноса имеет небезопасные права.")
            return directory, details
        finally:
            os.close(parent)

    def _read(self, identifier: object) -> bytes:
        if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
            raise ProtocolError("invalid_params", "Некорректный идентификатор файла переноса.")
        directory, info = self._directory()
        try:
            fd = os.open(identifier + ".kvn", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
            try:
                file_info = os.fstat(fd)
                if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != info.st_uid
                        or file_info.st_nlink != 1 or file_info.st_size < 1 or file_info.st_size > MAX_ENCRYPTED_BYTES):
                    raise ProtocolError("invalid_archive", "Некорректный файл переноса.")
                chunks = []
                remaining = MAX_ENCRYPTED_BYTES + 1
                while remaining:
                    chunk = os.read(fd, min(remaining, 65536))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                result = b"".join(chunks)
                if len(result) > MAX_ENCRYPTED_BYTES:
                    raise ProtocolError("invalid_archive", "Файл переноса превышает допустимый размер.")
                return result
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def _validate(self, state: dict) -> None:
        before = _identity(state)
        try:
            self.dispatcher._control().kvnctl.prepare_state(state)
        except (Exception, SystemExit) as exc:
            raise ProtocolError("migration_invalid", "Проверка конфигурации VPN не пройдена; состояние не изменено.") from exc
        if _identity(state) != before:
            raise ProtocolError("migration_identity_changed", "Конфигурация вызвала бы изменение ключей; перенос остановлен.")

    def export(self, params: dict) -> dict:
        self._auth(params)
        try:
            state = self.dispatcher._control().kvnctl.STATE_STORE.load()
            ciphertext = encrypt_migration(build_migration(state), params.get("passphrase", ""))
            directory, info = self._directory()
            try:
                import secrets
                identifier = secrets.token_hex(16)
                fd = os.open(identifier + ".kvn", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory)
                try:
                    os.fchown(fd, info.st_uid, info.st_gid)
                    with os.fdopen(os.dup(fd), "wb") as output:
                        output.write(ciphertext)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    os.close(fd)
            finally:
                os.close(directory)
            return {"ok": True, "archive_id": identifier, "size": len(ciphertext), "sha256": hashlib.sha256(ciphertext).hexdigest()}
        except (MigrationValidationError, MigrationCryptoError, OSError) as exc:
            raise ProtocolError("migration_export_failed", "Экспорт не выполнен: проверьте состояние VPN и GnuPG.") from exc

    def preview(self, params: dict) -> dict:
        owner = self._auth(params)
        try:
            encrypted = self._read(params.get("archive_id"))
            plaintext = decrypt_migration(encrypted, params.get("passphrase", ""))
            result = self.previews.preview(self.dispatcher._control().kvnctl.STATE_STORE, owner=owner,
                                           encrypted=encrypted, plaintext=plaintext, mode=params.get("mode"), validate=self._validate)
            return {"ok": True, **result}
        except (MigrationValidationError, MigrationCryptoError, MigrationPreviewError, OSError) as exc:
            raise ProtocolError("migration_preview_failed", "Архив не прошёл проверку или несовместим с целевым сервером.") from exc

    def commit(self, params: dict) -> dict:
        owner = self._auth(params)
        try:
            encrypted = self._read(params.get("archive_id"))
            result = self.previews.commit(self.dispatcher._control().kvnctl.STATE_STORE,
                                          identifier=params.get("preview_id"), owner=owner, encrypted=encrypted,
                                          backup_dir=Path("/var/lib/kvn-portal/migration-backups"),
                                          validate=self._validate, commit=commit_migration)
        except StateRevisionConflict as exc:
            raise ProtocolError("revision_conflict", "Состояние изменилось; повторите предварительный просмотр.") from exc
        except (MigrationValidationError, MigrationCryptoError, MigrationPreviewError, OSError) as exc:
            raise ProtocolError("migration_commit_failed", "Перенос не выполнен; повторите предварительную проверку.") from exc
        try:
            control = self.dispatcher._control()
            render = control.kvnctl.render_all(copy.deepcopy(result.state))
            apply = control.kvnctl.restart_services(render, before_state=result.before_state, after_state=result.state,
                                                    force_host_sync_services=control._state_host_sync_services(result.state))
            outcome, degraded = _apply_outcome(apply)
        except (Exception, SystemExit):
            outcome = "degraded"
            degraded = True
        return {"ok": not degraded, "changed": result.changed, "revision": result.after_revision,
                "outcome": outcome, "reconcile_required": degraded}


def handlers(dispatcher):
    handler = MigrationHandler(dispatcher)
    return {
        "migration.export": HandlerSpec(handler.export, True, frozenset({"session_owner", "root_password", "passphrase"})),
        "migration.preview": HandlerSpec(handler.preview, True, frozenset({"session_owner", "root_password", "passphrase", "archive_id", "mode"})),
        "migration.commit": HandlerSpec(handler.commit, True, frozenset({"session_owner", "root_password", "archive_id", "preview_id"})),
    }
