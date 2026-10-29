"""Короткоживущие предварительные просмотры административного переноса."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable
from pathlib import Path

from tools.kvnlib.core.io import JsonStateStore, TransactionResult
from tools.kvnlib.core.migration import MAX_JSON_BYTES, parse_migration, plan_migration, validate_identity_complete
from tools.kvnlib.core.state import state_revision


class MigrationPreviewError(ValueError):
    """Предварительный просмотр истёк, изменился или недоступен сессии."""


class MigrationPreviews:
    """Держит расшифрованные данные только в памяти процесса host-agent."""

    def __init__(self, *, ttl: float = 300.0, capacity: int = 2, clock: Callable[[], float] = time.monotonic):
        self.ttl = ttl
        self.capacity = capacity
        self.clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, dict] = {}

    def _purge(self) -> None:
        now = self.clock()
        for key in [key for key, value in self._entries.items() if value["expires"] <= now]:
            self._entries.pop(key)["timer"].cancel()

    def _expire(self, identifier: str) -> None:
        with self._lock:
            entry = self._entries.get(identifier)
            if entry is not None and entry["expires"] <= self.clock():
                del self._entries[identifier]

    def preview(self, store: JsonStateStore, *, owner: str, encrypted: bytes, plaintext: bytes,
                mode: str, validate: Callable[[dict], None]) -> dict:
        if (not isinstance(owner, str) or not owner or not isinstance(encrypted, bytes)
                or not encrypted or len(encrypted) > 2 * MAX_JSON_BYTES):
            raise MigrationPreviewError("Некорректные параметры предварительного просмотра.")
        envelope = parse_migration(plaintext)
        validate_identity_complete(envelope)
        state = store.load()
        revision = state_revision(state)
        candidate = plan_migration(state, envelope, mode)
        validate(candidate)
        digest = hashlib.sha256(encrypted).hexdigest()
        with self._lock:
            self._purge()
            if len(self._entries) >= self.capacity:
                raise MigrationPreviewError("Достигнут лимит предварительных просмотров. Повторите позже.")
            identifier = secrets.token_hex(16)
            timer = threading.Timer(self.ttl, self._expire, args=(identifier,))
            timer.daemon = True
            self._entries[identifier] = {
                "owner": owner, "sha256": digest, "revision": revision, "mode": mode,
                "expires": self.clock() + self.ttl, "envelope": envelope, "timer": timer,
            }
            timer.start()
        return {
            "preview_id": identifier, "sha256": digest, "revision": revision,
            "mode": mode, "user_count": len(envelope["users"]),
            "add_count": len(envelope["users"]), "skip_count": 0, "conflict_count": 0,
            "endpoint_changed": envelope["source_server"] != state.get("server", ""),
            "expires_in": int(self.ttl),
            "warnings": [
                "Адрес целевого сервера и учётные данные портала сохраняются.",
                "Проверьте DNS и сертификаты; клиентские конфигурации может потребоваться экспортировать заново.",
            ],
        }

    def commit(self, store: JsonStateStore, *, identifier: str, owner: str, encrypted: bytes,
               backup_dir: Path, validate: Callable[[dict], None],
               commit: Callable[..., TransactionResult]) -> TransactionResult:
        digest = hashlib.sha256(encrypted).hexdigest() if isinstance(encrypted, bytes) else ""
        with self._lock:
            self._purge()
            entry = self._entries.get(identifier) if isinstance(identifier, str) else None
            if entry is None or not isinstance(owner, str) or not hmac.compare_digest(entry["owner"], owner) or not hmac.compare_digest(entry["sha256"], digest):
                raise MigrationPreviewError("Просмотр истёк, архив изменился или принадлежит другой сессии.")
            # Одноразовый просмотр: повтор после потери ответа не выполняет вторую транзакцию.
            del self._entries[identifier]
            entry["timer"].cancel()
        return commit(store, entry["envelope"], mode=entry["mode"], revision=entry["revision"],
                      backup_dir=backup_dir, validate=validate)

    def cancel(self, *, identifier: str, owner: str) -> None:
        """Удаляет расшифрованный просмотр только для его владельца."""
        with self._lock:
            self._purge()
            entry = self._entries.get(identifier) if isinstance(identifier, str) else None
            if entry is None or not isinstance(owner, str) or not hmac.compare_digest(entry["owner"], owner):
                raise MigrationPreviewError("Просмотр недоступен или уже истёк.")
            del self._entries[identifier]
            entry["timer"].cancel()
