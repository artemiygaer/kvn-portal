"""SQLite runtime-хранилище сессий, блокировок и аудита."""

from __future__ import annotations

import json
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .security import opaque_token, token_hash

LOCKOUT_FAILURES = 5
LOCKOUT_SECONDS = 12 * 60 * 60
SESSION_IDLE_SECONDS = 30 * 60
SESSION_ABSOLUTE_SECONDS = 8 * 60 * 60
_AUDIT_SECRET_RE = re.compile(
    r"(?i)(password|token|secret|private[_-]?key|preshared[_-]?key|uuid)(\s*[:=]\s*)([^\s,;\"}]+)"
)
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")


def redact_audit_text(value: str) -> str:
    value = _AUDIT_SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<скрыто>", value)
    return _UUID_RE.sub("<uuid>", value)


class PortalStorage:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    @contextmanager
    def connection(self):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
        finally:
            connection.close()

    def migrate(self) -> None:
        for attempt in range(50):
            try:
                self._migrate_once()
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 49:
                    raise
                time.sleep(0.1)

    def _migrate_once(self) -> None:
        with self.connection() as db:
            journal_mode = str(db.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if journal_mode != "wal":
                db.execute("PRAGMA journal_mode=WAL")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_hash TEXT PRIMARY KEY,
                    csrf_token TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    absolute_expires_at INTEGER NOT NULL,
                    ip TEXT NOT NULL,
                    user_agent TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_failures (
                    ip TEXT PRIMARY KEY,
                    failures INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    correlation_id TEXT NOT NULL DEFAULT '',
                    target_type TEXT NOT NULL DEFAULT '',
                    target_name TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS audit_created_at_idx ON audit_events(created_at);
                CREATE TABLE IF NOT EXISTS confirmations (
                    token_hash TEXT PRIMARY KEY,
                    session_hash TEXT NOT NULL,
                    action TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS prepared_updates (
                    id TEXT PRIMARY KEY,
                    archive TEXT UNIQUE NOT NULL,
                    archive_name TEXT NOT NULL,
                    archive_size INTEGER NOT NULL,
                    archive_sha256 TEXT NOT NULL,
                    archive_kind TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ready', 'starting', 'started')),
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    started_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS prepared_updates_status_idx
                    ON prepared_updates(status, created_at DESC);
                """
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(audit_events)")}
            if "correlation_id" not in columns:
                db.execute("ALTER TABLE audit_events ADD COLUMN correlation_id TEXT NOT NULL DEFAULT ''")
            if "target_type" not in columns:
                db.execute("ALTER TABLE audit_events ADD COLUMN target_type TEXT NOT NULL DEFAULT ''")
            if "target_name" not in columns:
                db.execute("ALTER TABLE audit_events ADD COLUMN target_name TEXT NOT NULL DEFAULT ''")
            db.execute(
                "CREATE INDEX IF NOT EXISTS audit_target_idx "
                "ON audit_events(target_type, target_name, id DESC)"
            )

    def create_session(self, ip: str, user_agent: str, now: int | None = None) -> tuple[str, str]:
        now = int(now if now is not None else time.time())
        session_token = opaque_token()
        csrf_token = opaque_token()
        with self.connection() as db:
            db.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    token_hash(session_token),
                    csrf_token,
                    now,
                    now,
                    now + SESSION_ABSOLUTE_SECONDS,
                    ip,
                    user_agent[:512],
                ),
            )
        return session_token, csrf_token

    def get_session(
        self,
        token: str,
        now: int | None = None,
        *,
        ip: str | None = None,
        user_agent: str | None = None,
    ):
        if not token:
            return None
        now = int(now if now is not None else time.time())
        session_hash = token_hash(token)
        with self.connection() as db:
            row = db.execute("SELECT * FROM sessions WHERE session_hash=?", (session_hash,)).fetchone()
            if row is None:
                return None
            if ip is not None and row["ip"] != ip:
                return None
            if user_agent is not None and row["user_agent"] != user_agent[:512]:
                return None
            if row["absolute_expires_at"] <= now or row["last_seen"] + SESSION_IDLE_SECONDS <= now:
                db.execute("DELETE FROM sessions WHERE session_hash=?", (session_hash,))
                return None
            db.execute("UPDATE sessions SET last_seen=? WHERE session_hash=?", (now, session_hash))
            return dict(row)

    def invalidate_session(self, token: str) -> None:
        if token:
            with self.connection() as db:
                db.execute("DELETE FROM sessions WHERE session_hash=?", (token_hash(token),))

    def invalidate_all_sessions(self) -> None:
        with self.connection() as db:
            db.execute("DELETE FROM sessions")

    def lock_status(self, ip: str, now: int | None = None) -> int:
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            row = db.execute("SELECT blocked_until FROM login_failures WHERE ip=?", (ip,)).fetchone()
            if row is None or row["blocked_until"] <= now:
                return 0
            return row["blocked_until"] - now

    def record_failure(self, ip: str, now: int | None = None) -> int:
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM login_failures WHERE ip=?", (ip,)).fetchone()
            if row is None or (row["blocked_until"] > 0 and row["blocked_until"] <= now):
                failures = 0
            else:
                failures = row["failures"]
            failures += 1
            blocked_until = now + LOCKOUT_SECONDS if failures >= LOCKOUT_FAILURES else 0
            db.execute(
                "INSERT INTO login_failures(ip, failures, blocked_until, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip) DO UPDATE SET failures=excluded.failures, blocked_until=excluded.blocked_until, updated_at=excluded.updated_at",
                (ip, failures, blocked_until, now),
            )
            db.execute("COMMIT")
            return max(0, blocked_until - now)

    def clear_failures(self, ip: str) -> None:
        with self.connection() as db:
            db.execute("DELETE FROM login_failures WHERE ip=?", (ip,))

    def audit(
        self,
        actor: str,
        ip: str,
        action: str,
        result: str,
        detail: str = "",
        now: int | None = None,
        correlation_id: str | None = None,
        target_type: str = "",
        target_name: str = "",
    ) -> None:
        now = int(now if now is not None else time.time())
        correlation_id = correlation_id or uuid.uuid4().hex
        with self.connection() as db:
            db.execute(
                "INSERT INTO audit_events("
                "created_at, actor, ip, action, result, detail, correlation_id, target_type, target_name"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    now, actor[:128], ip, action[:128], result[:64],
                    redact_audit_text(detail)[:1024], correlation_id[:64],
                    redact_audit_text(str(target_type))[:32],
                    redact_audit_text(str(target_name))[:128],
                ),
            )

    def list_audit(
        self,
        *,
        action: str = "",
        result: str = "",
        target_type: str = "",
        target_name: str = "",
        page: int = 1,
        page_size: int = 50,
    ) -> dict:
        page = max(1, min(int(page), 10000))
        page_size = max(1, min(int(page_size), 100))
        clauses = []
        params = []
        if action:
            clauses.append("action=?")
            params.append(action[:128])
        if result:
            clauses.append("result=?")
            params.append(result[:64])
        if target_type:
            clauses.append("target_type=?")
            params.append(target_type[:32])
        if target_name:
            clauses.append("target_name=?")
            params.append(target_name[:128])
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.connection() as db:
            total = db.execute(f"SELECT COUNT(*) FROM audit_events{where}", params).fetchone()[0]
            rows = db.execute(
                f"SELECT * FROM audit_events{where} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, page_size, (page - 1) * page_size],
            ).fetchall()
        return {"events": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size}

    def prune_audit(self, keep: int = 10000) -> None:
        keep = max(100, min(int(keep), 10000))
        with self.connection() as db:
            db.execute(
                "DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT ?)",
                (keep,),
            )

    def cleanup(self, now: int | None = None) -> None:
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            db.execute(
                "DELETE FROM sessions WHERE absolute_expires_at<=? OR last_seen<?",
                (now, now - SESSION_IDLE_SECONDS),
            )
            db.execute(
                "DELETE FROM login_failures WHERE blocked_until<=? AND updated_at<?",
                (now, now - LOCKOUT_SECONDS),
            )
            db.execute(
                "DELETE FROM audit_events WHERE id NOT IN (SELECT id FROM audit_events ORDER BY id DESC LIMIT 10000)"
            )
            db.execute("DELETE FROM confirmations WHERE expires_at<=? OR used=1", (now,))

    @staticmethod
    def _prepared_update(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        result = dict(row)
        try:
            metadata = json.loads(result.pop("metadata"))
        except (TypeError, ValueError):
            metadata = {}
        result["metadata"] = metadata if isinstance(metadata, dict) else {}
        return result

    def publish_prepared_update(self, metadata: dict, now: int | None = None) -> dict:
        """Атомарно публикует проверенный архив и заменяет прежний готовый."""
        now = int(now if now is not None else time.time())
        update_id = opaque_token(24)
        safe_metadata = {
            key: metadata[key]
            for key in (
                "archive_members",
                "release_source",
                "release_images",
                "required_free_bytes",
                "source",
                "repository",
                "channel",
                "tag",
                "release_id",
                "asset_id",
                "validation",
            )
            if key in metadata
        }
        values = (
            update_id,
            str(metadata["archive"]),
            str(metadata["archive_name"]),
            int(metadata["archive_size"]),
            str(metadata["archive_sha256"]).lower(),
            str(metadata["archive_kind"]),
            json.dumps(safe_metadata, ensure_ascii=False, separators=(",", ":")),
            now,
            now,
        )
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            busy_row = db.execute(
                "SELECT * FROM prepared_updates WHERE archive=? AND status='starting'",
                (values[1],),
            ).fetchone()
            if busy_row is not None:
                db.execute("COMMIT")
                return {
                    "update": self._prepared_update(busy_row),
                    "replaced": [],
                    "busy": True,
                }
            replaced_rows = db.execute(
                "SELECT * FROM prepared_updates WHERE status='ready' ORDER BY created_at DESC"
            ).fetchall()
            db.execute("DELETE FROM prepared_updates WHERE status='ready'")
            db.execute(
                "DELETE FROM prepared_updates WHERE archive=? AND status='started'",
                (values[1],),
            )
            db.execute(
                """
                INSERT INTO prepared_updates(
                    id, archive, archive_name, archive_size, archive_sha256,
                    archive_kind, metadata, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ready', ?, ?)
                """,
                values,
            )
            row = db.execute("SELECT * FROM prepared_updates WHERE id=?", (update_id,)).fetchone()
            db.execute("COMMIT")
        return {
            "update": self._prepared_update(row),
            "replaced": [self._prepared_update(item) for item in replaced_rows],
            "busy": False,
        }

    def latest_prepared_update(self) -> dict | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM prepared_updates WHERE status='ready' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        return self._prepared_update(row)

    def get_prepared_update(self, update_id: str) -> dict | None:
        with self.connection() as db:
            row = db.execute("SELECT * FROM prepared_updates WHERE id=?", (update_id,)).fetchone()
        return self._prepared_update(row)

    def claim_prepared_update(self, update_id: str, now: int | None = None) -> dict | None:
        """Атомарно переводит готовое обновление в запуск; побеждает один запрос."""
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE prepared_updates SET status='starting', updated_at=? WHERE id=? AND status='ready'",
                (now, update_id),
            ).rowcount
            row = db.execute("SELECT * FROM prepared_updates WHERE id=?", (update_id,)).fetchone() if changed else None
            db.execute("COMMIT")
        return self._prepared_update(row)

    def release_prepared_update(self, update_id: str, now: int | None = None) -> bool:
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            changed = db.execute(
                "UPDATE prepared_updates SET status='ready', updated_at=? WHERE id=? AND status='starting'",
                (now, update_id),
            ).rowcount
        return bool(changed)

    def finish_prepared_update(self, update_id: str, now: int | None = None) -> bool:
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            changed = db.execute(
                """
                UPDATE prepared_updates
                SET status='started', updated_at=?, started_at=?
                WHERE id=? AND status='starting'
                """,
                (now, now, update_id),
            ).rowcount
        return bool(changed)

    def discard_prepared_update(self, update_id: str) -> dict | None:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM prepared_updates WHERE id=? AND status='ready'",
                (update_id,),
            ).fetchone()
            if row is not None:
                db.execute("DELETE FROM prepared_updates WHERE id=? AND status='ready'", (update_id,))
            db.execute("COMMIT")
        return self._prepared_update(row)

    def remove_prepared_update_by_archive(self, archive: str) -> None:
        with self.connection() as db:
            db.execute("DELETE FROM prepared_updates WHERE archive=?", (archive,))

    def create_confirmation(self, session_token: str, action: str, subject: str, now: int | None = None) -> str:
        now = int(now if now is not None else time.time())
        token = opaque_token(24)
        with self.connection() as db:
            db.execute(
                "INSERT INTO confirmations VALUES (?, ?, ?, ?, ?, 0)",
                (token_hash(token), token_hash(session_token), action, subject, now + 300),
            )
        return token

    def consume_confirmation(
        self,
        session_token: str,
        token: str,
        action: str,
        subject: str,
        now: int | None = None,
    ) -> bool:
        now = int(now if now is not None else time.time())
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM confirmations WHERE token_hash=?",
                (token_hash(token),),
            ).fetchone()
            valid = bool(
                row
                and not row["used"]
                and row["expires_at"] > now
                and row["session_hash"] == token_hash(session_token)
                and row["action"] == action
                and row["subject"] == subject
            )
            if valid:
                db.execute("UPDATE confirmations SET used=1 WHERE token_hash=?", (token_hash(token),))
            db.execute("COMMIT")
            return valid
