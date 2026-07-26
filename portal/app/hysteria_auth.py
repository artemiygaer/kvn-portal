"""Fail-closed cache пользователей для внутренней Hysteria HTTP-auth."""

from __future__ import annotations

import hmac
import json
import threading
from pathlib import Path


class HysteriaUserCache:
    def __init__(self, users_file: Path):
        self.users_file = Path(users_file)
        self._lock = threading.Lock()
        self._signature = None
        self._users: dict[str, str] = {}

    def _load(self) -> dict[str, str]:
        stat = self.users_file.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        with self._lock:
            if signature == self._signature:
                return self._users
            state = json.loads(self.users_file.read_text(encoding="utf-8"))
            users = {}
            for user in state.get("users", []):
                if not user.get("enabled", True) or "hysteria" not in user.get("systems", []):
                    continue
                password = user.get("hysteria_password")
                if isinstance(password, str) and password:
                    users[user["name"]] = password
            self._users = users
            self._signature = signature
            return users

    def authenticate(self, credential: str) -> str | None:
        try:
            users = self._load()
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if ":" not in credential:
            return None
        supplied_name, supplied_password = credential.split(":", 1)
        for name, password in users.items():
            name_ok = hmac.compare_digest(supplied_name, name)
            password_ok = hmac.compare_digest(supplied_password, password)
            if name_ok and password_ok:
                return name
        return None
