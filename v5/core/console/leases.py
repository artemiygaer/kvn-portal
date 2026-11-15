"""Одноразовый допуск к PTY: короткое окно, один терминал, отзыв при выходе."""

from collections import deque
from dataclasses import dataclass, field
import secrets
from threading import Event, Lock
import time

from .protocol import token

GRANT_SECONDS = 25
SESSION_SECONDS = 600
SESSION_REVOKED = 31 * 60


@dataclass
class Lease:
    session: str = field(repr=False)
    until: float
    cancelled: Event = field(default_factory=Event, repr=False)


class Leases:
    def __init__(self, authenticate, clock=time.monotonic):
        self.authenticate, self.clock = authenticate, clock
        self.lock = Lock()
        self.auth_slot = Lock()
        self.attempts = deque()
        self.grants = {}
        self.revoked = {}
        self.deny_until = float("-inf")
        self.active: Lease | None = None

    def _trim(self, now):
        self.grants = {key: grant for key, grant in self.grants.items() if grant[1] > now}
        self.revoked = {key: expiry for key, expiry in self.revoked.items() if expiry > now}
        while self.attempts and self.attempts[0] <= now - 60:
            self.attempts.popleft()

    def issue(self, session, password) -> str:
        if not token(session) or not isinstance(password, str):
            raise ValueError("invalid_request")
        if not self.auth_slot.acquire(blocking=False):
            raise ValueError("console_busy")
        try:
            with self.lock:
                now = self.clock()
                self._trim(now)
                if session in self.revoked or self.deny_until > now:
                    raise ValueError("console_session_revoked")
                if len(self.attempts) >= 5 or len(self.grants) >= 8 or self.active is not None:
                    raise ValueError("console_busy")
                self.attempts.append(now)
            if not self.authenticate(password):
                raise ValueError("console_auth_failed")
            with self.lock:
                now = self.clock()
                if session in self.revoked or self.deny_until > now:
                    raise ValueError("console_session_revoked")
                if self.active is not None:
                    raise ValueError("console_busy")
                grant = secrets.token_urlsafe(32)
                self.grants = {key: item for key, item in self.grants.items() if item[0] != session}
                self.grants[grant] = session, now + GRANT_SECONDS
                return grant
        finally:
            self.auth_slot.release()

    def consume(self, session, grant) -> Lease:
        if not token(session) or not token(grant):
            raise ValueError("invalid_request")
        with self.lock:
            now = self.clock()
            self._trim(now)
            if session in self.revoked or self.deny_until > now:
                raise ValueError("console_session_revoked")
            value = self.grants.get(grant)
            if value is None or value[0] != session:
                raise ValueError("console_grant_invalid")
            if self.active is not None:
                raise ValueError("console_busy")
            del self.grants[grant]
            self.active = Lease(session, now + SESSION_SECONDS)
            return self.active

    def release(self, lease):
        with self.lock:
            if self.active is lease:
                self.active = None

    def revoke(self, session):
        if not token(session):
            raise ValueError("invalid_request")
        with self.lock:
            now = self.clock()
            self._trim(now)
            if len(self.revoked) >= 128:
                self.deny_until = now + SESSION_REVOKED
                self.revoked.clear()
                self.grants.clear()
                if self.active is not None:
                    self.active.cancelled.set()
            self.revoked[session] = now + SESSION_REVOKED
            self.grants = {key: value for key, value in self.grants.items() if value[0] != session}
            if self.active is not None and self.active.session == session:
                self.active.cancelled.set()
