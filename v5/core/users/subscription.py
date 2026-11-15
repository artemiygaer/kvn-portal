"""Подписка только по токену и подтверждённым правам текущего runtime."""

import base64
import re
from typing import Protocol
from urllib.parse import parse_qs, urlsplit

from .model import ModuleState, SubscriptionToken, User
from .store import UserStore

MAX_URIS = 32
MAX_URI_BYTES = 8192
MAX_CONFIG_BYTES = 4096
CONFIG_MODULES = frozenset({"amneziawg", "wireguard"})
URI_MODULES = frozenset({"xray", "hysteria"})


class SubscriptionModule(Protocol):
    def state(self) -> ModuleState: ...
    def subscription_uris(self, user: User) -> tuple[str, ...]: ...


def _safe_uri(value: str, *, telegram=False) -> bool:
    if not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= MAX_URI_BYTES:
        return False
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        return False
    try:
        parsed = urlsplit(value)
        if telegram:
            if (parsed.scheme, parsed.netloc, parsed.path, parsed.fragment) != ("tg", "proxy", "", ""):
                return False
            fields = parse_qs(parsed.query, strict_parsing=True, max_num_fields=3)
            return (fields.keys() == {"server", "port", "secret"} and all(len(items) == 1 for items in fields.values())
                    and fields["port"][0] in {"443", "2446"}
                    and re.fullmatch(r"ee(?:[0-9a-f]{2}){17,196}", fields["secret"][0]) is not None)
        return parsed.scheme in {"vless", "hysteria2"} and bool(parsed.netloc) and parsed.port is not None
    except ValueError:
        return False


class SubscriptionService:
    def __init__(self, store: UserStore, modules: dict[str, SubscriptionModule], guard):
        self.store, self.modules, self.guard = store, dict(modules), guard

    def render(self, token: SubscriptionToken) -> bytes | None:
        with self.guard():
            owner = self.store.subscription_owner(token)
            if owner is None:
                return None
            values = self._profiles_locked(owner)
            if values is None or self.store.subscription_owner(token) != owner:
                return None
            if not values:
                return b""
            return base64.b64encode(("\n".join(values) + "\n").encode("ascii"))

    def profiles(self, user_id: str) -> tuple[str, ...] | None:
        with self.guard():
            return self._profiles_locked(user_id, include_telegram=True)

    def config(self, user_id: str, name: str) -> bytes | None:
        """Отдельный файл туннеля: не включать в URI-подписку по токену."""
        if not isinstance(name, str) or name not in CONFIG_MODULES:
            return None
        with self.guard():
            result, module = self.store.get(user_id), self.modules.get(name)
            if result is None or module is None or not result[0].enabled:
                return None
            user, revision, grants = result
            grant = next((item for item in grants if item.grant.module_id == name), None)
            if grant is None or not grant.grant.enabled or not grant.applied or grant.error:
                return None
            try:
                if not grant.can_export(user, module.state()):
                    return None
                raw = module.client_config(user)
            except Exception:
                return None
            if (not isinstance(raw, bytes) or not raw.startswith(b"[Interface]\n")
                    or len(raw) > MAX_CONFIG_BYTES or not raw.isascii()):
                return None
            latest = self.store.get(user_id)
            return raw if latest is not None and latest[1] == revision else None

    def _profiles_locked(self, owner: str, *, include_telegram=False) -> tuple[str, ...] | None:
        result = self.store.get(owner)
        if result is None or not result[0].enabled:
            return None
        user, revision, grants = result
        values = []
        for grant in grants:
            name = grant.grant.module_id
            telegram = include_telegram and name == "telemt"
            if ((name not in URI_MODULES and not telegram) or not grant.grant.enabled
                    or not grant.applied or grant.error):
                continue
            module = self.modules.get(name)
            if module is None:
                continue
            try:
                state = module.state()
                if not isinstance(state, ModuleState) or state.module != name:
                    return None
                if not grant.can_export(user, state):
                    continue
                uris = module.subscription_uris(user)
            except Exception:
                return None
            if not isinstance(uris, tuple) or not all(_safe_uri(item, telegram=telegram) for item in uris):
                return None
            values.extend(uris)
            if len(values) > MAX_URIS:
                return None
        latest = self.store.get(owner)
        if latest is None or latest[1] != revision:
            return None
        return tuple(values)
