"""Изменение аккаунта Xray без доступа к состоянию других модулей."""

from dataclasses import replace
from uuid import uuid4

from .config import Settings
from .clients import client_profiles
from .credentials import Account
from .profiles import Kind


def set_user(settings: Settings, user_id: str, enabled: bool, *, imported=None) -> Settings:
    if not isinstance(settings, Settings) or type(enabled) is not bool:
        raise ValueError("Некорректные параметры пользователя Xray")
    current = next((account for account in settings.accounts if account.name == user_id), None)
    if current is None:
        if not enabled:
            return settings
        current = Account(user_id, imported["uuid"] if imported is not None else str(uuid4()), ())
    if imported is not None and imported["uuid"] != current.id:
        raise ValueError("Импортированный UUID конфликтует с ключом назначения")
    allowed = {Kind(value) for value in imported["profiles"]} if imported is not None else set(Kind)
    grants = tuple(profile.kind for profile in settings.profiles.values if profile.kind in allowed) if enabled else ()
    updated = replace(current, grants=grants)
    accounts = (tuple(updated if account.name == user_id else account for account in settings.accounts)
                if any(account.name == user_id for account in settings.accounts) else (*settings.accounts, updated))
    return replace(settings, accounts=accounts)


def subscription_uris(settings: Settings, user_id: str, endpoint: str, public_reality) -> tuple[str, ...]:
    account = next((item for item in settings.accounts if item.name == user_id), None)
    if account is None:
        return ()
    return tuple(profile.uri() for profile in client_profiles(settings, account.id, endpoint, public_reality, active=True))
