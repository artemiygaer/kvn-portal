"""Изменение одного аккаунта Hysteria без потери секрета при отзыве."""

from dataclasses import replace

from .config import Account, Settings
from .clients import client_profile


def set_user(settings: Settings, user_id: str, enabled: bool, *, imported=None) -> Settings:
    if not isinstance(settings, Settings) or type(enabled) is not bool:
        raise ValueError("Некорректные параметры пользователя Hysteria")
    name = imported["login"] if imported is not None else user_id
    current = next((account for account in settings.accounts if account.name == name), None)
    if current is None:
        if not enabled:
            return settings
        current = Account(name, imported["password"], imported=True) if imported is not None else Account.create(name)
    if imported is not None and (not current.imported or imported["password"] != current.password):
        raise ValueError("Импортированный пароль конфликтует с учётной записью назначения")
    updated = replace(current, enabled=enabled)
    accounts = (tuple(updated if account.name == name else account for account in settings.accounts)
                if any(account.name == name for account in settings.accounts) else (*settings.accounts, updated))
    return replace(settings, accounts=accounts)


def subscription_uris(settings: Settings, user_id: str, *, imported=None) -> tuple[str, ...]:
    profile = client_profile(settings, imported["login"] if imported is not None else user_id, active=True)
    return () if profile is None else (profile.uri(),)
