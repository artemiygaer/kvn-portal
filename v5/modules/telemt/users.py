"""Проекция персонального секрета и восстановление отдельных legacy-аккаунтов."""

from dataclasses import replace

from v5.modules.mtproto_common.profiles import Secret

from .settings import Account, Settings


def set_user(settings, user_id, enabled, *, imported=None):
    if not isinstance(settings, Settings) or type(enabled) is not bool:
        raise ValueError("Некорректное право Telemt")
    current = next((item for item in settings.accounts if item.name == user_id), None)
    secret = Secret(imported["secret"]) if imported is not None else None
    if current is None:
        if not enabled:
            return settings
        account = Account(user_id, secret) if secret is not None else Account.create(user_id)
        return replace(settings, accounts=(*settings.accounts, account))
    if secret is not None and current.secret != secret:
        raise ValueError("Импортированный секрет конфликтует с настройками Telemt")
    return replace(settings, accounts=tuple(replace(item, enabled=enabled) if item == current else item
                                           for item in settings.accounts))


def restore_seed(settings, seed):
    """Не подменять аккаунты назначения и не включать сохранённые выключенными."""
    current = {item.name: item for item in settings.accounts}
    for name, value in seed.items():
        item = Account(name, Secret(value["secret"]), value["enabled"]) if isinstance(value, dict) else Account(name, Secret(value))
        if name in current and current[name] != item:
            raise ValueError("Импортированный аккаунт конфликтует с настройками Telemt")
        current[name] = item
    return replace(settings, accounts=tuple(current.values()))
