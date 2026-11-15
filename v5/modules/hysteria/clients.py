"""Клиентский URI и подписка только для активного разрешённого профиля."""

import base64
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

from v5.core.tls.identity import TLSIdentity

from .config import Account, Settings, identity


@dataclass(frozen=True, slots=True)
class ClientProfile:
    settings: Settings = field(repr=False)
    account: Account = field(repr=False)
    endpoint: TLSIdentity

    def __post_init__(self):
        if (not isinstance(self.settings, Settings) or not isinstance(self.account, Account)
                or not self.account.enabled or self.account not in self.settings.accounts
                or not isinstance(self.endpoint, TLSIdentity) or self.endpoint != identity(self.endpoint.name)
                or (self.settings.tls.is_ip and self.settings.tls != self.endpoint)):
            raise ValueError("Профиль Hysteria2 недоступен для этого пользователя или TLS-имени")

    @property
    def server(self) -> str:
        return f"{self.endpoint.authority}:{self.settings.port}"

    def uri(self) -> str:
        tls = self.settings.tls
        params = {} if tls.is_ip else {"sni": tls.name}
        if self.settings.salamander:
            params.update({"obfs": "salamander", "obfs-password": self.settings.salamander})
        auth = quote(self.account.auth, safe=":")
        suffix = "?" + urlencode(params, quote_via=quote) if params else ""
        title = quote(f"{self.account.name} · Hysteria2", safe="")
        return f"hysteria2://{auth}@{self.server}/{suffix}#{title}"

    def native(self) -> dict:
        """Настройки CLI, без local listeners и без обхода проверки сертификата."""
        data = {"server": self.server, "auth": self.account.auth, "tls": {"insecure": False}}
        if not self.settings.tls.is_ip:
            data["tls"]["sni"] = self.settings.tls.name
        if self.settings.salamander:
            data["obfs"] = {"type": "salamander", "salamander": {"password": self.settings.salamander}}
        return data


def client_profile(settings: Settings, user: str, *, active: bool,
                   endpoint: str | None = None) -> ClientProfile | None:
    if type(active) is not bool:
        raise ValueError("Некорректное состояние экспорта")
    account = next((item for item in settings.accounts if item.name == user and item.enabled), None)
    if not active or account is None:
        return None
    return ClientProfile(settings, account, settings.tls if endpoint is None else identity(endpoint))


def subscription(profile: ClientProfile | None) -> bytes:
    return base64.b64encode((profile.uri() + "\n").encode("ascii")) if profile else b""
