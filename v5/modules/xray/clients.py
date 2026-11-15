"""VLESS-ссылки и тестируемые клиентские настройки без экспорта закрытого ключа."""

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import quote, urlencode

from v5.core.tls.identity import TLSIdentity

from .config import Settings, VISION
from .credentials import Account, PublicReality
from .profiles import Kind, Profile


def _identity(raw: str) -> TLSIdentity:
    try:
        ip_address(raw)
    except ValueError:
        return TLSIdentity(raw, False)
    return TLSIdentity(raw, True)


@dataclass(frozen=True, slots=True)
class ClientProfile:
    account: Account
    profile: Profile
    endpoint: TLSIdentity
    public_reality: PublicReality | None = None
    direct: bool = False

    def __post_init__(self) -> None:
        if (not isinstance(self.account, Account) or not isinstance(self.profile, Profile)
                or not isinstance(self.endpoint, TLSIdentity) or type(self.direct) is not bool
                or self.profile.kind not in self.account.grants
                or (self.direct and not self.profile.exposure.direct)
                or (not self.direct and not self.profile.exposure.shared)):
            raise ValueError("Профиль VLESS недоступен пользователю")
        if self.profile.kind is Kind.TLS:
            identity = self.profile.tls_identity()
            if identity.is_ip and identity != self.endpoint:
                raise ValueError("Для сертификата IP адрес подключения должен совпадать с IP SAN")
            if self.public_reality is not None:
                raise ValueError("TLS не принимает ключ Reality")
        elif not isinstance(self.public_reality, PublicReality):
            raise ValueError("Нет открытого ключа Reality")

    @property
    def port(self) -> int:
        return self.profile.port if self.direct else 443

    @property
    def flow(self) -> str:
        return VISION if self.profile.kind is Kind.REALITY_TCP else ""

    def uri(self) -> str:
        profile = self.profile
        params = {
            "type": "xhttp" if profile.kind is Kind.REALITY_XHTTP else "tcp",
            "security": "tls" if profile.kind is Kind.TLS else "reality",
            "encryption": "none",
            "sni": profile.sni,
        }
        if self.public_reality is not None:
            params.update(fp="chrome", pbk=self.public_reality.key, sid=self.public_reality.short_id, spx="/")
        if self.flow:
            params["flow"] = self.flow
        if profile.kind is Kind.REALITY_XHTTP:
            params.update(path=profile.path, mode="auto")
        title = quote(f"{self.account.name} · {profile.kind.value}", safe="")
        return (f"vless://{self.account.id}@{self.endpoint.authority}:{self.port}?"
                + urlencode(params, quote_via=quote) + "#" + title)

    def outbound(self) -> dict:
        """Нативный JSON Xray для воспроизводимой проверки каждого URI."""
        profile = self.profile
        settings = {"network": "xhttp" if profile.kind is Kind.REALITY_XHTTP else "raw"}
        if self.public_reality is None:
            settings.update(security="tls", tlsSettings={"serverName": profile.sni})
        else:
            settings.update(security="reality", realitySettings={
                "serverName": profile.sni, "fingerprint": "chrome", "password": self.public_reality.key,
                "shortId": self.public_reality.short_id, "spiderX": "/",
            })
        if profile.kind is Kind.REALITY_XHTTP:
            settings["xhttpSettings"] = {"path": profile.path, "mode": "auto"}
        user = {"id": self.account.id, "encryption": "none"}
        if self.flow:
            user["flow"] = self.flow
        return {"protocol": "vless", "settings": {
            "vnext": [{"address": self.endpoint.name, "port": self.port, "users": [user]}]},
            "streamSettings": settings}


def client_profiles(settings: Settings, account_id: str, endpoint: str,
                    reality: PublicReality | Mapping[Kind, PublicReality] | None,
                    *, active: bool, prefer_direct: bool = False) -> tuple[ClientProfile, ...]:
    if type(active) is not bool or type(prefer_direct) is not bool:
        raise ValueError("Некорректное состояние экспорта")
    account = next((item for item in settings.accounts if item.id == account_id), None)
    if not active or account is None:
        return ()
    address = _identity(endpoint)
    result = []
    for profile in sorted(settings.profiles.values, key=lambda item: item.port):
        if profile.kind not in account.grants:
            continue
        direct = not profile.exposure.shared or (prefer_direct and profile.exposure.direct)
        public = reality.get(profile.kind) if isinstance(reality, Mapping) else reality
        result.append(ClientProfile(account, profile, address, None if profile.kind is Kind.TLS else public, direct))
    return tuple(result)


def subscription(profiles: tuple[ClientProfile, ...]) -> bytes:
    """Стандартная V2Ray-подписка: base64 строк URI, без сырого серверного JSON."""
    if not profiles:
        return b""
    return base64.b64encode(("\n".join(item.uri() for item in profiles) + "\n").encode("ascii"))
