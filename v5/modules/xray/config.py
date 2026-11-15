"""Рендер доверенного конфига Xray из ограниченной схемы, без произвольного JSON."""

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address

from v5.core.packages.manifest import canonical_json, json_object
from v5.core.private_files import read_private, write_private

from .credentials import Account, RealityKey
from .profiles import Exposure, Kind, Profile, Profiles, Reality

MAX_SETTINGS = 128 * 1024
MAX_ACCOUNTS = 512
VISION = "xtls-rprx-vision"
CONFIG_ROOT = "/etc/kvn-xray"
_LOCAL_IPS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)


@dataclass(frozen=True, slots=True)
class Settings:
    profiles: Profiles
    accounts: tuple[Account, ...] = ()
    ipv4: str = "0.0.0.0"

    def __post_init__(self) -> None:
        if not isinstance(self.profiles, Profiles) or not isinstance(self.ipv4, str):
            raise ValueError("Некорректные настройки Xray")
        address = ip_address(self.ipv4)
        if address.version != 4 or address.is_loopback or address.is_multicast or address.is_link_local:
            raise ValueError("Некорректный IPv4 Xray")
        object.__setattr__(self, "ipv4", address.compressed)
        if (not isinstance(self.accounts, tuple) or len(self.accounts) > MAX_ACCOUNTS
                or any(not isinstance(item, Account) for item in self.accounts)
                or len({item.id for item in self.accounts}) != len(self.accounts)
                or len({item.name for item in self.accounts}) != len(self.accounts)):
            raise ValueError("Некорректный список пользователей Xray")

    @classmethod
    def load(cls, path):
        return parse_settings(read_private(path, MAX_SETTINGS))

    def save(self, path):
        data = canonical_json({
            "schema": 1, "ipv4": self.ipv4,
            "profiles": [{"kind": p.kind, "exposure": p.exposure, "sni": p.sni, "reality": p.reality,
                          "external_host": p.external_host, "path": p.path} for p in self.profiles.values],
            "accounts": [{"name": item.name, "id": item.id, "grants": list(item.grants)} for item in self.accounts],
        })
        if len(data) > MAX_SETTINGS:
            raise ValueError("Слишком большие настройки Xray")
        write_private(path, data)


def parse_settings(raw: bytes) -> Settings:
    if len(raw) > MAX_SETTINGS:
        raise ValueError("Слишком большие настройки Xray")
    value = json_object(raw)
    if (value.keys() != {"schema", "ipv4", "profiles", "accounts"} or type(value["schema"]) is not int
            or value["schema"] != 1 or not isinstance(value["profiles"], list) or len(value["profiles"]) > len(Kind)
            or not isinstance(value["accounts"], list) or len(value["accounts"]) > MAX_ACCOUNTS):
        raise ValueError("Некорректная схема настроек Xray")
    profiles, accounts = [], []
    for item in value["profiles"]:
        if not isinstance(item, dict) or item.keys() != {"kind", "exposure", "sni", "reality", "external_host", "path"}:
            raise ValueError("Некорректная схема профиля Xray")
        reality = Reality(item["reality"]) if item["reality"] is not None else None
        profiles.append(Profile(Kind(item["kind"]), Exposure(item["exposure"]), item["sni"],
                                reality, item["external_host"], item["path"]))
    for item in value["accounts"]:
        if not isinstance(item, dict) or item.keys() != {"name", "id", "grants"} or not isinstance(item["grants"], list):
            raise ValueError("Некорректная схема пользователя Xray")
        accounts.append(Account(item["name"], item["id"], tuple(Kind(grant) for grant in item["grants"])))
    return Settings(Profiles(tuple(profiles)), tuple(accounts), value["ipv4"])


def stream(profile: Profile, key: RealityKey | None) -> dict:
    network = "xhttp" if profile.kind is Kind.REALITY_XHTTP else "raw"
    if profile.kind is Kind.TLS:
        return {"network": network, "security": "tls", "tlsSettings": {
            "minVersion": "1.2", "certificates": [{
                "certificateFile": f"{CONFIG_ROOT}/tls.crt", "keyFile": f"{CONFIG_ROOT}/tls.key",
            }],
        }}
    if key is None:
        raise ValueError("Не подготовлен ключ Reality")
    value = {"network": network, "security": "reality", "realitySettings": {
        "show": False, "target": profile.target, "xver": 0, "serverNames": [profile.sni],
        "privateKey": key.private, "shortIds": list(key.short_ids),
    }}
    if profile.kind is Kind.REALITY_XHTTP:
        value["xhttpSettings"] = {"path": profile.path, "mode": "auto"}
    return value


def render_server(settings: Settings, key: RealityKey | Mapping[Kind, RealityKey] | None,
                  *, site_names: tuple[str, ...]) -> dict:
    settings.profiles.network(site_names=site_names, ipv4=settings.ipv4)
    inbounds = []
    for profile in sorted(settings.profiles.values, key=lambda item: item.port):
        users = [{"id": user.id, "email": user.name, **({"flow": VISION} if profile.kind is Kind.REALITY_TCP else {})}
                 for user in settings.accounts if profile.kind in user.grants]
        inbounds.append({
            "tag": profile.kind.value, "listen": settings.ipv4 if profile.exposure.direct else "127.0.0.1",
            "port": profile.port, "protocol": "vless", "settings": {"users": users, "decryption": "none"},
            "streamSettings": stream(profile, key.get(profile.kind) if isinstance(key, Mapping) else key),
        })
    return {
        "log": {"access": "none", "loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [{"tag": "public", "protocol": "freedom",
                       "streamSettings": {"sockopt": {"domainStrategy": "UseIP"}}},
                      {"tag": "blocked", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPOnDemand", "rules": [
            {"type": "field", "ip": list(_LOCAL_IPS), "outboundTag": "blocked"},
        ]},
    }
