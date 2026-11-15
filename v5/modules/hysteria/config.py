"""Ограниченная схема сервера: UDP, доверенный TLS и индивидуальный доступ."""

from dataclasses import asdict, dataclass, field
from ipaddress import ip_address
import re
from secrets import token_urlsafe

from v5.core.network.plan import Binding, ModuleNetwork, Publication
from v5.core.packages.manifest import canonical_json, json_object, reject
from v5.core.private_files import read_private, write_private
from v5.core.tls.identity import TLSIdentity

MODULE = "hysteria"
CONFIG_ROOT = "/etc/kvn-hysteria"
TLS_ROOT = "/etc/kvn-hysteria-tls"
INNER_PORT = 11443
MAX_SETTINGS = 128 * 1024
MAX_ACCOUNTS = 512
_USER = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}", re.ASCII)
_SECRET = re.compile(r"[A-Za-z0-9_-]{24,128}", re.ASCII)
_IMPORTED_USER = re.compile(r"[A-Za-z0-9_.-]{1,64}", re.ASCII)
_IMPORTED_SECRET = re.compile(r"[!-~]{1,128}", re.ASCII)
_LOCAL = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)


def identity(raw: str) -> TLSIdentity:
    if not isinstance(raw, str):
        raise ValueError("Укажите имя или IPv4 для TLS")
    try:
        address = ip_address(raw.strip())
    except ValueError:
        return TLSIdentity(raw, False)
    if address.version != 4 or address.is_loopback or address.is_link_local:
        raise ValueError("Для Hysteria2 нужен внешний IPv4")
    return TLSIdentity(raw, True)


@dataclass(frozen=True, slots=True)
class Account:
    name: str
    password: str = field(repr=False)
    enabled: bool = True
    imported: bool = False

    def __post_init__(self):
        name = _IMPORTED_USER if self.imported else _USER
        secret = _IMPORTED_SECRET if self.imported else _SECRET
        if (not isinstance(self.name, str) or not name.fullmatch(self.name)
                or self.name in {".", "..", "_kvn_no_user"}
                or not isinstance(self.password, str) or not secret.fullmatch(self.password)
                or type(self.enabled) is not bool or type(self.imported) is not bool):
            raise ValueError("Некорректная учётная запись Hysteria2")

    @classmethod
    def create(cls, name: str) -> "Account":
        return cls(name, token_urlsafe(32))

    @property
    def auth(self) -> str:
        return f"{self.name}:{self.password}"

    def document(self):
        row = asdict(self)
        if not self.imported:
            row.pop("imported")
        return row


@dataclass(frozen=True, slots=True)
class Settings:
    tls: TLSIdentity
    accounts: tuple[Account, ...] = field(default=(), repr=False)
    bind: str = "0.0.0.0"
    port: int = 443
    salamander: str | None = field(default=None, repr=False)

    def __post_init__(self):
        if not isinstance(self.tls, TLSIdentity) or self.tls != identity(self.tls.name):
            raise ValueError("Некорректный TLS Hysteria2")
        binding = self.binding
        if binding.address.version != 4 or binding.address.is_loopback:
            raise ValueError("Некорректный IPv4 для прослушивания Hysteria2")
        object.__setattr__(self, "bind", binding.ip)
        if (not isinstance(self.accounts, tuple) or len(self.accounts) > MAX_ACCOUNTS
                or any(not isinstance(item, Account) for item in self.accounts)
                or len({item.name for item in self.accounts}) != len(self.accounts)):
            raise ValueError("Некорректный список пользователей Hysteria2")
        if self.salamander is not None and (not isinstance(self.salamander, str)
                                            or not _SECRET.fullmatch(self.salamander)):
            raise ValueError("Некорректный пароль Salamander")

    @property
    def binding(self) -> Binding:
        return Binding("udp", self.bind, self.port)

    def network(self) -> ModuleNetwork:
        return ModuleNetwork(MODULE, publications=(Publication(self.binding),))

    def save(self, path):
        raw = canonical_json({"schema": 1, "tls": self.tls.name, "bind": self.bind, "port": self.port,
                              "salamander": self.salamander, "accounts": [item.document() for item in self.accounts]})
        if len(raw) > MAX_SETTINGS:
            reject("hysteria_settings_invalid")
        write_private(path, raw)

    @classmethod
    def load(cls, path) -> "Settings":
        return parse_settings(read_private(path, MAX_SETTINGS))


def parse_settings(raw: bytes) -> Settings:
    if len(raw) > MAX_SETTINGS:
        reject("hysteria_settings_invalid")
    data = json_object(raw)
    if (data.keys() != {"schema", "tls", "accounts", "bind", "port", "salamander"}
            or type(data["schema"]) is not int or data["schema"] != 1
            or not isinstance(data["accounts"], list) or len(data["accounts"]) > MAX_ACCOUNTS
            or any(not isinstance(item, dict) or item.keys() not in ({"name", "password", "enabled"},
                                                                     {"name", "password", "enabled", "imported"})
                   for item in data["accounts"])):
        reject("hysteria_settings_invalid")
    return Settings(identity(data["tls"]), tuple(Account(**item) for item in data["accounts"]),
                    data["bind"], data["port"], data["salamander"])


def render_server(settings: Settings, *, idle_secret: str | None = None) -> dict:
    users = {item.name: item.password for item in settings.accounts if item.enabled}
    if not users:
        if not isinstance(idle_secret, str) or not _SECRET.fullmatch(idle_secret):
            reject("hysteria_accounts_required")
        # Служебное имя недопустимо для обычной учётной записи.
        users = {"_kvn_no_user": idle_secret}
    data = {
        "listen": f"0.0.0.0:{INNER_PORT}",
        "tls": {"cert": f"{TLS_ROOT}/server.pem", "key": f"{TLS_ROOT}/server.pem",
                "sniGuard": "dns-san" if settings.tls.is_ip else "strict"},
        "auth": {"type": "userpass", "userpass": users},
        "acl": {"inline": [f"reject({value})" for value in _LOCAL]},
        "speedTest": False,
    }
    if settings.salamander is not None:
        data["obfs"] = {"type": "salamander", "salamander": {"password": settings.salamander}}
    return data
