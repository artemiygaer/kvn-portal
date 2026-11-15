"""Ограниченные параметры и нативный TOML Telemt 3.5."""

from dataclasses import asdict, dataclass, field
import json

from v5.core.packages.manifest import canonical_json, json_object, reject
from v5.core.private_files import read_private, write_private
from v5.modules.mtproto_common.profiles import CoverTarget, Exposure, IDLE_USER, PORTS, Secret, profile, valid_user

MODULE = "telemt"
MAX_SETTINGS = 64 * 1024
MAX_ACCOUNTS = 256


@dataclass(frozen=True, slots=True)
class Account:
    name: str
    secret: Secret = field(repr=False)
    enabled: bool = True

    def __post_init__(self):
        if (not valid_user(self.name)
                or not isinstance(self.secret, Secret) or type(self.enabled) is not bool):
            raise ValueError("Некорректная учётная запись Telemt")

    @classmethod
    def create(cls, name):
        return cls(name, Secret.create())


@dataclass(frozen=True, slots=True)
class Settings:
    exposure: Exposure
    accounts: tuple[Account, ...] = field(repr=False)

    def __post_init__(self):
        if (not isinstance(self.exposure, Exposure) or not isinstance(self.accounts, tuple)
                or len(self.accounts) > MAX_ACCOUNTS or any(not isinstance(item, Account) for item in self.accounts)
                or len({item.name.casefold() for item in self.accounts}) != len(self.accounts)
                or len({item.secret for item in self.accounts}) != len(self.accounts)):
            raise ValueError("Некорректные параметры Telemt")

    def save(self, path):
        users = [{"name": item.name, "secret": item.secret.value, "enabled": item.enabled} for item in self.accounts]
        write_private(path, canonical_json({"schema": 1, "exposure": asdict(self.exposure), "accounts": users}))

    @classmethod
    def load(cls, path):
        data = json_object(read_private(path, MAX_SETTINGS))
        if (data.keys() != {"schema", "exposure", "accounts"} or type(data["schema"]) is not int or data["schema"] != 1
                or not isinstance(data["exposure"], dict)
                or data["exposure"].keys() != {"sni", "own_site", "shared", "direct_ip"}
                or not isinstance(data["accounts"], list) or len(data["accounts"]) > MAX_ACCOUNTS
                or any(not isinstance(row, dict) or row.keys() != {"name", "secret", "enabled"} for row in data["accounts"])):
            reject("telemt_settings_invalid")
        return cls(Exposure(**data["exposure"]), tuple(Account(row["name"], Secret(row["secret"]), row["enabled"])
                                                       for row in data["accounts"]))


def render_server(settings: Settings, cover: CoverTarget, *, idle: Secret | None = None) -> bytes:
    active = {item.name: item.secret for item in settings.accounts if item.enabled}
    if not active:
        if not isinstance(idle, Secret) or any(item.secret == idle for item in settings.accounts):
            reject("telemt_idle_secret_required")
        active[IDLE_USER] = idle
    endpoint = settings.exposure
    endpoint.validate_cover(cover)
    quote = json.dumps
    rows = [
        "[general]", "use_middle_proxy = false", 'log_level = "silent"',
        "[general.modes]", "classic = false", "secure = false", "tls = true",
        "[general.links]", "show = []",
        "[server]", f"port = {PORTS[MODULE]}", "proxy_protocol = false",
        "[server.api]", "enabled = false",
        "[[server.listeners]]", f"ip = {quote(endpoint.address)}",
        "[censorship]", f"tls_domain = {quote(endpoint.sni)}", "mask = true",
        f"mask_host = {quote(cover.ip)}", f"mask_port = {cover.port}", "tls_emulation = false",
        "[access.users]",
        *(f"{quote(name)} = {quote(secret.value)}" for name, secret in sorted(active.items())),
    ]
    return ("\n".join(rows) + "\n").encode("ascii")


def client_profile(settings: Settings, name: str, server: str, *, active: bool, direct: bool = False):
    if type(active) is not bool:
        raise ValueError("Некорректное состояние экспорта Telemt")
    account = next((row for row in settings.accounts if row.enabled and row.name == name), None)
    if not active or account is None:
        return None
    return profile(MODULE, settings.exposure, account.secret, server, direct=direct, user=account.name)
