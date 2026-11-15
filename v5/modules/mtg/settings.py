"""Ограниченные параметры и нативный TOML MTG 2.3."""

from dataclasses import asdict, dataclass, field, replace
import json

from v5.core.packages.manifest import canonical_json, json_object, reject
from v5.core.private_files import read_private, write_private
from v5.modules.mtproto_common.profiles import CoverTarget, Exposure, PORTS, Secret, profile

MODULE = "mtg"


@dataclass(frozen=True, slots=True)
class Settings:
    exposure: Exposure
    secret: Secret = field(repr=False)

    def __post_init__(self):
        if not isinstance(self.exposure, Exposure) or not isinstance(self.secret, Secret):
            raise ValueError("Некорректные параметры MTG")

    def save(self, path):
        write_private(path, canonical_json({"schema": 1, "exposure": asdict(self.exposure),
                                            "secret": self.secret.value}))

    @classmethod
    def load(cls, path):
        data = json_object(read_private(path, 4096))
        if (data.keys() != {"schema", "exposure", "secret"} or type(data["schema"]) is not int or data["schema"] != 1
                or not isinstance(data["exposure"], dict)
                or data["exposure"].keys() != {"sni", "own_site", "shared", "direct_ip"}):
            reject("mtg_settings_invalid")
        return cls(Exposure(**data["exposure"]), Secret(data["secret"]))


def render_server(settings: Settings, cover: CoverTarget) -> bytes:
    endpoint = settings.exposure
    endpoint.validate_cover(cover)
    quote = json.dumps
    rows = [
        f"secret = {quote(settings.secret.for_sni(endpoint.sni))}",
        f"bind-to = {quote(f'{endpoint.address}:{PORTS[MODULE]}')}",
        "debug = false",
        'prefer-ip = "prefer-ipv4"',
        "[domain-fronting]", f"host = {quote(cover.ip)}", f"port = {cover.port}", "proxy-protocol = false",
        "[defense.anti-replay]", "enabled = true",
    ]
    return ("\n".join(rows) + "\n").encode("ascii")


def restore_seed(settings: Settings, seed: dict) -> Settings:
    """Переносит общий секрет, не меняя SNI и публикацию нового сервера."""
    return replace(settings, secret=Secret(seed["secret"]))


def client_profile(settings: Settings, server: str, *, active: bool, allowed: bool, direct: bool = False):
    if type(active) is not bool or type(allowed) is not bool:
        raise ValueError("Некорректное состояние экспорта MTG")
    if not active or not allowed:
        return None
    return profile(MODULE, settings.exposure, settings.secret, server, direct=direct)
