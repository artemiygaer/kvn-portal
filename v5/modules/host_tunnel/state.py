"""Закрытое состояние одного туннеля с разделением схем WG и AWG."""

from dataclasses import asdict, dataclass, fields, replace
from pathlib import Path

from v5.core.packages.manifest import canonical_json, json_object
from v5.core.private_files import read_private, write_private
from v5.modules.amneziawg import profile as amneziawg
from v5.modules import wireguard

from .config import AWG, WG, Settings, Tunnel, settings_from_document


MAX_SETTINGS_BYTES = 256 * 1024
MODULES_ROOT = Path("/var/lib/kvn-v5/modules")
TUNNELS = {item.module: item for item in (WG, AWG)}


def _fields(cls) -> set[str]:
    return {item.name for item in fields(cls)}


def _awg_profile(data) -> amneziawg.Profile:
    if (not isinstance(data, dict) or data.keys() != _fields(amneziawg.Profile)
            or any(not isinstance(data[name], list) for name in ("headers", "padding", "tagged"))):
        raise ValueError("Некорректная схема профиля AWG")
    data = data.copy()
    for name in ("headers", "padding", "tagged"):
        data[name] = tuple(data[name])
    if data["v31"] is not None:
        modern = data["v31"]
        if not isinstance(modern, dict) or modern.keys() != _fields(amneziawg.V31):
            raise ValueError("Некорректная схема AWG 3.1")
        data["v31"] = amneziawg.V31(**modern)
    return amneziawg.Profile(**data)


@dataclass(frozen=True, slots=True)
class State:
    spec: Tunnel
    settings: Settings
    profile: amneziawg.Profile | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.settings, Settings) or self.spec not in (WG, AWG)
                or (self.spec == WG and self.profile is not None)
                or (self.spec == AWG and not isinstance(self.profile, amneziawg.Profile))):
            raise ValueError("Настройки не соответствуют выбранному модулю")

    @property
    def mode(self) -> str:
        return self.profile.mode if self.profile else "standard"

    def server(self) -> bytes:
        return (amneziawg.server(self.settings, self.profile) if self.profile else wireguard.server(self.settings))

    def client(self, peer, **options) -> bytes:
        if self.profile:
            return amneziawg.client(self.settings, peer, self.profile, **options)
        return wireguard.client(self.settings, peer, **options)

    def peer_only(self, other: "State") -> bool:
        return (self.spec == other.spec and self.profile == other.profile
                and replace(self.settings, peers=()) == replace(other.settings, peers=()))

    def save(self, path: Path) -> None:
        data = canonical_json({"schema": 1, "module": self.spec.module, "settings": asdict(self.settings),
                               "profile": asdict(self.profile) if self.profile else None})
        if len(data) > MAX_SETTINGS_BYTES:
            raise ValueError("Слишком большие настройки туннеля")
        write_private(path, data)

    @classmethod
    def load(cls, spec: Tunnel, path: Path) -> "State":
        value = json_object(read_private(path, MAX_SETTINGS_BYTES))
        if (value.keys() != {"schema", "module", "settings", "profile"} or type(value["schema"]) is not int
                or value["schema"] != 1 or value["module"] != spec.module
                or (spec == WG and value["profile"] is not None)):
            raise ValueError("Некорректная схема или другой модуль туннеля")
        profile = _awg_profile(value["profile"]) if spec == AWG else None
        return cls(spec, settings_from_document(value["settings"]), profile)
