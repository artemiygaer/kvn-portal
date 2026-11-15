"""Снимок переносимых ключей из реестра и закрытых нативных настроек."""

from v5.core.packages.manifest import PackageError
from v5.modules.host_tunnel.state import State, TUNNELS
from v5.modules.host_tunnel.users import server_seed
from v5.modules.hysteria.config import Settings as HysteriaSettings
from v5.modules.mtg.settings import Settings as MTGSettings
from v5.modules.telemt.settings import Settings as TelemtSettings
from v5.modules.xray.config import Settings as XraySettings
from v5.modules.xray.credentials import load_reality

from .crypto import ArchiveError
from .portable import PortableArchive, XRAY_PROFILES


def _optional(load, *args):
    try:
        return load(*args)
    except FileNotFoundError:
        return None


def _remember(saved, name, candidate, identity):
    previous = saved.get(name)
    if previous is None:
        saved[name] = candidate
    elif any(previous[key] != candidate[key] for key in identity):
        raise ArchiveError("migration_export_conflict")


class MigrationExporter:
    def __init__(self, repository, target):
        self.repository, self.target = repository, target

    def collect(self):
        try:
            with self.target.guard():
                return self._collect_locked()
        except ArchiveError:
            raise
        except (OSError, PackageError, ValueError, KeyError):
            raise ArchiveError("migration_export_unavailable") from None

    def _collect_locked(self):
        result = self.repository.current().document()
        modules = self.target.modules
        native = {name: _optional(settings.load, modules / name / "settings.json")
                  for name, settings in (("xray", XraySettings), ("hysteria", HysteriaSettings),
                                         ("telemt", TelemtSettings), ("mtg", MTGSettings))}
        accounts = {name: {item.name: item for item in native[name].accounts} if native[name] is not None else {}
                    for name in ("xray", "hysteria", "telemt")}
        xray = native["xray"]
        telemt_cards = set()
        for row in result["users"]:
            uid, grants, keys = row["id"], row["grants"], row["credentials"]
            if "xray" in grants and (item := accounts["xray"].get(uid)) is not None:
                kinds = item.grants or tuple(profile.kind for profile in xray.profiles.values)
                _remember(keys, "xray", {"uuid": item.id, "profiles": sorted(kind.value for kind in kinds) or sorted(XRAY_PROFILES)},
                          ("uuid",))
            if "hysteria" in grants:
                login = keys.get("hysteria", {}).get("login", uid)
                if (item := accounts["hysteria"].get(login)) is not None:
                    _remember(keys, "hysteria", {"login": item.name, "password": item.password}, ("login", "password"))
            if "telemt" in grants:
                telemt_cards.add(uid)
                if (item := accounts["telemt"].get(uid)) is not None:
                    _remember(keys, "telemt", {"secret": item.secret.value}, ("secret",))
        seeds = result["seeds"]
        for name, spec in TUNNELS.items():
            if (state := _optional(State.load, spec, modules / name / "settings.json")) is not None:
                seeds[name] = server_seed(state)
        if (key := _optional(load_reality, modules / "xray/reality.json")) is not None:
            # Общий нативный ключ остаётся fallback для режимов без своего seed.
            reality = seeds.setdefault("xray", {})
            for name in sorted(XRAY_PROFILES - {"tls"}):
                reality.setdefault(name, {"private": key.private, "short_ids": list(key.short_ids)})
        if native["mtg"] is not None:
            seeds["mtg"] = {"secret": native["mtg"].secret.value}
        if native["telemt"] is not None:
            extras = {name: {"secret": item.secret.value, "enabled": item.enabled}
                      for name, item in accounts["telemt"].items() if name not in telemt_cards}
            if extras:
                seeds["telemt"] = extras
            else:
                seeds.pop("telemt", None)
        return PortableArchive.parse(result)
