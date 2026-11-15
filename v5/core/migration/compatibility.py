"""Проверка переносимых ключей против нативных настроек, без запуска модулей."""

from dataclasses import replace
from ipaddress import IPv4Address, IPv4Interface

from v5.core.packages.manifest import PackageError, json_object
from v5.modules.amneziawg.profile import Profile
from v5.modules.host_tunnel.config import AWG, Settings
from v5.modules.host_tunnel.credentials import peer, public_key
from v5.modules.host_tunnel.state import State, TUNNELS
from v5.modules.host_tunnel.users import restore_seed
from v5.modules.hysteria.config import Settings as HysteriaSettings
from v5.modules.telemt.settings import MAX_ACCOUNTS as MAX_TELEMT_ACCOUNTS, Settings as TelemtSettings
from v5.modules.xray.config import Settings as XraySettings

from .crypto import ArchiveError


def _optional(load, *args):
    try:
        return load(*args)
    except FileNotFoundError:
        return None


def _credentials(archive, module):
    return tuple((row.user.id, json_object(raw)) for row in archive.users
                 for name, raw in row.credentials if name == module)


def _check_tunnel(modules, spec, archive, seeds):
    peers = tuple(peer(item) for _, item in _credentials(archive, spec.module))
    seed = seeds.get(spec.module)
    if not peers and seed is None:
        return
    current = _optional(State.load, spec, modules / spec.module / "settings.json")
    if current is None:
        if seed is None:
            # Нужна проверка адресов до первого configure; ключ здесь не создаётся.
            subnet = IPv4Interface(spec.address)
            for item in peers:
                address = IPv4Address(item.address)
                if address not in subnet.network or address in (subnet.ip, subnet.network.network_address,
                                                                 subnet.network.broadcast_address):
                    raise ValueError("Адрес вне подсети назначения")
            return
        data = json_object(seed)
        # Создаём только DTO для проверки схемы и совместимости, не файл и не интерфейс.
        original = State(spec, Settings(spec.address, data["private_key"]), Profile() if spec == AWG else None)
        current = restore_seed(original, data)
    settings = current.settings
    if peers and public_key(settings.private_key) in {item.public_key for item in peers}:
        raise ValueError("Ключ клиента совпал с ключом сервера")
    replace(settings, peers=(*settings.peers, *peers))


def _check_accounts(modules, archive, before, seeds):
    xray = _optional(XraySettings.load, modules / "xray/settings.json")
    if xray is not None:
        names = {item.name for item in xray.accounts}
        ids = {item.id for item in xray.accounts}
        if any(row.user.id in names and "xray" in dict(row.grants) for row in archive.users) or any(
                item["uuid"] in ids for _, item in _credentials(archive, "xray")):
            raise ArchiveError("migration_xray_conflict")
    hysteria = _optional(HysteriaSettings.load, modules / "hysteria/settings.json")
    if hysteria is not None:
        names = {item.name for item in hysteria.accounts}
        incoming = dict(_credentials(archive, "hysteria"))
        if any(incoming.get(row.user.id, {}).get("login", row.user.id) in names
               for row in archive.users if "hysteria" in dict(row.grants)):
            raise ArchiveError("migration_hysteria_conflict")
    telemt = _optional(TelemtSettings.load, modules / "telemt/settings.json")
    incoming_names = {row.user.id.casefold() for row in archive.users if "telemt" in dict(row.grants)}
    saved_names = {row.user.id.casefold() for row in before.users if "telemt" in dict(row.grants)}
    extra = set(name.casefold() for name in json_object(seeds.get("telemt", b"{}"))) if telemt is None else set()
    if telemt is not None:
        extra = {item.name.casefold() for item in telemt.accounts}
        secrets = {item.secret.value for item in telemt.accounts}
        if incoming_names & extra or any(item["secret"] in secrets for _, item in _credentials(archive, "telemt")):
            raise ArchiveError("migration_telemt_conflict")
    if len(incoming_names | saved_names | extra) > MAX_TELEMT_ACCOUNTS:
        raise ArchiveError("migration_telemt_limit")


def check_archive(modules, archive, mode, before):
    # В merge входные серверные ключи игнорируются. Нельзя валидировать адрес
    # клиента по подсети сервера-источника вместо сохранённой цели.
    seeds = dict(archive.seeds if mode == "restore" else before.seeds)
    for name, spec in sorted(TUNNELS.items()):
        try:
            _check_tunnel(modules, spec, archive, seeds)
        except (OSError, ValueError, PackageError, KeyError):
            raise ArchiveError(f"migration_{name}_conflict") from None
    try:
        _check_accounts(modules, archive, before, seeds)
    except ArchiveError:
        raise
    except (OSError, ValueError, PackageError, KeyError):
        raise ArchiveError("migration_target_unavailable") from None
