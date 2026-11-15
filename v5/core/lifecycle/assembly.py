"""Сборка lifecycle для доверенных встроенных адаптеров, без discovery архивов."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from v5.core.contracts import MODULE_IDS, USER_PENDING_NAME
from v5.core.migration.material import MigrationMaterial
from v5.core.migration.portable import normalize_credential
from v5.core.network.runtime import NetworkRuntime
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.signature import load_publisher
from v5.core.packages.status import PACKAGE_STATE
from v5.core.tls.controller import GatewayController
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore
from v5.core.users.journal import UserApplyJournal
from v5.core.users.credentials import StoredCredentials
from v5.core.users.recovery import UserRecovery
from v5.core.users.settings_backend import SettingsBackend
from v5.core.users.settings_module import SettingsUserModule
from v5.core.users.store import UserStore
from v5.modules.amneziawg.adapter import amneziawg_adapter
from v5.modules.host_tunnel.state import TUNNELS
from v5.modules.host_tunnel.user_backend import TunnelUserBackend
from v5.modules.host_tunnel.users import client_file, project_user as project_tunnel_user
from v5.modules.hysteria.adapter import HysteriaAdapter
from v5.modules.hysteria.config import render_server as render_hysteria
from v5.modules.hysteria.idle import idle_secret
from v5.modules.hysteria.users import set_user as set_hysteria_user, subscription_uris as hysteria_uris
from v5.modules.mtg.adapter import mtg_adapter
from v5.modules.mtproto_common.runtime import cover_target
from v5.modules.telemt.adapter import telemt_adapter
from v5.modules.telemt.settings import client_profile as telemt_profile
from v5.modules.telemt.users import set_user as set_telemt_user
from v5.modules.wireguard.adapter import wireguard_adapter
from v5.modules.xray.adapter import XrayAdapter
from v5.modules.xray.profiles import Kind
from v5.modules.xray.users import set_user as set_xray_user, subscription_uris as xray_uris

from .controller import Lifecycle, LifecycleError, RuntimeAdapter
from .journal import IntentJournal, PENDING_NAME


@dataclass(frozen=True, slots=True)
class HostContext:
    packages: PackageRegistry
    gateway: GatewayController
    material: MigrationMaterial | None = None


AdapterFactory = Callable[[HostContext], RuntimeAdapter]
# Ключи и фабрики добавляются только с проверенным кодом адаптеров.
BUILTIN_ADAPTERS: dict[str, AdapterFactory] = {
    "xray": XrayAdapter, "wireguard": wireguard_adapter, "amneziawg": amneziawg_adapter,
    "hysteria": HysteriaAdapter, "telemt": telemt_adapter, "mtg": mtg_adapter,
}


def host_gateway() -> GatewayController:
    names, ipv6 = registry()
    return GatewayController(GATEWAY_ROOT / "nginx.conf", CertificateStore(GATEWAY_ROOT / "certs"),
                             names, ipv6=ipv6)


def build_lifecycle(*, root: Path = PACKAGE_STATE) -> Lifecycle:
    gateway = host_gateway()
    packages = PackageRegistry(root, load_publisher())
    users = UserStore(root.parent / "users")
    material = MigrationMaterial(users)
    credentials = StoredCredentials(users, normalize_credential)
    context = HostContext(packages, gateway, material)
    adapters = {name: factory(context) for name, factory in BUILTIN_ADAPTERS.items()}
    xray, hysteria, telemt = (adapters[name] for name in ("xray", "hysteria", "telemt"))

    def endpoint():
        return next((item for item in gateway.identities if not item.is_ip), gateway.identities[0]).name

    def export_xray(user, settings):
        profiles = settings.profiles.values
        tls = next((profile.tls_identity() for profile in profiles if profile.kind is Kind.TLS), None)
        return xray_uris(settings, user.id, tls.name if tls else endpoint(), xray.public_reality(settings))

    def project_xray(settings, user_id, enabled):
        return set_xray_user(settings, user_id, enabled, imported=material.credential(user_id, "xray"))

    def project_hysteria(settings, user_id, enabled):
        return set_hysteria_user(settings, user_id, enabled, imported=material.credential(user_id, "hysteria"))

    def export_hysteria(user, settings):
        return hysteria_uris(settings, user.id, imported=material.credential(user.id, "hysteria"))

    def project_telemt(settings, user_id, enabled):
        return set_telemt_user(settings, user_id, enabled, imported=material.credential(user_id, "telemt"))

    def export_telemt(user, settings):
        profile = telemt_profile(settings, user.id, endpoint(), active=True, direct=not settings.exposure.shared)
        return (profile.uri(),) if profile is not None else ()

    builders = {
        "xray": (xray, project_xray,
                 lambda settings: settings.profiles.network(site_names=gateway.site_names, ipv4=settings.ipv4),
                 export_xray),
        "hysteria": (hysteria, project_hysteria,
                     lambda settings: render_hysteria(settings, idle_secret=idle_secret(hysteria.root, create=True)),
                     export_hysteria),
        "telemt": (telemt, project_telemt,
                   lambda settings: telemt.render(settings, cover_target(settings.exposure, gateway)), export_telemt),
    }
    user_modules = {}
    for name, (adapter, transform, validate, export) in builders.items():
        backend = SettingsBackend(name, adapter, transform, validate)
        user_modules[name] = SettingsUserModule(users, packages, backend,
                                               UserApplyJournal(adapter.root / USER_PENDING_NAME),
                                               export)
    def project_tunnel(settings, user_id, enabled):
        return project_tunnel_user(settings, user_id, enabled, material=material, credentials=credentials)

    def export_tunnel(user, settings):
        return client_file(settings, material.credential(user.id, settings.spec.module), endpoint=endpoint(), active=True)

    for name in TUNNELS:
        adapter = adapters[name]
        backend = TunnelUserBackend(adapter, project_tunnel)
        # Формат .conf не подмешивается в подписку HAPP.
        user_modules[name] = SettingsUserModule(users, packages, backend,
                                               UserApplyJournal(adapter.root / USER_PENDING_NAME),
                                               lambda user, settings: (), config_exporter=export_tunnel)
    lifecycle = Lifecycle(packages, adapters, NetworkRuntime(gateway), IntentJournal(root / PENDING_NAME),
                          site_names=gateway.site_names, epochs=users,
                          user_recovery=UserRecovery(packages, users, user_modules))
    lifecycle.user_store, lifecycle.user_modules = users, user_modules
    return lifecycle


def reconcile_boot(*, root: Path = PACKAGE_STATE) -> None:
    database = root / "registry.sqlite3"
    pending = root / PENDING_NAME
    if not database.exists() and not database.is_symlink():
        user_journals = (root.parent / "modules" / name / USER_PENDING_NAME for name in MODULE_IDS)
        if (pending.exists() or pending.is_symlink() or any(path.exists() or path.is_symlink() for path in user_journals)
                or host_gateway().network_routes().routes):
            raise LifecycleError("module_registry_missing")
        # Пустому ядру не нужны БД пакетов, сетевые утилиты или новый процесс.
        return
    lifecycle = build_lifecycle(root=root)
    if not lifecycle.adapters and not pending.exists() and not pending.is_symlink():
        if any(row["enabled"] for row in lifecycle.inventory.installed()):
            raise LifecycleError("adapter_unavailable")
        if not host_gateway().network_routes().routes:
            return
    lifecycle.reconcile()
