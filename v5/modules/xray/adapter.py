"""Встроенный адаптер Xray: проверенные ресурсы, systemd и ingress ядра."""

from dataclasses import asdict
import hashlib
import hmac
import socket
import time

from v5.core.lifecycle.controller import LifecycleError
from v5.core.lifecycle.systemd import SystemdAdapter
from v5.core.packages.docker_image import Docker
from v5.core.packages.manifest import canonical_json, reject
from v5.core.private_files import private_directory

from .config import Settings
from .profiles import Kind, Profile, Profiles
from .credentials import profile_reality_keys
from .runtime import MODULE_ROOT, inspect_container, prepare, runtime_state, stop_container

STARTUP_SECONDS = 75


def public_profile(profile: Profile) -> dict:
    """Только несекретные параметры и версия для защиты от устаревшей формы."""
    result = asdict(profile)
    result['revision'] = hashlib.sha256(canonical_json(result)).hexdigest()
    return result


class XrayAdapter(SystemdAdapter):
    def __init__(self, context, *, root=MODULE_ROOT, docker=None):
        self.context, self.root = context, root
        self.docker = Docker() if docker is None else docker
        super().__init__("xray", self._network, self._probe)

    def settings(self):
        try:
            return Settings.load(self.root / "settings.json")
        except FileNotFoundError:
            reject("xray_profiles_required")

    def _network(self):
        settings = self.settings()
        if not settings.profiles.values:
            reject("xray_profiles_required")
        return settings.profiles.network(site_names=self.context.gateway.site_names, ipv4=settings.ipv4)

    def running(self) -> bool:
        if super().running():
            return True
        if (self.root / "runtime.json").exists():
            current = inspect_container(self.docker)
            return bool(current and current["running"])
        return False

    def start(self) -> None:
        prepare(self.root, self.context.packages, self.context.gateway, self.docker, imported=self._imported_reality())
        super().start()

    def _imported_reality(self):
        material = getattr(self.context, "material", None)
        return material.server_seed("xray") if material is not None else None

    def public_reality(self, settings):
        keys = profile_reality_keys(self.root / "reality.json", settings.profiles.values, imported=self._imported_reality())
        return {kind: key.public for kind, key in keys.items()}

    def prepare_upgrade(self, manifest, archive) -> None:
        self.docker.resolve(manifest, archive)

    def stop(self) -> None:
        super().stop()
        if (self.root / "runtime.json").exists():
            stop_container(self.docker)

    def _addresses(self):
        settings = self.settings()
        addresses = []
        for item in settings.profiles.values:
            if not item.exposure.direct:
                addresses.append(("127.0.0.1", item.port))
            elif settings.ipv4 == "0.0.0.0":
                addresses.extend((("127.0.0.1", item.port), ("::1", item.port)))
            else:
                addresses.append((settings.ipv4, item.port))
        return addresses

    def verify_export(self) -> None:
        """Проверка без ожидания старта под блокировкой выдачи профилей."""
        config = runtime_state(self.root)
        current = inspect_container(self.docker, timeout=5)
        if not current or not current["running"] or not config.matches(current):
            raise LifecycleError("xray_not_healthy")
        for address in self._addresses():
            with socket.create_connection(address, timeout=0.5):
                pass

    def _probe(self) -> None:
        config = runtime_state(self.root)
        # Первый запуск distroless-образа на маленьком хосте может занять десятки секунд.
        deadline = time.monotonic() + STARTUP_SECONDS
        addresses = self._addresses()
        while time.monotonic() < deadline:
            try:
                for address in addresses:
                    with socket.create_connection(address, timeout=1):
                        pass
            except OSError:
                pass
            else:
                # Не запускать Docker CLI на каждом опросе, пока порты ещё закрыты.
                current = inspect_container(self.docker)
                if current and current["running"] and current["image"] == config.image:
                    return
            time.sleep(0.5)
        raise LifecycleError("xray_not_healthy")

    def configure(self, settings: Settings, *, initial=False, validate=None) -> None:
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item["module"] == "xray"), None)
            if row is None:
                reject("module_not_installed")
            if row["enabled"] or row.get("updating") or self.running():
                reject("module_must_be_disabled")
            path = self.root / "settings.json"
            if initial and (path.exists() or path.is_symlink()):
                reject("xray_already_configured")
            network = settings.profiles.network(site_names=self.context.gateway.site_names, ipv4=settings.ipv4)
            if validate is not None:
                validate(network)
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            private_directory(self.root.parent)
            self.root.mkdir(mode=0o700, exist_ok=True)
            settings.save(path)

    def add_profile(self, profile, *, validate=None) -> None:
        """Добавить профиль выключенного модуля, не меняя выданные UUID и ключи."""
        if not isinstance(profile, Profile):
            raise ValueError("Некорректный профиль Xray")
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item["module"] == "xray"), None)
            if row is None:
                reject("module_not_installed")
            if row["enabled"] or row.get("updating") or self.running():
                reject("module_must_be_disabled")
            previous = self.settings()
            try:
                candidate = Settings(Profiles((*previous.profiles.values, profile)), previous.accounts, previous.ipv4)
            except ValueError:
                reject("xray_profile_conflict")
            network = candidate.profiles.network(site_names=self.context.gateway.site_names, ipv4=candidate.ipv4)
            if validate is not None:
                validate(network)
            candidate.save(self.root / "settings.json")

    def profile_list(self) -> list[dict]:
        packages = self.context.packages
        with packages.runtime_guard():
            if not any(row['module'] == 'xray' for row in packages.installed()):
                reject('module_not_installed')
            try:
                return [public_profile(profile) for profile in self.settings().profiles.values]
            except FileNotFoundError:
                return []
            except ValueError as exc:
                if str(exc) == 'xray_profiles_required':
                    return []
                raise

    def change_profile(self, kind: Kind, revision: str, replacement: Profile | None, *, validate=None) -> None:
        if (not isinstance(kind, Kind) or not isinstance(revision, str) or len(revision) != 64
                or any(ch not in '0123456789abcdef' for ch in revision)
                or (replacement is not None and (not isinstance(replacement, Profile) or replacement.kind != kind))):
            reject('xray_settings_invalid')
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item['module'] == 'xray'), None)
            if row is None:
                reject('module_not_installed')
            if row['enabled'] or row.get('updating') or self.running():
                reject('module_must_be_disabled')
            previous = self.settings()
            old = next((item for item in previous.profiles.values if item.kind == kind), None)
            if old is None or not hmac.compare_digest(public_profile(old)['revision'], revision):
                reject('xray_profile_changed')
            if replacement is None and any(kind in account.grants for account in previous.accounts):
                reject('xray_profile_in_use')
            values = tuple(replacement if item.kind == kind else item for item in previous.profiles.values
                           if item.kind != kind or replacement is not None)
            try:
                candidate = Settings(Profiles(values), previous.accounts, previous.ipv4)
            except ValueError:
                reject('xray_profile_conflict')
            network = candidate.profiles.network(site_names=self.context.gateway.site_names, ipv4=candidate.ipv4)
            if validate is not None:
                validate(network)
            candidate.save(self.root / 'settings.json')
