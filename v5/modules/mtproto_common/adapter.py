"""Lifecycle двух отдельных systemd-служб и независимых секретов."""

from dataclasses import asdict, replace
import hashlib
import hmac
import re
import time

from v5.core.lifecycle.controller import LifecycleError
from v5.core.lifecycle.systemd import SystemdAdapter
from v5.core.packages.docker_image import Docker
from v5.core.packages.manifest import PackageError, canonical_json, reject
from v5.core.private_files import private_directory

from .profiles import PORTS
from .runtime import MODULES, cover_target, inspect_container, listening, prepare, read_runtime, stop_container

STARTUP_SECONDS = 120


def public_exposure(exposure):
    """Публичная ревизия не содержит пользовательских или серверных ключей."""
    fields = asdict(exposure)
    fields['revision'] = hashlib.sha256(canonical_json(fields)).hexdigest()
    return fields


class MTProtoAdapter(SystemdAdapter):
    def __init__(self, context, module, settings_type, render, *, root=None, docker=None, restore_seed=None):
        if module not in PORTS:
            reject("unsafe_mtproto_runtime")
        self.context, self.settings_type, self.render = context, settings_type, render
        self.restore_seed = restore_seed
        self.root = MODULES / module if root is None else root
        self.docker = Docker() if docker is None else docker
        super().__init__(module, self._network, self._probe)

    def settings(self):
        try:
            return self.settings_type.load(self.root / "settings.json")
        except FileNotFoundError:
            reject("mtproto_settings_required")

    def _network(self):
        return self.settings().exposure.network(self.module, site_names=self.context.gateway.site_names)

    def preflight(self):
        self.docker.ready()
        settings = self.settings()
        self.render(settings, cover_target(settings.exposure, self.context.gateway))

    def running(self):
        if super().running():
            return True
        if (self.root / "runtime.json").exists():
            entry = inspect_container(self.docker, self.module)
            return bool(entry and entry["running"])
        return False

    def start(self):
        prepare(self.module, self.root, self.settings(), self.render, self.context, self.docker)
        super().start()

    def stop(self):
        super().stop()
        if (self.root / "runtime.json").exists():
            stop_container(self.docker, self.module)

    def prepare_upgrade(self, manifest, archive):
        self.docker.resolve(manifest, archive)

    def _probe(self):
        runtime = read_runtime(self.module, self.root)
        deadline = time.monotonic() + STARTUP_SECONDS
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                entry = inspect_container(self.docker, self.module, timeout=min(remaining, 25))
            except PackageError as exc:
                if str(exc) != "mtproto_inspect_unavailable":
                    raise
                entry = None
            if entry and entry["running"]:
                if not runtime.matches(entry):
                    raise LifecycleError("mtproto_running_state_mismatch")
                if listening(entry["pid"], runtime.address, PORTS[self.module]):
                    return
            time.sleep(max(0, min(0.4, deadline - time.monotonic())))
        raise LifecycleError("mtproto_not_healthy")

    def verify_export(self):
        runtime = read_runtime(self.module, self.root)
        entry = inspect_container(self.docker, self.module, timeout=5)
        if (not entry or not entry["running"] or not runtime.matches(entry)
                or not listening(entry["pid"], runtime.address, PORTS[self.module])):
            raise LifecycleError("mtproto_not_healthy")

    def exposure_view(self):
        packages = self.context.packages
        with packages.runtime_guard():
            if not any(row['module'] == self.module for row in packages.installed()):
                reject('module_not_installed')
            try:
                return public_exposure(self.settings().exposure)
            except PackageError as exc:
                if str(exc) == 'mtproto_settings_required':
                    return None
                raise

    def change_exposure(self, exposure, revision, *, validate=None):
        from .profiles import Exposure
        if (not isinstance(exposure, Exposure) or not isinstance(revision, str)
                or re.fullmatch(r'[0-9a-f]{64}', revision) is None):
            reject('mtproto_settings_invalid')
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item['module'] == self.module), None)
            if row is None:
                reject('module_not_installed')
            if row['enabled'] or row.get('updating') or self.running():
                reject('module_must_be_disabled')
            previous = self.settings()
            if not hmac.compare_digest(public_exposure(previous.exposure)['revision'], revision):
                reject('mtproto_settings_changed')
            if exposure.direct_ip is not None and previous.exposure.direct_ip is not None:
                try:
                    exposure = replace(exposure, direct_ip=previous.exposure.direct_ip)
                except ValueError:
                    reject('mtproto_settings_invalid')
            try:
                network = exposure.network(self.module, site_names=self.context.gateway.site_names)
            except ValueError:
                reject('mtproto_settings_invalid')
            if validate is not None:
                validate(network)
            replace(previous, exposure=exposure).save(self.root / 'settings.json')

    def configure(self, settings, *, initial=False, validate=None):
        if not isinstance(settings, self.settings_type):
            raise ValueError("Некорректные параметры MTProto")
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item["module"] == self.module), None)
            if row is None:
                reject("module_not_installed")
            if row["enabled"] or row.get("updating") or self.running():
                reject("module_must_be_disabled")
            path = self.root / "settings.json"
            if initial and (path.exists() or path.is_symlink()):
                reject("mtproto_already_configured")
            try:
                network = settings.exposure.network(self.module, site_names=self.context.gateway.site_names)
            except ValueError:
                reject("mtproto_settings_invalid")
            if validate is not None:
                validate(network)
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            private_directory(self.root.parent)
            self.root.mkdir(mode=0o700, exist_ok=True)
            material = getattr(self.context, "material", None)
            if self.restore_seed is not None and material is not None and not (path.exists() or path.is_symlink()):
                seed = material.server_seed(self.module)
                if seed is not None:
                    settings = self.restore_seed(settings, seed)
            settings.save(path)
