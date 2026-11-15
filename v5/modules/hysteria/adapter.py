"""Опциональный адаптер Hysteria2: без SNI-маршрутов и без установки Docker."""

from dataclasses import replace
import hashlib
import hmac
import re
from secrets import token_urlsafe
import time

from v5.core.lifecycle.controller import LifecycleError
from v5.core.lifecycle.systemd import SystemdAdapter
from v5.core.packages.docker_image import Docker
from v5.core.packages.manifest import PackageError, canonical_json, reject
from v5.core.private_files import private_directory

from .config import MODULE, Settings, render_server
from .idle import idle_secret
from .runtime import (
    MODULE_ROOT, certificate, inspect_container, listening, prepare, publish_certificate, runtime_state, stop_container,
)

STARTUP_SECONDS = 120


def public_settings(settings):
    fields = {'identity': settings.tls.name, 'port': settings.port, 'bind': settings.bind,
              'salamander': settings.salamander is not None}
    fields['revision'] = hashlib.sha256(canonical_json(fields)).hexdigest()
    return fields


class HysteriaAdapter(SystemdAdapter):
    def __init__(self, context, *, root=MODULE_ROOT, docker=None):
        self.context, self.root = context, root
        self.docker = Docker() if docker is None else docker
        super().__init__(MODULE, self._network, self._probe)

    def settings(self):
        try:
            return Settings.load(self.root / "settings.json")
        except FileNotFoundError:
            reject("hysteria_settings_required")

    def _network(self):
        return self.settings().network()

    def preflight(self) -> None:
        settings = self.settings()
        render_server(settings, idle_secret=idle_secret(self.root, create=True))
        certificate(settings, self.context.gateway)
        self.docker.ready()

    def running(self) -> bool:
        if super().running():
            return True
        if (self.root / "runtime.json").exists():
            current = inspect_container(self.docker)
            return bool(current and current["running"])
        return False

    def start(self) -> None:
        prepare(self.root, self.context.packages, self.context.gateway, self.docker)
        super().start()

    def stop(self) -> None:
        super().stop()
        if (self.root / "runtime.json").exists():
            stop_container(self.docker)

    def prepare_upgrade(self, manifest, archive) -> None:
        self.docker.resolve(manifest, archive)

    def refresh_certificate(self) -> None:
        packages = self.context.packages
        with packages.runtime_guard():
            if not any(item["module"] == MODULE and item["enabled"] for item in packages.installed()):
                return
            publish_certificate(self.root, certificate(self.settings(), self.context.gateway))

    def _probe(self) -> None:
        runtime = runtime_state(self.root)
        # Первый запуск Docker bridge на малом сервере может быть долгим.
        deadline = time.monotonic() + STARTUP_SECONDS
        while (remaining := deadline - time.monotonic()) > 0:
            try:
                current = inspect_container(self.docker, timeout=min(remaining, 25))
            except PackageError as exc:
                # На холодном Docker inspect может ждать запуска контейнера.
                # Повторяем только сбой транспорта, чужой контейнер не принимаем.
                if str(exc) != "hysteria_inspect_unavailable":
                    raise
                current = None
            if current and current["running"]:
                if not runtime.matches(current):
                    raise LifecycleError("hysteria_running_state_mismatch")
                if listening(current["pid"]):
                    return
            time.sleep(max(0, min(0.4, deadline - time.monotonic())))
        raise LifecycleError("hysteria_not_healthy")

    def verify_export(self) -> None:
        """Одна проверка текущего поколения и слушающего UDP, без повтора."""
        runtime = runtime_state(self.root)
        current = inspect_container(self.docker, timeout=5)
        if (not current or not current["running"] or not runtime.matches(current)
                or not listening(current["pid"])):
            raise LifecycleError("hysteria_not_healthy")

    def settings_view(self):
        packages = self.context.packages
        with packages.runtime_guard():
            if not any(row['module'] == MODULE for row in packages.installed()):
                reject('module_not_installed')
            try:
                return public_settings(self.settings())
            except PackageError as exc:
                if str(exc) == 'hysteria_settings_required':
                    return None
                raise

    def change_settings(self, tls, port, salamander, revision, *, validate=None):
        from v5.core.tls.identity import TLSIdentity
        if (not isinstance(tls, TLSIdentity) or type(port) is not int or type(salamander) is not bool
                or not isinstance(revision, str) or re.fullmatch(r'[0-9a-f]{64}', revision) is None):
            reject('hysteria_settings_invalid')
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item['module'] == MODULE), None)
            if row is None:
                reject('module_not_installed')
            if row['enabled'] or row.get('updating') or self.running():
                reject('module_must_be_disabled')
            previous = self.settings()
            if not hmac.compare_digest(public_settings(previous)['revision'], revision):
                reject('hysteria_settings_changed')
            if tls not in self.context.gateway.identities:
                reject('hysteria_tls_identity_unregistered')
            try:
                secret = (previous.salamander or token_urlsafe(32)) if salamander else None
                candidate = replace(previous, tls=tls, port=port, salamander=secret)
                network = candidate.network()
            except (TypeError, ValueError):
                reject('hysteria_settings_invalid')
            if validate is not None:
                validate(network)
            candidate.save(self.root / 'settings.json')

    def configure(self, settings: Settings, *, initial=False, validate=None) -> None:
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item["module"] == MODULE), None)
            if row is None:
                reject("module_not_installed")
            if row["enabled"] or row.get("updating") or self.running():
                reject("module_must_be_disabled")
            path = self.root / "settings.json"
            if initial and (path.exists() or path.is_symlink()):
                reject("hysteria_already_configured")
            if settings.tls not in self.context.gateway.identities:
                reject("hysteria_tls_identity_unregistered")
            network = settings.network()
            if validate is not None:
                validate(network)
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            private_directory(self.root.parent)
            self.root.mkdir(mode=0o700, exist_ok=True)
            settings.save(path)
