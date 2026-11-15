"""Привязать отдельный kernel-туннель к подписанному пакету и systemd."""

from dataclasses import replace
import hashlib
import hmac
import re

from v5.core.lifecycle.controller import LifecycleError
from v5.core.lifecycle.systemd import SystemdAdapter
from v5.core.packages.manifest import canonical_json
from v5.core.private_files import private_directory

from .config import Tunnel
from .runtime import TunnelRuntime
from .state import MODULES_ROOT, State
from .users import restore_seed


def public_egress(state):
    fields = {'module': state.spec.module, 'egress': state.settings.egress,
              'address': state.settings.address, 'mtu': state.settings.mtu}
    fields['revision'] = hashlib.sha256(canonical_json(fields)).hexdigest()
    return fields


class TunnelAdapter(SystemdAdapter):
    def __init__(self, context, spec: Tunnel, *, modules_root=MODULES_ROOT):
        self.context, self.spec = context, spec
        self.root = modules_root / spec.module
        self.runtime = TunnelRuntime(spec)
        super().__init__(spec.module, self._network, self._probe)

    def settings(self) -> State:
        try:
            return State.load(self.spec, self.root / "settings.json")
        except FileNotFoundError as exc:
            raise LifecycleError("tunnel_configuration_required") from exc

    def _network(self):
        self.settings()
        return self.spec.network(ipv6=self.context.gateway.ipv6)

    def preflight(self) -> None:
        self.runtime.preflight(self.settings())

    def running(self) -> bool:
        if super().running():
            return True
        link = self.runtime.link()
        return bool(link and link.owned)

    def start(self) -> None:
        self.context.packages.verified_install(self.spec.module)
        self._command("start", timeout=135)

    def stop(self) -> None:
        self._command("stop", timeout=90)
        self.runtime.stop()

    def _probe(self) -> None:
        self.runtime.verify(self.settings())

    def egress_view(self):
        packages = self.context.packages
        with packages.runtime_guard():
            if not any(row['module'] == self.spec.module for row in packages.installed()):
                raise LifecycleError('module_not_installed')
            try:
                return public_egress(self.settings())
            except LifecycleError as exc:
                if exc.code == 'tunnel_configuration_required':
                    return None
                raise

    def change_egress(self, egress, revision):
        if (not isinstance(revision, str) or re.fullmatch(r'[0-9a-f]{64}', revision) is None):
            raise LifecycleError('tunnel_configuration_invalid')
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            row = next((item for item in packages.installed() if item['module'] == self.spec.module), None)
            if row is None:
                raise LifecycleError('module_not_installed')
            if row['enabled'] or row.get('updating') or self.running():
                raise LifecycleError('module_must_be_disabled')
            previous = self.settings()
            if not hmac.compare_digest(public_egress(previous)['revision'], revision):
                raise LifecycleError('tunnel_configuration_changed')
            try:
                candidate = replace(previous, settings=replace(previous.settings, egress=egress))
            except (TypeError, ValueError):
                raise LifecycleError('tunnel_egress_invalid') from None
            candidate.save(self.root / 'settings.json')

    def configure(self, state: State, *, initial=False) -> None:
        if state.spec != self.spec:
            raise LifecycleError("tunnel_module_mismatch")
        packages = self.context.packages
        with packages.runtime_guard():
            packages.require_network_idle()
            record = next((row for row in packages.installed() if row["module"] == self.spec.module), None)
            if record is None:
                raise LifecycleError("module_not_installed")
            self.root.parent.mkdir(mode=0o700, exist_ok=True)
            private_directory(self.root.parent)
            self.root.mkdir(mode=0o700, exist_ok=True)
            path = self.root / "settings.json"
            if initial and (path.exists() or path.is_symlink()):
                raise LifecycleError("tunnel_already_configured")
            if not record["enabled"]:
                if self.running():
                    raise LifecycleError("module_reconcile_required")
                material = getattr(self.context, "material", None)
                if material is not None and not (path.exists() or path.is_symlink()):
                    seed = material.server_seed(self.spec.module)
                    if seed is not None:
                        state = restore_seed(state, seed)
                state.save(path)
                return
            previous = self.settings()
            if state == previous:
                return
            self.runtime.sync(previous, state)
            try:
                state.save(path)
            except BaseException:
                self.runtime.sync(state, previous)
                raise
