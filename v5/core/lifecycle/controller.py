"""Координировать процессы, ingress и подтверждённое состояние пакетов."""

from collections.abc import Mapping
from contextlib import AbstractContextManager
from dataclasses import replace
from typing import Protocol

from v5.core.contracts import validate_module_id
from v5.core.network.plan import ModuleNetwork, NetworkPlan, build_plan

from .journal import IntentJournal


class LifecycleError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class RuntimeAdapter(Protocol):
    def network(self) -> ModuleNetwork: ...
    def running(self) -> bool: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def verify(self) -> None: ...


class Inventory(Protocol):
    def runtime_guard(self) -> AbstractContextManager: ...
    def require_user_idle(self) -> None: ...
    def installed(self) -> tuple[dict, ...]: ...
    def commit_enabled(self, previous: frozenset[str], desired: frozenset[str]) -> None: ...
    def pending_upgrade(self): ...
    def begin_upgrade(self, module: str, ticket: str): ...
    def candidate_selected(self, pending) -> bool: ...
    def verified_candidate(self, pending): ...
    def select_upgrade(self, pending, *, rollback: bool = False) -> None: ...
    def finish_upgrade(self, pending, *, commit: bool) -> None: ...


class Ingress(Protocol):
    def preflight(self, plan: NetworkPlan, previous: NetworkPlan) -> None: ...
    def apply(self, plan: NetworkPlan, *, reconcile: bool = False) -> None: ...
    def verify(self, plan: NetworkPlan) -> None: ...


class Lifecycle:
    def __init__(self, inventory: Inventory, adapters: Mapping[str, RuntimeAdapter], ingress: Ingress,
                 journal: IntentJournal, *, site_names: tuple[str, ...], epochs=None, user_recovery=None):
        self.inventory, self.adapters, self.ingress = inventory, dict(adapters), ingress
        self.journal, self.site_names = journal, site_names
        self.epochs = epochs
        self.user_recovery = user_recovery
        for module in self.adapters:
            validate_module_id(module)

    def _state(self) -> tuple[frozenset[str], frozenset[str]]:
        records = self.inventory.installed()
        return (frozenset(row["module"] for row in records),
                frozenset(row["module"] for row in records if row["enabled"]))

    def _plan(self, enabled: frozenset[str]) -> NetworkPlan:
        if not enabled <= self.adapters.keys():
            raise LifecycleError("adapter_unavailable")
        descriptors = []
        for module in sorted(enabled):
            descriptor = self.adapters[module].network()
            if not isinstance(descriptor, ModuleNetwork) or descriptor.module != module:
                raise LifecycleError("adapter_identity_mismatch")
            descriptors.append(replace(descriptor, enabled=True))
        return build_plan(descriptors, site_names=self.site_names)

    def preview_configuration_locked(self, module: str, candidate: ModuleNetwork) -> NetworkPlan:
        """Проверить будущий профиль вместе с включёнными модулями под общей блокировкой."""
        validate_module_id(module)
        if not isinstance(candidate, ModuleNetwork) or candidate.module != module:
            raise LifecycleError("adapter_identity_mismatch")
        installed, enabled = self._state()
        if module not in installed:
            raise LifecycleError("module_not_installed")
        descriptors = [replace(candidate, enabled=True)]
        for name in sorted(enabled - {module}):
            adapter = self.adapters.get(name)
            if adapter is None:
                raise LifecycleError("adapter_unavailable")
            network = adapter.network()
            if not isinstance(network, ModuleNetwork) or network.module != name:
                raise LifecycleError("adapter_identity_mismatch")
            descriptors.append(replace(network, enabled=True))
        return build_plan(descriptors, site_names=self.site_names)

    def _run(self, plan: NetworkPlan, *, reconcile: bool, user_affected=frozenset()) -> dict:
        policies = {}
        for module in plan.active:
            adapter = self.adapters[module]
            if self.user_recovery is not None and module in user_affected:
                policies[module] = self.user_recovery.project_locked(module)
            if not adapter.running():
                adapter.start()
            adapter.verify()
        # Сначала убрать маршруты, затем останавливать их backend.
        self.ingress.apply(plan, reconcile=reconcile)
        self._stop_inactive(plan)
        self.ingress.verify(plan)
        return policies

    def _confirm_epoch(self, module: str, policies: dict) -> None:
        if self.epochs is None:
            return
        policy = policies.get(module)
        if policy is None:
            self.epochs.confirm_module(module)
        else:
            self.epochs.confirm_module(module, policy=policy)

    def _stop_inactive(self, plan: NetworkPlan) -> None:
        for module, adapter in sorted(self.adapters.items()):
            if module not in plan.active and adapter.running():
                adapter.stop()
                if adapter.running():
                    raise LifecycleError("module_stop_unconfirmed")

    def _recover(self) -> NetworkPlan:
        _, committed = self._state()
        plan = self._plan(committed)
        pending = self.journal.read()
        affected = frozenset(self.adapters) if pending is None else pending[0] ^ pending[1]
        if self.epochs is not None:
            for module in sorted(affected):
                self.epochs.invalidate_module(module)
        try:
            policies = self._run(plan, reconcile=True, user_affected=affected)
        except BaseException:
            # Даже если шлюз не восстановился, закрыть неподтверждённые прямые sockets.
            self._stop_inactive(plan)
            raise
        for module in sorted(affected & committed):
            self._confirm_epoch(module, policies)
        self.journal.clear()
        return plan

    def reconcile(self) -> NetworkPlan:
        with self.inventory.runtime_guard():
            if self.user_recovery is not None:
                self.user_recovery.recover_offline_locked()
            self.inventory.require_user_idle()
            if self.inventory.pending_upgrade() is not None:
                return self._recover_upgrade()
            self.journal.read()
            return self._recover()

    def _recover_upgrade(self) -> NetworkPlan:
        pending = self.inventory.pending_upgrade()
        if pending is None:
            raise LifecycleError("module_revision_changed")
        if self.epochs is not None:
            self.epochs.invalidate_module(pending.module)
        _, committed = self._state()
        if self.inventory.candidate_selected(pending):
            without = self._plan(committed - {pending.module})
            try:
                self._run(without, reconcile=True)
            except BaseException:
                self._stop_inactive(without)
                self.inventory.select_upgrade(pending, rollback=True)
                raise
            self.inventory.select_upgrade(pending, rollback=True)
        old = self._plan(committed)
        policies = self._run(old, reconcile=True, user_affected={pending.module})
        if pending.module in committed:
            self._confirm_epoch(pending.module, policies)
        self.inventory.finish_upgrade(pending, commit=False)
        return old

    def upgrade(self, module: str, ticket: str) -> NetworkPlan:
        validate_module_id(module)
        with self.inventory.runtime_guard():
            self.inventory.require_user_idle()
            if self.inventory.pending_upgrade() is not None:
                self._recover_upgrade()
            if self.journal.read() is not None:
                self._recover()
            _, committed = self._state()
            old, without = self._plan(committed), self._plan(committed - {module})
            pending = self.inventory.begin_upgrade(module, ticket)
            prepare = getattr(self.adapters[module], "prepare_upgrade", None)
            if prepare is not None:
                try:
                    # Долгая загрузка образа не прерывает текущие подключения.
                    prepare(*self.inventory.verified_candidate(pending))
                except BaseException:
                    self.inventory.finish_upgrade(pending, commit=False)
                    raise
            try:
                if self.epochs is not None:
                    self.epochs.invalidate_module(module)
                self._run(without, reconcile=False)
                self.inventory.select_upgrade(pending)
                policies = self._run(old, reconcile=False, user_affected={module})
                self._confirm_epoch(module, policies)
                self.inventory.finish_upgrade(pending, commit=True)
            except BaseException as error:
                try:
                    self._recover_upgrade()
                except Exception as failure:
                    raise LifecycleError("module_upgrade_rollback_unconfirmed") from failure
                if not isinstance(error, Exception):
                    raise
                raise LifecycleError("module_upgrade_rolled_back") from error
            return old

    def preview_enable(self, module: str) -> NetworkPlan:
        """Проверить декларации без запуска, bind и исправления состояния."""
        validate_module_id(module)
        with self.inventory.runtime_guard():
            self.inventory.require_user_idle()
            if self.inventory.pending_upgrade() is not None or self.journal.read() is not None:
                raise LifecycleError("module_reconcile_required")
            installed, current = self._state()
            if module not in installed:
                raise LifecycleError("module_not_installed")
            return self._plan(current | {module})

    def change(self, module: str, enabled: bool) -> NetworkPlan:
        validate_module_id(module)
        if type(enabled) is not bool:
            raise ValueError("Некорректное состояние модуля")
        with self.inventory.runtime_guard():
            self.inventory.require_user_idle()
            if self.inventory.pending_upgrade() is not None:
                self._recover_upgrade()
            if self.journal.read() is not None:
                self._recover()
            installed, current = self._state()
            if module not in installed:
                raise LifecycleError("module_not_installed")
            desired = current | {module} if enabled else current - {module}
            before, after = self._plan(current), self._plan(desired)
            if desired == current:
                for name, adapter in self.adapters.items():
                    if name in current:
                        adapter.verify()
                    elif adapter.running():
                        raise LifecycleError("module_reconcile_required")
                self.ingress.verify(before)
                return before
            if enabled:
                preflight = getattr(self.adapters[module], "preflight", None)
                if preflight is not None:
                    preflight()
            self.ingress.preflight(after, before)
            self.journal.write(current, desired)
            try:
                if self.epochs is not None:
                    self.epochs.invalidate_module(module)
                policies = self._run(after, reconcile=False, user_affected={module})
                self.inventory.commit_enabled(current, desired)
                if enabled:
                    self._confirm_epoch(module, policies)
            except BaseException as error:
                try:
                    recovered = self._recover()
                except Exception as failure:
                    raise LifecycleError("network_rollback_unconfirmed") from failure
                if not isinstance(error, Exception):
                    raise
                if frozenset(recovered.active) == desired:
                    return recovered
                raise LifecycleError("network_apply_rolled_back") from error
            self.journal.clear()
            return after
