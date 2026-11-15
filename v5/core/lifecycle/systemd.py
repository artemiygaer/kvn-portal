"""Только заранее известные unit модулей, без аргументов команд из пакета."""

from collections.abc import Callable
import subprocess

from v5.core.contracts import validate_module_id
from v5.core.network.plan import ModuleNetwork

from .controller import LifecycleError


class SystemdAdapter:
    def __init__(self, module: str, describe: Callable[[], ModuleNetwork], probe: Callable[[], None]):
        self.module = validate_module_id(module)
        self.unit = f"kvn-v5-module-{self.module}.service"
        self.describe, self.probe = describe, probe

    def _command(self, *args: str, timeout: int = 45) -> str:
        try:
            return subprocess.run(
                ["/usr/bin/systemctl", "--no-pager", *args, self.unit],
                check=True, capture_output=True, text=True, timeout=timeout,
                stdin=subprocess.DEVNULL, env={"LC_ALL": "C"},
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise LifecycleError("module_systemd_failed") from exc

    def _state(self) -> str:
        lines = self._command("show", "-p", "LoadState", "-p", "ActiveState", timeout=10)
        info = dict(line.split("=", 1) for line in lines.splitlines() if "=" in line)
        if info.get("ActiveState") not in {"active", "inactive", "failed", "activating", "deactivating", "reloading",
                                          "refreshing", "maintenance"} or not info.get("LoadState"):
            raise LifecycleError("module_state_unavailable")
        return info["ActiveState"]

    def network(self) -> ModuleNetwork:
        return self.describe()

    def running(self) -> bool:
        return self._state() not in {"inactive", "failed"}

    def start(self) -> None:
        self._command("start")

    def stop(self) -> None:
        self._command("stop")

    def verify(self) -> None:
        if self._state() != "active":
            raise LifecycleError("module_not_healthy")
        self.probe()
