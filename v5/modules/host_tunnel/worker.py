"""Вход systemd: только start/stop известного WireGuard или AmneziaWG."""

import sys

from v5.core.lifecycle.controller import LifecycleError
from v5.core.network.plan import NetworkConflict
from v5.core.packages.manifest import PackageError

from .runtime import TunnelRuntime
from .state import MODULES_ROOT, TUNNELS, State


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("start", "stop") or sys.argv[2] not in TUNNELS:
        return 2
    operation, spec = sys.argv[1], TUNNELS[sys.argv[2]]
    runtime = TunnelRuntime(spec)
    try:
        if operation == "start":
            runtime.start(State.load(spec, MODULES_ROOT / spec.module / "settings.json"))
        else:
            runtime.stop()
    except (LifecycleError, NetworkConflict, PackageError) as exc:
        print(f"Туннель: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("Туннель: закрытые настройки недоступны", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
