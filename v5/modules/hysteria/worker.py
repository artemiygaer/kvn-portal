"""Фиксированная точка входа systemd для Hysteria2."""

import os
import sys

from v5.core.packages.docker_image import Docker, ENV
from v5.core.packages.manifest import PackageError, reject

from .runtime import inspect_container, runtime_state, stop_container


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 2 or sys.argv[1] not in ("run", "stop"):
        return 2
    docker = Docker()
    try:
        if sys.argv[1] == "stop":
            stop_container(docker)
            return 0
        runtime = runtime_state()
        current = inspect_container(docker)
        if current and current["running"]:
            if not runtime.matches(current):
                reject("hysteria_running_state_mismatch")
            args = docker.command("container", "attach", "--no-stdin", current["id"])
        else:
            if current:
                stop_container(docker)
            args = docker.command(*runtime.arguments())
        os.execve(args[0], args, ENV)
    except PackageError as exc:
        print(f"Hysteria2: {exc}", file=sys.stderr)
    except (OSError, ValueError):
        print("Hysteria2: рабочее поколение недоступно", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
