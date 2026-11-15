"""Только фиксированные argv для запуска известных MTProto-адаптеров."""

import os
import sys

from v5.core.packages.docker_image import Docker, ENV
from v5.core.packages.manifest import PackageError, reject

from .profiles import PORTS
from .runtime import MODULES, inspect_container, read_runtime, stop_container


def main():
    if os.geteuid() != 0 or len(sys.argv) != 3 or sys.argv[1] not in PORTS or sys.argv[2] not in ("run", "stop"):
        return 2
    module, action = sys.argv[1:]
    docker = Docker()
    try:
        if action == "stop":
            stop_container(docker, module)
            return 0
        runtime = read_runtime(module, MODULES / module)
        entry = inspect_container(docker, module)
        if entry and entry["running"]:
            if not runtime.matches(entry):
                reject("mtproto_running_state_mismatch")
            args = docker.command("container", "attach", "--no-stdin", entry["id"])
        else:
            if entry:
                stop_container(docker, module)
            args = docker.command(*runtime.arguments())
        os.execve(args[0], args, ENV)
    except PackageError as exc:
        print(f"{module}: {exc}", file=sys.stderr)
    except (OSError, ValueError):
        print(f"{module}: рабочее поколение недоступно", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
