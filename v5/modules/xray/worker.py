"""Точка запуска только для systemd unit Xray."""

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
        if current:
            if current["running"]:
                if current["image"] != runtime.image:
                    reject("xray_running_image_mismatch")
                args = docker.command("container", "attach", "--no-stdin", current["id"])
            else:
                stop_container(docker)
                args = docker.command(*runtime.arguments(test=False))
        else:
            args = docker.command(*runtime.arguments(test=False))
        os.execve(args[0], args, ENV)
    except PackageError as exc:
        print(f"Xray: {exc}", file=sys.stderr)
    except (OSError, ValueError):
        print("Xray: рабочее поколение недоступно", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
