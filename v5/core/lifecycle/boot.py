"""Однократная сверка желаемого состояния модулей после загрузки Debian."""

import os
import sqlite3
import sys

from v5.core.packages.manifest import PackageError
from v5.core.tls.transaction import GatewayApplyError

from .assembly import reconcile_boot
from .controller import LifecycleError


def main() -> int:
    if os.geteuid() != 0:
        return 1
    try:
        reconcile_boot()
    except (LifecycleError, GatewayApplyError, PackageError) as exc:
        code = getattr(exc, "code", str(exc))
        print(f"Сверка модулей не завершена: {code}", file=sys.stderr)
        return 1
    except (OSError, sqlite3.Error, ValueError):
        print("Сверка модулей не завершена: состояние недоступно", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
