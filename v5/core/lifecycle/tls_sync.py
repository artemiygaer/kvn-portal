"""Передать действующую пару шлюза включённому модулю Hysteria2."""

import os
import sqlite3
import sys
import time

from v5.core.packages.manifest import PackageError

from .assembly import build_lifecycle


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        return 2
    try:
        adapter = build_lifecycle().adapters["hysteria"]
        deadline = time.monotonic() + 300
        while True:
            try:
                adapter.refresh_certificate()
                break
            except PackageError as exc:
                if str(exc) != "module_operation_busy" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
    except (OSError, ValueError, sqlite3.Error):
        print("Hysteria2: не удалось синхронизировать сертификат", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
