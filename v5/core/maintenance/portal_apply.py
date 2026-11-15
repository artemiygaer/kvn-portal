"""Независимая systemd-задача применения проверенного обновления ядра."""

import json
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time
import traceback

from v5.core import audit
from v5.core.packages.lock import runtime_lock
from v5.core.packages.signature import load_publisher
from v5.core.private_files import private_directory, read_private
from v5.core.release import CORE_PIN

from .__main__ import locked
from .core_update import CoreUpdate, UpdateError
from .portal_store import PortalUpdateStore, TICKET, UpdateStoreError

LOCATION = Path("/etc/kvn-v5/core/install-location.json")
_INSTALL = re.compile(r"/root/[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z", re.ASCII)


def install_location(path=LOCATION):
    private_directory(path.parent)
    try:
        value = json.loads(read_private(path, 4096))
    except FileNotFoundError as exc:
        raise UpdateStoreError("core_install_location_missing") from exc
    if (not isinstance(value, dict) or set(value) != {"format", "path"} or type(value["format"]) is not int
            or value["format"] != 1 or not isinstance(value["path"], str) or _INSTALL.fullmatch(value["path"]) is None):
        raise UpdateStoreError("core_install_location_invalid")
    return Path(value["path"])


def _apply(payload, uid):
    deadline = time.monotonic() + 20
    while True:
        result = subprocess.run(["/usr/bin/systemctl", "list-units", "--no-legend", "--plain",
                                 "--state=active,activating,deactivating", "kvn-v5-core-update@*.service"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=True)
        if not result.stdout.strip():
            break
        if time.monotonic() >= deadline:
            raise UpdateStoreError("core_update_busy")
        time.sleep(.5)
    with locked(install_location()):
        with runtime_lock(Path("/var/lib/kvn-v5/packages")):
            private_directory(CORE_PIN.parent)
            return CoreUpdate().apply(payload, load_publisher(CORE_PIN), uid)


def perform(ticket, store, *, executor=_apply):
    if not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None:
        raise UpdateStoreError("core_ticket_invalid")
    deadline = time.monotonic() + 15
    while True:
        try:
            with store.locked():
                if store.record(ticket)["status"] != "queued":
                    raise UpdateStoreError("core_not_ready")
                store.set_status(ticket, "running")
            break
        except UpdateStoreError as exc:
            if str(exc) != "core_update_busy" or time.monotonic() >= deadline:
                raise
            time.sleep(.25)
    ok = False
    try:
        executor(store._directory(ticket) / "payload", store.uid)
        ok = True
    finally:
        with store.locked():
            store.set_status(ticket, "applied" if ok else "failed")
        audit.record("maintenance.core_update", ok)
    return ok


def main():
    if len(sys.argv) != 2 or TICKET.fullmatch(sys.argv[1]) is None:
        raise SystemExit(2)
    time.sleep(2)
    try:
        uid = pwd.getpwnam("kvn-v5-web").pw_uid
        perform(sys.argv[1], PortalUpdateStore(uid))
    except Exception as exc:
        # В журнале фиксируем только типы и заранее заданные сообщения ядра:
        # исключения внешних команд могут содержать пути или секреты.
        current = exc
        for _ in range(4):
            if current is None:
                break
            detail = f": {current}" if isinstance(current, UpdateError) else ""
            print(f"Диагностика обновления: {type(current).__name__}{detail}", file=sys.stderr)
            if isinstance(current, PermissionError):
                for frame in traceback.extract_tb(current.__traceback__):
                    print(f"  {Path(frame.filename).name}:{frame.lineno} ({frame.name})", file=sys.stderr)
            current = current.__cause__
        print("Обновление не подтверждено. Проверьте службу и core-recover по SSH.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
