"""Открыть Shell один раз после подтверждённого перехода с v5.0.8."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import time

from v5.core.packages.debian_provision import ProvisionError, parse_os_release, run_apt_transaction
from v5.core.release import LIVE, installed_version

from . import WEB_SOCKET_UNIT

TRANSACTIONS = LIVE.parent / ".kvn-v5-core"
SYSTEMCTL = "/usr/bin/systemctl"
UNIT = "kvn-v5-shell-transition.service"


def _launch(action, live, run):
    run(("/usr/bin/systemd-run", "--no-block", "--collect", f"--unit={UNIT}",
         f"--working-directory={live}",
         "-p", "UMask=0077", "-p", "RuntimeMaxSec=900s",
         "/usr/bin/python3", "-m", "v5.core.console.upgrade", action),
        cwd=live, timeout=5, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def is_transition(*, live=LIVE, transactions=TRANSACTIONS):
    # Установка с нуля и рестарт службы не имеют предыдущего дерева в pending.
    return installed_version(live) == "5.0.9" and installed_version(transactions / "pending/tree") == "5.0.8"


def schedule(*, live=LIVE, transactions=TRANSACTIONS, run=subprocess.run):
    if is_transition(live=live, transactions=transactions):
        _launch("activate", live, run)


def schedule_transition():
    _launch("activate", LIVE, subprocess.run)


def control(action, confirm, *, live=LIVE, transactions=TRANSACTIONS, run=subprocess.run):
    if action not in ("enable", "disable") or confirm != "yes":
        raise ProvisionError("invalid_request")
    if (transactions / "pending").exists():
        raise ProvisionError("core_update_busy")
    _launch(action, live, run)
    return {"queued": True}


def _ensure_dependency():
    if importlib.util.find_spec("websockets") is None:
        system = parse_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
        run_apt_transaction(system, ("python3-websockets",))


def _set_socket(action, run):
    run((SYSTEMCTL, action, WEB_SOCKET_UNIT), timeout=20, check=True, stdin=subprocess.DEVNULL)


def activate(*, live=LIVE, transactions=TRANSACTIONS, run=subprocess.run):
    deadline = time.monotonic() + 300
    while (transactions / "pending").exists():
        if time.monotonic() >= deadline:
            return
        time.sleep(1)
    # При откате остаётся прежняя версия. Для чистой установки нет предыдущей.
    if installed_version(live) != "5.0.9" or installed_version(transactions / "previous/tree") != "5.0.8":
        return
    _ensure_dependency()
    if installed_version(live) == "5.0.9" and not (transactions / "pending").exists():
        _set_socket("start", run)


def manual(action):
    from v5.core import audit
    from v5.core.maintenance.__main__ import locked
    from v5.core.maintenance.portal_apply import install_location

    ok = False
    try:
        with locked(install_location()):
            if action == "enable":
                _ensure_dependency()
            _set_socket("start" if action == "enable" else "stop", subprocess.run)
        ok = True
    finally:
        audit.record("maintenance.shell", ok)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 1:
            schedule()
        elif sys.argv[1:] == ["activate"]:
            activate()
        elif sys.argv[1:] in (["enable"], ["disable"]):
            manual(sys.argv[1])
        else:
            raise SystemExit(2)
    except (OSError, ValueError, ProvisionError, subprocess.SubprocessError):
        print("Shell не включён. Повторите вручную по инструкции в портале.", file=sys.stderr)
        raise SystemExit(1) from None
