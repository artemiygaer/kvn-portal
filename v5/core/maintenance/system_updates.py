"""Отдельные фиксированные операции APT: проверка, установка, перезагрузка."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from v5.core import audit
from v5.core.packages.debian_provision import apt_base, apt_stage, parse_os_release, provision_lock
from v5.core.private_files import read_private, write_private

from .portal_store import UpdateStoreError

UNIT = "kvn-v5-system-update.service"
STATE = Path("/var/lib/kvn-v5/provision/system-update.json")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
REBOOT_REQUIRED = Path("/run/reboot-required")
PLAN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_INST = re.compile(r"Inst ([a-z0-9][a-z0-9+.:\-]{0,119})(?: \[[^\]\r\n]*\])? \(([a-zA-Z0-9+.~:\-]{1,80})(?:\s|\))",
                   re.ASCII)
LIFETIME = 3600
_RUNNING = frozenset({"checking", "installing", "rebooting"})


def parse_plan(output: str) -> tuple[tuple[str, str], ...]:
    packages = {}
    for line in output.splitlines():
        if line.startswith("Remv "):
            raise UpdateStoreError("system_removal_refused")
        if line.startswith("Inst "):
            match = _INST.match(line)
            if not match or match[1] in packages or len(packages) >= 5000:
                raise UpdateStoreError("system_plan_invalid")
            packages[match[1]] = match[2]
    if re.search(r"^Conf ", output, flags=re.M) and not packages:
        raise UpdateStoreError("system_dpkg_incomplete")
    return tuple(sorted(packages.items()))


def plan_digest(packages):
    return hashlib.sha256(json.dumps(packages, separators=(",", ":")).encode("ascii")).hexdigest()


def boot_id():
    return BOOT_ID.read_text(encoding="ascii").strip()


def read_state(path=STATE):
    try:
        return json.loads(read_private(path, 16384))
    except FileNotFoundError:
        return {"phase": "unchecked"}


def publish(path, row):
    write_private(path, json.dumps(row, separators=(",", ":")).encode("ascii"))


def active(*, run=subprocess.run):
    return run(("/usr/bin/systemctl", "is-active", "--quiet", UNIT), timeout=3, check=False,
               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def status(path=STATE, *, clock=time.time, is_active=active):
    saved = read_state(path)
    reboot = saved.get("reboot_boot") == boot_id() or REBOOT_REQUIRED.is_file()
    if saved.get("phase") in _RUNNING and not is_active():
        if saved["phase"] == "rebooting" and saved.get("job_boot") != boot_id():
            saved = {**saved, "phase": "done"}
        elif clock() - saved.get("updated", 0) >= 15:
            saved = {**saved, "phase": "failed"}
    stale = saved.get("checked", 0) + LIFETIME <= clock()
    return {**saved, "stale": stale, "needs_reboot": reboot}


def launch(action, params, *, run=subprocess.run):
    extra = ()
    if action == "install" and params.get("confirm") == "yes":
        approval = params.get("plan")
        if not isinstance(approval, str) or not PLAN.fullmatch(approval):
            raise UpdateStoreError("system_plan_invalid")
        current = status()
        if current.get("phase") != "ready" or current["stale"] or current.get("plan") != approval:
            raise UpdateStoreError("system_plan_changed")
        extra = (approval,)
    elif action == "reboot" and params.get("confirm") == "yes":
        if not status()["needs_reboot"]:
            raise UpdateStoreError("system_reboot_not_required")
    elif action != "check" or params:
        raise UpdateStoreError("invalid_request")
    if active():
        raise UpdateStoreError("system_busy")
    cmd = ("/usr/bin/systemd-run", "--quiet", "--no-block", "--collect", f"--unit={UNIT}",
           "--working-directory=/usr/local/lib/kvn-v5", "-p", "StateDirectory=kvn-v5/provision",
           "-p", "StateDirectoryMode=0700", "-p", "UMask=0077", "-p", "RuntimeMaxSec=3600s",
           "-p", "Nice=5", "/usr/bin/python3", "-B", "-m", "v5.core.maintenance.system_updates", action, *extra)
    run(cmd, check=True, timeout=8, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return {"queued": True}


def _apt(argv, stage, *, capture=False, timeout=300):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "APT_CONFIG": str(stage / "apt.conf"),
           "DEBIAN_FRONTEND": "noninteractive", "APT_LISTCHANGES_FRONTEND": "none", "NEEDRESTART_MODE": "l"}
    result = subprocess.run(argv, timeout=timeout, check=True, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.stdout.decode("ascii", errors="replace") if capture else ""


def perform(action, approval="", *, path=STATE, apt=_apt, clock=time.time):
    row = read_state(path)
    now = int(clock())
    this_boot = boot_id()
    if action == "reboot":
        if row.get("reboot_boot") != this_boot and not REBOOT_REQUIRED.is_file():
            raise UpdateStoreError("system_reboot_not_required")
        audit_result = subprocess.run(("/usr/bin/dpkg", "--audit"), check=True, timeout=30,
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if audit_result.stdout.strip():
            raise UpdateStoreError("system_dpkg_incomplete")
        publish(path, {**row, "phase": "rebooting", "job_boot": this_boot, "updated": now})
        subprocess.run(("/usr/bin/systemctl", "reboot", "--no-block"), check=True, timeout=30,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    if action == "install" and (row.get("phase") != "ready" or row.get("plan") != approval
                               or row.get("checked", 0) + LIFETIME <= now):
        raise UpdateStoreError("system_plan_changed")
    publish(path, {**row, "phase": "checking" if action == "check" else "installing", "updated": now})
    system = parse_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
    with apt_stage(system) as stage:
        apt_cmd = apt_base(stage)
        operation = ("--with-new-pkgs", "--no-remove", "upgrade")
        apt(apt_cmd + ("update", "--error-on=any"), stage)
        packages = parse_plan(apt(apt_cmd + ("-s", *operation), stage, capture=True))
        digest = plan_digest(packages)
        fresh = {"phase": "ready", "plan": digest, "checked": int(clock()), "updated": int(clock()),
                 "total": len(packages), "packages": packages[:20], "reboot_boot": row.get("reboot_boot")}
        if action == "check":
            publish(path, fresh)
            return
        if digest != approval:
            publish(path, {**fresh, "phase": "plan_changed"})
            return
        if packages:
            apt(apt_cmd + ("-y", "-o", "DPkg::Options::=--force-confdef", "-o", "DPkg::Options::=--force-confold",
                           *operation), stage, timeout=3300)
        new_kernel = any(name.startswith("linux-image-") for name, _ in packages)
        publish(path, {**fresh, "phase": "done", "total": 0, "packages": [],
                       "reboot_boot": this_boot if new_kernel else fresh["reboot_boot"]})


def main():
    from .__main__ import locked
    from .portal_apply import install_location

    args = sys.argv[1:]
    if os.geteuid() != 0 or not (args in (["check"], ["reboot"]) or
                               len(args) == 2 and args[0] == "install" and PLAN.fullmatch(args[1])):
        return 2
    ok = False
    try:
        with locked(install_location()), provision_lock():
            try:
                perform(*args)
            except (OSError, ValueError, subprocess.SubprocessError, UpdateStoreError) as exc:
                code = str(exc) if isinstance(exc, UpdateStoreError) else "system_failed"
                publish(STATE, {**read_state(), "phase": "failed", "code": code, "updated": int(time.time())})
                return 1
        ok = True
        return 0
    finally:
        audit.record("maintenance.system", ok)


if __name__ == "__main__":
    raise SystemExit(main())
