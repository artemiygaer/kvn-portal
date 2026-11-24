"""Фоновая проверка GitHub без скачивания или установки пакетов."""

import json
from pathlib import Path
import re
import subprocess
import sys
import time

from v5.core.packages.manifest import PackageError
from v5.core.private_files import read_private, write_private
from v5.core.release import LIVE, installed_version, stable_version

from .core_github import GitHubCore
from .portal_store import UpdateStoreError

STATE = Path("/var/lib/kvn-v5/provision/core-release.json")
UNIT = "kvn-v5-core-release-check"
TAG = re.compile(r"v5\.[0-9]{1,6}\.[0-9]{1,6}\Z", re.ASCII)
INTERVAL = 6 * 3600


def snapshot(current, path=STATE, *, clock=time.time):
    try:
        state = json.loads(read_private(path, 512))
        tag, checked = state.get("tag"), state["checked"]
        if type(checked) is not int or not 0 <= clock() - checked <= INTERVAL * 2:
            return {"status": "unknown"}
        if tag is None:
            return {"status": "unavailable"}
        if not isinstance(tag, str) or not TAG.fullmatch(tag) or current is None:
            return {"status": "unknown"}
        newer = stable_version(tag[1:]) > stable_version(current)
        return {"status": "available" if newer else "current", "tag": tag, "checked": checked}
    except (OSError, ValueError, AttributeError, KeyError):
        return {"status": "unknown"}


def refresh(path=STATE, *, source=None, clock=time.time):
    source = source if source is not None else GitHubCore()
    try:
        tag = source.latest()
        if not TAG.fullmatch(tag):
            raise ValueError("invalid_release")
    except (OSError, PackageError, UpdateStoreError, ValueError):
        tag = None
    write_private(path, json.dumps({"tag": tag, "checked": int(clock())}).encode("ascii"))


def schedule(*, run=subprocess.run):
    args = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "timeout": 5}
    if run(("/usr/bin/systemctl", "is-active", "--quiet", f"{UNIT}.timer"), **args).returncode == 0:
        return
    run(("/usr/bin/systemd-run", "--quiet", "--no-block", "--collect", f"--unit={UNIT}",
         "--on-active=45s", "--on-unit-active=6h", "--timer-property=PartOf=kvn-v5-agent.service",
         f"--working-directory={LIVE}", "-p", "StateDirectory=kvn-v5/provision", "-p", "StateDirectoryMode=0700",
         "-p", "UMask=0077", "-p", "ProtectSystem=strict", "-p", "ProtectHome=yes",
         "-p", "NoNewPrivileges=yes", "-p", "CapabilityBoundingSet=", "-p", "RuntimeMaxSec=60s",
         "/usr/bin/python3", "-B", "-m", "v5.core.maintenance.release_poll", "refresh"), check=True, **args)


if __name__ == "__main__":
    if sys.argv[1:] == ["schedule"]:
        schedule()
    elif sys.argv[1:] == ["refresh"]:
        refresh()
    else:
        raise SystemExit(2)
