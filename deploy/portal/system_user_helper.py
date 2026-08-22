#!/usr/bin/env python3
"""Узкий root-helper создания обычного Linux-пользователя для портала."""

from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys


USERNAME_RE = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
PRIVILEGED_GROUPS = {"sudo", "adm", "wheel"}
USERADD = "/usr/sbin/useradd"
USERDEL = "/usr/sbin/userdel"
CHPASSWD = "/usr/sbin/chpasswd"
ID = "/usr/bin/id"


class CreateError(RuntimeError):
    pass


def _run(argv: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=20,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def create_user(username: str, password: str) -> dict[str, object]:
    if os.geteuid() != 0:
        raise CreateError("helper requires root")
    if USERNAME_RE.fullmatch(username) is None:
        raise CreateError("invalid username")
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise CreateError("account exists")
    if not 12 <= len(password) <= 128 or any(char in password for char in ("\n", "\r", "\x00", ":")):
        raise CreateError("invalid password")

    created = False
    try:
        add = _run([USERADD, "--create-home", "--shell", "/bin/bash", "--no-log-init", username])
        if add.returncode != 0:
            raise CreateError("useradd failed")
        created = True
        changed = _run([CHPASSWD], input_text=f"{username}:{password}\n")
        if changed.returncode != 0:
            raise CreateError("chpasswd failed")
        account = pwd.getpwnam(username)
        id_result = _run([ID, "-nG", username])
        if id_result.returncode != 0:
            raise CreateError("group verification failed")
        groups = set(id_result.stdout.split())
        if account.pw_dir != f"/home/{username}" or account.pw_shell != "/bin/bash":
            raise CreateError("account attributes mismatch")
        if groups & PRIVILEGED_GROUPS:
            raise CreateError("privileged group detected")
        return {
            "ok": True,
            "user": username,
            "home": account.pw_dir,
            "shell": account.pw_shell,
            "privileged": False,
        }
    except (CreateError, OSError, subprocess.TimeoutExpired):
        if created:
            _run([USERDEL, "--remove", username])
        raise CreateError("account creation failed") from None


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] != "create":
        sys.stderr.write("Некорректный вызов helper.\n")
        return 2
    password = sys.stdin.readline().removesuffix("\n")
    if sys.stdin.read(1):
        sys.stderr.write("Некорректный ввод.\n")
        return 2
    try:
        result = create_user(sys.argv[2], password)
    except CreateError:
        sys.stderr.write("Не удалось создать пользователя.\n")
        return 1
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
