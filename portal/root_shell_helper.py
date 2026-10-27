#!/usr/bin/env python3
"""Однопоточный запуск фиксированного PTY shell/PAM; не RPC и не exec API."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pwd
import re


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("shell", "auth-systemd", "auth-su"))
    parser.add_argument("--tty-fd", required=True, type=int)
    parser.add_argument("--directory", default="/root")
    parser.add_argument("--unit", default="")
    args = parser.parse_args()
    if os.geteuid() != 0 or args.tty_fd < 3 or not os.isatty(args.tty_fd):
        raise SystemExit(126)
    if args.unit and not re.fullmatch(r"kvn-portal-root-shell-[0-9a-f]{12}", args.unit):
        raise SystemExit(126)
    # login_tty делает setsid/controlling TTY/dup2 без Python fork в threaded agent.
    os.login_tty(args.tty_fd)
    env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm-256color"}
    su = "/usr/bin/su" if Path("/usr/bin/su").is_file() else "/bin/su"
    if args.mode == "auth-systemd":
        argv = ["/usr/bin/systemd-run", "--quiet", "--collect", "--wait", "--pty",
                "--uid=nobody", su, "root", "-c", "/bin/true"]
    elif args.mode == "auth-su":
        nobody = pwd.getpwnam("nobody")
        os.setgroups([])
        os.setgid(nobody.pw_gid)
        os.setuid(nobody.pw_uid)
        argv = [su, "-", "root", "-c", "/bin/true"]
    else:
        directory = Path(args.directory).resolve(strict=True)
        os.chdir(directory)
        shell = "/bin/bash" if Path("/bin/bash").is_file() else "/bin/sh"
        env.update(HOME="/root", USER="root", LOGNAME="root", SHELL=shell,
                   KVN_PORTAL_SHELL="1")
        argv = [shell, "-l"] if shell.endswith("bash") else [shell]
        if args.unit:
            argv = ["/usr/bin/systemd-run", "--quiet", "--collect", "--wait", "--pty",
                    f"--unit={args.unit}", f"--property=WorkingDirectory={directory}",
                    "--setenv=TERM=xterm-256color", "--setenv=LANG=C.UTF-8",
                    "--setenv=LC_ALL=C.UTF-8", "--setenv=KVN_PORTAL_SHELL=1", *argv]
    os.execve(argv[0], argv, env)


if __name__ == "__main__":
    main()
