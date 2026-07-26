#!/usr/bin/env python3
"""Проверяет tracked/staged source tree на runtime и секретные артефакты."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
ALLOWED_RUNTIME_TEMPLATES = {
    "deploy/users.json",
    "deploy/nginx/site/index.html",
    "deploy/portal-data/.gitkeep",
    "deploy/portal-runtime/.gitkeep",
}
DENIED_PARTS = {
    ".supergoal",
    ".agents",
    ".playwright-cli",
    ".playwright-mcp",
    ".docker-tmp",
    "clients",
    "certs",
    "site-certs",
    "portal-data",
    "portal-runtime",
    "output",
    ".update-backups",
    ".deploy-runtime-e2e",
}
DENIED_NAMES = {
    ".env",
    "CLIENT_LINKS.md",
    "portal.db",
    "portal.db-wal",
    "portal.db-shm",
    "metrics.db",
    "metrics.db-wal",
    "metrics.db-shm",
    "nginx.conf",
    "portal-gateway.conf",
    "awg0.conf",
    "wg0.conf",
    "ocserv.conf",
    "ocserv.env",
    "users.txt",
}
DENIED_SUFFIXES = (".log", ".sock", ".key", ".pem", ".p12", ".pfx")
DENIED_ARCHIVES = re.compile(
    r"^(?:kvn-vpn-(?:deploy|release-linux-amd64|backup)[^/]*\.(?:tar|tar\.gz)|"
    r"kvn-vpn-images-linux-amd64\.tar)$"
)
SECRET_PATTERNS = {
    "private key": re.compile(
        rb"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/]"
    ),
    "GitHub token": re.compile(
        rb"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})"
    ),
}
BINARY_SUFFIXES = {".whl", ".png", ".ico", ".tar", ".gz"}


def git_paths(mode: str) -> list[str]:
    git_command = "git"
    bundled_git = (
        Path.home()
        / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/cmd/git.exe"
    )
    if os.name == "nt" and bundled_git.is_file():
        git_command = str(bundled_git)
    command = [git_command, "ls-files", "-z"]
    if mode == "staged":
        command = [
            git_command,
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ]
    elif mode == "worktree":
        command = [
            git_command,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ]
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(ROOT),
        }
    )
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    return sorted(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)


def denied_path(relative: str) -> str:
    if relative in ALLOWED_RUNTIME_TEMPLATES:
        return ""
    path = PurePosixPath(relative)
    if any(part in DENIED_PARTS for part in path.parts):
        return "runtime-каталог"
    if path.name == "users.json":
        return "production users.json"
    if path.name in DENIED_NAMES:
        return "runtime/generated файл"
    if path.name.endswith(DENIED_SUFFIXES):
        return "секретный/runtime suffix"
    if DENIED_ARCHIVES.fullmatch(path.name):
        return "сборочный/backup архив"
    return ""


def validate(paths: list[str]) -> tuple[list[str], int]:
    errors: list[str] = []
    total_bytes = 0
    for relative in paths:
        reason = denied_path(relative)
        if reason:
            errors.append(f"{relative}: {reason}")
            continue
        path = ROOT / relative
        if path.is_symlink():
            errors.append(f"{relative}: symlink запрещён")
            continue
        if not path.is_file():
            errors.append(f"{relative}: tracked path не является обычным файлом")
            continue
        payload = path.read_bytes()
        total_bytes += len(payload)
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(payload):
                errors.append(f"{relative}: найден {label}")
    return errors, total_bytes


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка source tree без runtime/секретов")
    parser.add_argument(
        "--mode",
        choices=("tracked", "staged", "worktree"),
        default="tracked",
    )
    args = parser.parse_args()
    try:
        paths = git_paths(args.mode)
    except RuntimeError as exc:
        print(f"[ОШИБКА] Не удалось получить список git: {exc}", file=sys.stderr)
        return 1
    errors, total_bytes = validate(paths)
    if errors:
        for error in errors:
            print(f"[ОШИБКА] {error}", file=sys.stderr)
        print(f"[ИТОГ] source safety: файлов {len(paths)}, ошибок {len(errors)}", file=sys.stderr)
        return 1
    print(
        f"[OK] source safety: mode={args.mode}, files={len(paths)}, "
        f"bytes={total_bytes}, forbidden=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
