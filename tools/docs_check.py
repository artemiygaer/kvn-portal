#!/usr/bin/env python3
"""Проверяет согласованность публичной документации без чтения runtime."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
DOCS = (
    Path("README.md"),
    Path("ARCHITECTURE.md"),
    Path("DEPLOY.md"),
    Path("PORTAL_UPDATE_NOTES.md"),
    Path("PROJECT_AUDIT.md"),
    Path("CONTAINER_SECURITY.md"),
    Path("HANDOFF_PROMPT.md"),
    Path("AGENTS.md"),
    Path("MTPROTO.md"),
    *tuple(sorted(path.relative_to(ROOT) for path in (ROOT / "v5").rglob("*.md"))),
)
REQUIRED = {
    "README.md": (
        "KVN Portal",
        "artemiygaer/kvn-portal",
        "Debian 12/13",
        "/root/portal",
        "v5/install/README.md",
        "v5/ARCHITECTURE.md",
    ),
    "DEPLOY.md": (
        "v5/DEPLOY.md",
        "v5/install/README.md",
        ".kvn",
    ),
    "HANDOFF_PROMPT.md": (
        "v5/ARCHITECTURE.md",
        "v5/install/README.md",
        "WSL",
    ),
    "ARCHITECTURE.md": (
        "v5/ARCHITECTURE.md",
        "v5/AGENTS.md",
    ),
}
FORBIDDEN_PATTERNS = {
    "production IPv4": re.compile(r"\b46\.29\.239\.64\b"),
    "production domain": re.compile(r"(?:^|[.\s`/])gaer\.loc\.cc\b", re.IGNORECASE),
    "GitHub token": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}"),
    "private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "local Windows path": re.compile(r"(?:[A-Za-z]:\\(?:Users|bot)\\|H:\\)", re.IGNORECASE),
    "local WSL path": re.compile(r"/mnt/[a-z]/", re.IGNORECASE),
    "local user home": re.compile(r"/home/[A-Za-z0-9._-]+/"),
}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def check_links(relative: Path, text: str, errors: list[str]) -> int:
    checked = 0
    for raw_target in LINK_RE.findall(text):
        target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
        if not target or target.startswith(("#", "http://", "https://", "mailto:")):
            continue
        target = unquote(target).split("#", 1)[0]
        if not target:
            continue
        checked += 1
        destination = (ROOT / relative.parent / target).resolve()
        try:
            destination.relative_to(ROOT.resolve())
        except ValueError:
            errors.append(f"{relative}: ссылка выходит за корень: {raw_target}")
            continue
        if not destination.exists():
            errors.append(f"{relative}: не найдена ссылка: {target}")
    return checked


def main() -> int:
    errors: list[str] = []
    link_count = 0
    texts: dict[str, str] = {}
    for relative in DOCS:
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"не найден документ: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        texts[relative.as_posix()] = text
        link_count += check_links(relative, text, errors)
        for label, pattern in FORBIDDEN_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{relative}: найдено запрещённое значение ({label})")

    for relative, fragments in REQUIRED.items():
        text = texts.get(relative, "")
        for fragment in fragments:
            if fragment not in text:
                errors.append(f"{relative}: отсутствует обязательный фрагмент: {fragment}")

    deploy = texts.get("v5/DEPLOY.md", "")
    for fragment in ("/root/portal", "8443", ".kvn", "GitHub"):
        if fragment not in deploy:
            errors.append(f"v5/DEPLOY.md: отсутствует обязательный фрагмент: {fragment}")

    if errors:
        for error in errors:
            print(f"[ОШИБКА] {error}", file=sys.stderr)
        print(f"[ИТОГ] Документация: ошибок {len(errors)}", file=sys.stderr)
        return 1
    print(
        f"[OK] Документация v5: {len(DOCS)} файлов, {link_count} локальных ссылок"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
