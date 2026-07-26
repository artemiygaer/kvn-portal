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
    Path("deploy/DEPLOY.md"),
    Path("PORTAL_UPDATE_NOTES.md"),
    Path("PROJECT_AUDIT.md"),
    Path("CONTAINER_SECURITY.md"),
    Path("HANDOFF_PROMPT.md"),
    Path("AGENTS.md"),
    Path("MTPROTO.md"),
)
SHIPPING_DOCS = (
    "README.md",
    "PROJECT_AUDIT.md",
    "CONTAINER_SECURITY.md",
    "HANDOFF_PROMPT.md",
    "PORTAL_UPDATE_NOTES.md",
    "MTPROTO.md",
    "AGENTS.md",
    "tools/docs_check.py",
)
SERVICES = {
    "nginx",
    "portal",
    "portal-gateway",
    "xray",
    "hysteria",
    "telemt",
    "mtg",
    "ocserv",
}
PORTS = (
    "80/tcp",
    "443/tcp",
    "443/udp",
    "4443/udp",
    "51820/udp",
    "51821/udp",
    "2096/tcp",
    "2443-2448/tcp",
)
REQUIRED = {
    "README.md": (
        "ZIP для Telegram",
        "artemiygaer/kvn-portal",
        "updates configure",
        "public-ip",
        "IP SAN",
        "tools/docs_check.py",
    ),
    "deploy/DEPLOY.md": (
        "Обновление через портал",
        "Ручное обновление через update.sh",
        "Обновление из GitHub Releases",
        "--bootstrap-only",
        "ZIP для Telegram",
        "root-only",
    ),
    "HANDOFF_PROMPT.md": (
        "Статус",
        "Архитектура",
        "Release и публикация",
        "Полный gate",
        "тестов проекта прошли",
        "no-build --pull never",
    ),
}
FORBIDDEN_PATTERNS = {
    "production IPv4": re.compile(r"\b46\.29\.239\.64\b"),
    "production domain": re.compile(r"(?:^|[.\s`/])gaer\.loc\.cc\b", re.IGNORECASE),
    "GitHub token": re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{8,}"),
    "private key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
}
LINK_RE = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


def compose_services() -> set[str]:
    """Извлекает только ключи первого уровня секции services."""
    result: set[str] = set()
    inside = False
    for line in (ROOT / "docker-compose.yml").read_text(encoding="utf-8").splitlines():
        if line == "services:":
            inside = True
            continue
        if inside and line and not line.startswith((" ", "\t", "#")):
            break
        match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line) if inside else None
        if match:
            result.add(match.group(1))
    return result


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

    readme = texts.get("README.md", "")
    deploy = texts.get("deploy/DEPLOY.md", "")
    for port in PORTS:
        if port not in readme or port not in deploy:
            errors.append(f"порт {port} не синхронизирован в README.md и deploy/DEPLOY.md")

    actual_services = compose_services()
    if actual_services != SERVICES:
        errors.append(
            "docker-compose.yml: service set отличается: "
            f"ожидалось {sorted(SERVICES)}, получено {sorted(actual_services)}"
        )

    canonical_path = ROOT / "tools/canonical-files.txt"
    canonical = set(canonical_path.read_text(encoding="utf-8").splitlines())
    for relative in SHIPPING_DOCS:
        if relative not in canonical:
            errors.append(f"tools/canonical-files.txt: не поставляется {relative}")

    if errors:
        for error in errors:
            print(f"[ОШИБКА] {error}", file=sys.stderr)
        print(f"[ИТОГ] Документация: ошибок {len(errors)}", file=sys.stderr)
        return 1
    print(
        f"[OK] Документация: {len(DOCS)} файлов, {link_count} локальных ссылок, "
        f"{len(SERVICES)} Compose-сервисов, {len(PORTS)} портовых контрактов"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
