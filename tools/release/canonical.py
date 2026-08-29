#!/usr/bin/env python3
"""Готовит временное дерево deploy из canonical source и безопасных шаблонов."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


MANIFEST_NAME = ".kvn-canonical-files"
BUILD_INFO = "portal/build_info.py"
TEMPLATE_ROOT = "packaging/deploy-template"
DOCKERFILE_BUILD_ID = re.compile(rb"KVN_BUILD_ID=[A-Za-z0-9._-]+")
DOCKERFILE_VERSION = re.compile(rb"KVN_VERSION=v[0-9]+\.[0-9]+\.[0-9]+")


def _relative(value: str) -> Path:
    path = Path(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise SystemExit(f"[ОШИБКА] Небезопасный путь deploy: {value}")
    return path


def _canonical(root: Path) -> list[str]:
    schema = root / "tools/canonical-files.txt"
    if not schema.is_file():
        raise SystemExit("[ОШИБКА] Не найден канонический список: tools/canonical-files.txt")
    values = schema.read_text(encoding="utf-8").splitlines()
    if not values:
        raise SystemExit("[ОШИБКА] Канонический список пуст: tools/canonical-files.txt")
    for value in values:
        _relative(value)
    return values


def _copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def stage(
    root: Path,
    destination: Path,
    build_id: str,
    version: str,
    deploy_only: list[str],
) -> None:
    canonical = _canonical(root)
    template_root = root / TEMPLATE_ROOT
    allowed_templates = {
        value for value in deploy_only if value != "DEPLOY.md"
    }
    actual_templates = {
        path.relative_to(template_root).as_posix()
        for path in template_root.rglob("*")
        if path.is_file()
    }
    unexpected = sorted(actual_templates - allowed_templates)
    missing_templates = sorted(allowed_templates - actual_templates)
    if unexpected:
        raise SystemExit(
            "[ОШИБКА] Неожиданный deploy-only шаблон: " + ", ".join(unexpected)
        )
    if missing_templates:
        raise SystemExit(
            "[ОШИБКА] Не найден deploy-only шаблон: " + ", ".join(missing_templates)
        )
    for value in canonical:
        source = root / _relative(value)
        if not source.is_file():
            raise SystemExit(f"[ОШИБКА] Не найден исходный файл: {value}")
        target = destination / value
        if value == "portal/Dockerfile":
            payload = DOCKERFILE_BUILD_ID.sub(
                f"KVN_BUILD_ID={build_id}".encode("ascii"),
                source.read_bytes(),
            )
            payload = DOCKERFILE_VERSION.sub(
                f"KVN_VERSION={version}".encode("ascii"), payload,
            )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            shutil.copymode(source, target)
        else:
            _copy(source, target)

    for value in deploy_only:
        relative = _relative(value)
        source = root / "DEPLOY.md" if value == "DEPLOY.md" else root / TEMPLATE_ROOT / relative
        if not source.is_file():
            raise SystemExit(f"[ОШИБКА] Не найден deploy-only шаблон: {source.relative_to(root)}")
        _copy(source, destination / relative)

    build_info = destination / BUILD_INFO
    build_info.parent.mkdir(parents=True, exist_ok=True)
    build_info.write_text(
        f'BUILD_ID = "{build_id}"\nVERSION = "{version}"\n',
        encoding="utf-8",
    )
    (destination / MANIFEST_NAME).write_text(
        "".join(f"{value}\n" for value in canonical),
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("build_id")
    parser.add_argument("version")
    parser.add_argument("deploy_only", nargs="*")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    stage(
        root,
        args.destination.resolve(),
        args.build_id,
        args.version,
        args.deploy_only,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
