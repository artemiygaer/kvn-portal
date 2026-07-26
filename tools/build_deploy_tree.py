#!/usr/bin/env python3
"""Быстро готовит и синхронизирует дерево deploy без runtime-данных."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


MANIFEST_NAME = ".kvn-canonical-files"
BUILD_INFO = "portal/build_info.py"
DOCKERFILE_BUILD_ID = re.compile(rb"KVN_BUILD_ID=[A-Za-z0-9._-]+")


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


def stage(root: Path, destination: Path, build_id: str, deploy_only: list[str]) -> None:
    canonical = _canonical(root)
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
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            shutil.copymode(source, target)
        else:
            _copy(source, target)

    for value in deploy_only:
        relative = _relative(value)
        source = root / "deploy" / relative
        if not source.is_file():
            raise SystemExit(f"[ОШИБКА] Не найден deploy-only файл: deploy/{value}")
        _copy(source, destination / relative)

    build_info = destination / BUILD_INFO
    build_info.parent.mkdir(parents=True, exist_ok=True)
    build_info.write_text(f'BUILD_ID = "{build_id}"\n', encoding="utf-8")
    (destination / MANIFEST_NAME).write_text(
        "".join(f"{value}\n" for value in canonical),
        encoding="utf-8",
    )


def sync(root: Path, source: Path) -> None:
    canonical = _canonical(root)
    deploy = root / "deploy"
    previous_manifest = deploy / MANIFEST_NAME
    if previous_manifest.is_file():
        for value in previous_manifest.read_text(encoding="utf-8").splitlines():
            target = deploy / _relative(value)
            if target.is_file() or target.is_symlink():
                target.unlink()
            elif target.exists():
                raise SystemExit(
                    f"[ОШИБКА] Путь старого deploy manifest не является файлом: {value}"
                )

    for value in [*canonical, BUILD_INFO, MANIFEST_NAME]:
        _copy(source / _relative(value), deploy / value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    stage_parser = subparsers.add_parser("stage")
    stage_parser.add_argument("root", type=Path)
    stage_parser.add_argument("destination", type=Path)
    stage_parser.add_argument("build_id")
    stage_parser.add_argument("deploy_only", nargs="*")

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("root", type=Path)
    sync_parser.add_argument("source", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if args.command == "stage":
        stage(root, args.destination.resolve(), args.build_id, args.deploy_only)
    else:
        sync(root, args.source.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
