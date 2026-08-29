"""Безопасные контракты перехода со старого deploy на актуальный release."""

from __future__ import annotations

import argparse
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LEGACY_BOOTSTRAP_FILES = (
    "update.sh",
    "tools/deploy_archive.py",
    "tools/canonical-files.txt",
)
SUPPORTED_ARTIFACTS = ("source", "full")
SUPPORTED_ENTRYPOINTS = ("cli", "portal")


class MigrationError(ValueError):
    """Переход отклонён до изменения установленного проекта."""


@dataclass(frozen=True)
class MigrationPlan:
    """Неизменяемый план поддерживаемого обновления."""

    source_version: str
    artifact_kind: str
    entrypoint: str
    bootstrap_required: bool
    external_bridge_required: bool


def plan_migration(source_version: str, artifact_kind: str, entrypoint: str) -> MigrationPlan:
    """Проверяет и возвращает поддерживаемый путь v3→v4."""
    if not source_version.startswith("v3."):
        raise MigrationError("поддерживается bootstrap только с v3")
    if artifact_kind not in SUPPORTED_ARTIFACTS:
        raise MigrationError("неизвестный тип release-артефакта")
    if entrypoint not in SUPPORTED_ENTRYPOINTS:
        raise MigrationError("неизвестная точка запуска обновления")
    # Портал v3 проверяет новый canonical manifest старым validator до запуска
    # updater. Поэтому первый переход из browser требует одноразовый SSH-мост.
    return MigrationPlan(
        source_version,
        artifact_kind,
        entrypoint,
        bootstrap_required=True,
        external_bridge_required=entrypoint == "portal",
    )


def _safe_bootstrap_member(name: str) -> str:
    prefix = "deploy/"
    if not name.startswith(prefix) or "\\" in name or "\x00" in name:
        raise MigrationError("небезопасный bootstrap-путь")
    relative = name.removeprefix(prefix)
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise MigrationError("небезопасный bootstrap-путь")
    return relative


def extract_legacy_bootstrap(archive_path: Path, target: Path) -> tuple[Path, ...]:
    """Извлекает только три файла, понятные updater v3, без extractall."""
    required = {f"deploy/{name}": name for name in LEGACY_BOOTSTRAP_FILES}
    extracted: list[Path] = []
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = {member.name: member for member in archive.getmembers()}
            missing = [name for archive_name, name in required.items() if archive_name not in members]
            if missing:
                raise MigrationError("в архиве не хватает bootstrap-файлов: " + ", ".join(missing))
            for archive_name, relative in required.items():
                _safe_bootstrap_member(archive_name)
                member = members[archive_name]
                if not member.isreg() or member.size < 1 or member.size > 2 * 1024 * 1024:
                    raise MigrationError(f"bootstrap-файл имеет неверный тип или размер: {relative}")
                source = archive.extractfile(member)
                if source is None:
                    raise MigrationError(f"bootstrap-файл не читается: {relative}")
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                extracted.append(destination)
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise MigrationError(f"не удалось извлечь bootstrap: {exc}") from exc
    return tuple(extracted)


def main() -> int:
    parser = argparse.ArgumentParser(description="Миграции release KVN")
    subparsers = parser.add_subparsers(dest="command", required=True)
    extract = subparsers.add_parser("extract-bootstrap")
    extract.add_argument("archive", type=Path)
    extract.add_argument("target", type=Path)
    args = parser.parse_args()
    try:
        extract_legacy_bootstrap(args.archive, args.target)
    except MigrationError as exc:
        parser.exit(1, f"[ОШИБКА] {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
