"""Единая проверка update-артефактов для CLI, GitHub и портала."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any, Literal

from tools.release.deploy_archive import inspect_archive
from tools.release.full_archive import sha256_file, validate_release


ArtifactKind = Literal["deploy", "release"]


def artifact_kind(name: str) -> ArtifactKind:
    if name.startswith("kvn-vpn-release-linux-amd64") and name.endswith(".tar.gz"):
        return "release"
    if name.startswith("kvn-vpn-deploy") and name.endswith(".tar.gz"):
        return "deploy"
    raise ValueError("неизвестное имя deploy/release архива")


def inspect_update_artifact(path: Path, kind: ArtifactKind | None = None) -> dict[str, Any]:
    """Проверяет артефакт одним контрактом без изменения проекта."""
    resolved_kind = kind or artifact_kind(path.name)
    if resolved_kind not in {"deploy", "release"}:
        raise ValueError("неизвестный тип release-артефакта")
    if resolved_kind == "release":
        manifest = validate_release(path)
        required_free = (
            int(manifest["source"]["size"])
            + int(manifest["images"]["size"])
            + 256 * 1024 * 1024
        )
        return {
            "archive_kind": resolved_kind,
            "metadata": {
                "name": path.name,
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "member_count": 3,
            },
            "manifest": manifest,
            "required_free_bytes": required_free,
            "has_required_space": shutil.disk_usage(path.parent).free >= required_free,
        }
    metadata = inspect_archive(path)
    return {
        "archive_kind": resolved_kind,
        "metadata": metadata,
        "manifest": None,
        "required_free_bytes": 0,
        "has_required_space": True,
    }
