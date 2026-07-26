#!/usr/bin/env python3
"""Формирует проверяемый manifest двух публичных release-артефактов."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.deploy_archive import inspect_archive
from tools.release_archive import PLATFORM, sha256_file, validate_release


REPOSITORY = "artemiygaer/kvn-portal"
RELEASE_NAME = "kvn-vpn-release-linux-amd64.tar.gz"
DEPLOY_NAME = "kvn-vpn-deploy.tar.gz"
PUBLICATION_NAMES = (
    RELEASE_NAME,
    DEPLOY_NAME,
    "publication-manifest.json",
    "SHA256SUMS",
)


def build_publication_manifest(release: Path, deploy: Path) -> dict:
    if release.name != RELEASE_NAME or deploy.name != DEPLOY_NAME:
        raise ValueError("неверные имена публичных артефактов")
    release_manifest = validate_release(release)
    deploy_metadata = inspect_archive(deploy)
    deploy_sha256 = sha256_file(deploy)
    source = release_manifest["source"]
    if source["sha256"] != deploy_sha256 or source["size"] != deploy.stat().st_size:
        raise ValueError("внешний deploy не совпадает с source deploy внутри full release")
    return {
        "format": 1,
        "repository": REPOSITORY,
        "build_id": release_manifest["build_id"],
        "platform": PLATFORM,
        "assets": [
            {
                "name": RELEASE_NAME,
                "sha256": sha256_file(release),
                "size": release.stat().st_size,
            },
            {
                "name": DEPLOY_NAME,
                "sha256": deploy_sha256,
                "size": deploy.stat().st_size,
                "member_count": deploy_metadata["member_count"],
            },
        ],
        "publication_files": list(PUBLICATION_NAMES),
    }


def atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(payload, encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manifest публичного KVN release")
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--deploy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = build_publication_manifest(args.release, args.deploy)
        atomic_write(
            args.output,
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )
    except (OSError, ValueError) as exc:
        print(f"[ОШИБКА] Publication manifest: {exc}")
        return 1
    print(
        f"[OK] Publication manifest: build={manifest['build_id']}, "
        f"assets={len(manifest['assets'])}, files={len(manifest['publication_files'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
