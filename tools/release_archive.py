#!/usr/bin/env python3
"""Создаёт и проверяет офлайн-релиз KVN для Linux/amd64."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from tools.deploy_archive import ArchiveValidationError, inspect_archive


PLATFORM = "linux/amd64"
SOURCE_NAME = "kvn-vpn-deploy.tar.gz"
IMAGES_NAME = "kvn-vpn-images-linux-amd64.tar"
MANIFEST_NAME = "release-manifest.json"
RELEASE_MEMBERS = (MANIFEST_NAME, SOURCE_NAME, IMAGES_NAME)
EXPECTED_IMAGE_REFS = (
    "kvn-portal:local",
    "nginx:1.31.1-alpine",
    "ghcr.io/telemt/telemt:3.4.24",
    "nineseconds/mtg:2.2.8",
    "tobyxdd/hysteria:v2.10.0",
    "kvn-ocserv:local",
    "ghcr.io/xtls/xray-core:26.3.27",
)
MAX_RELEASE_BYTES = 2 * 1024 * 1024 * 1024
MAX_IMAGES_BYTES = 1792 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
BUILD_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REPO_DIGEST_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")


class ReleaseValidationError(ValueError):
    """Релиз не соответствует безопасному офлайн-формату KVN."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: Path) -> dict[str, str | int]:
    return {"name": path.name, "sha256": sha256_file(path), "size": path.stat().st_size}


def build_manifest(build_id: str, source: Path, images: Path, metadata: list[dict]) -> dict:
    """Формирует детерминированный логический manifest из готовых артефактов."""
    if not BUILD_ID_RE.fullmatch(build_id):
        raise ReleaseValidationError("недопустимый build-id")
    by_ref = {item.get("ref"): item for item in metadata if isinstance(item, dict)}
    if set(by_ref) != set(EXPECTED_IMAGE_REFS):
        missing = sorted(set(EXPECTED_IMAGE_REFS) - set(by_ref))
        extra = sorted(set(by_ref) - set(EXPECTED_IMAGE_REFS))
        raise ReleaseValidationError(f"неверный список образов; missing={missing}, extra={extra}")
    records = []
    for ref in EXPECTED_IMAGE_REFS:
        item = by_ref[ref]
        image_id = item.get("id")
        platform = item.get("platform")
        if not isinstance(image_id, str) or not IMAGE_ID_RE.fullmatch(image_id):
            raise ReleaseValidationError(f"неверный ID образа: {ref}")
        if platform != PLATFORM:
            raise ReleaseValidationError(f"неверная платформа образа {ref}: {platform}")
        digests = item.get("repo_digests", [])
        if not isinstance(digests, list) or not all(isinstance(value, str) for value in digests):
            raise ReleaseValidationError(f"неверные repo digests образа: {ref}")
        if not ref.startswith("kvn-") and not any(REPO_DIGEST_RE.fullmatch(value) for value in digests):
            raise ReleaseValidationError(f"upstream-образ не имеет immutable digest: {ref}")
        records.append({
            "ref": ref,
            "id": image_id,
            "platform": platform,
            "repo_digests": sorted(set(digests)),
        })
    return {
        "format": 1,
        "platform": PLATFORM,
        "build_id": build_id,
        "source": _artifact(source),
        "images": {**_artifact(images), "items": records},
    }


def _tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def create_release(output: Path, build_id: str, source: Path, images: Path, metadata: list[dict]) -> dict:
    """Упаковывает source, Docker image archive и логический manifest без временных меток."""
    if source.name != SOURCE_NAME or images.name != IMAGES_NAME:
        raise ReleaseValidationError("имена внутренних артефактов не соответствуют формату release")
    manifest = build_manifest(build_id, source, images, metadata)
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                archive.addfile(_tar_info(MANIFEST_NAME, len(manifest_bytes)), fileobj=_BytesReader(manifest_bytes))
                for path in (source, images):
                    with path.open("rb") as handle:
                        archive.addfile(_tar_info(path.name, path.stat().st_size), fileobj=handle)
    temporary.replace(output)
    return manifest


class _BytesReader:
    def __init__(self, value: bytes):
        self.value = value
        self.offset = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.value) - self.offset
        result = self.value[self.offset:self.offset + size]
        self.offset += len(result)
        return result


def _safe_member_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ReleaseValidationError("небезопасный путь в release")
    return name


def _member_sha256(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    handle = archive.extractfile(member)
    if handle is None:
        raise ReleaseValidationError(f"не удалось прочитать {member.name}")
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _validate_image_archive(path: Path, expected_refs: list[str]) -> dict[str, str]:
    try:
        with tarfile.open(path, "r:") as archive:
            members = archive.getmembers()
            for member in members:
                _safe_member_name(member.name.rstrip("/"))
                if not (member.isdir() or member.isreg()):
                    raise ReleaseValidationError("Docker image archive содержит ссылку или специальный файл")
            manifest_member = archive.getmember("manifest.json")
            handle = archive.extractfile(manifest_member)
            if handle is None:
                raise ReleaseValidationError("Docker image archive не содержит читаемый manifest.json")
            docker_manifest = json.loads(handle.read().decode("utf-8"))
    except (OSError, tarfile.TarError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError("Docker image archive повреждён") from exc
    tags = sorted({tag for item in docker_manifest for tag in item.get("RepoTags") or []})
    if tags != sorted(expected_refs):
        raise ReleaseValidationError(f"Docker image archive содержит неверные tags: {tags}")
    loaded_ids: dict[str, str] = {}
    for item in docker_manifest:
        config_id = Path(str(item.get("Config", ""))).name.removesuffix(".json")
        image_id = f"sha256:{config_id}"
        if not IMAGE_ID_RE.fullmatch(image_id):
            raise ReleaseValidationError("Docker image archive содержит неверный Config ID")
        for tag in item.get("RepoTags") or []:
            loaded_ids[tag] = image_id
    return loaded_ids


def normalize_image_archive(path: Path) -> None:
    """Убирает переменные tar metadata из результата ``docker image save``."""
    temporary = path.with_suffix(path.suffix + ".normalized")
    try:
        with tarfile.open(path, "r:") as source, tarfile.open(
            temporary, "w:", format=tarfile.GNU_FORMAT,
        ) as target:
            for member in sorted(source.getmembers(), key=lambda item: item.name):
                if not (member.isdir() or member.isreg()):
                    raise ReleaseValidationError("Docker image archive содержит ссылку или специальный файл")
                normalized = tarfile.TarInfo(member.name)
                normalized.type = member.type
                normalized.mode = member.mode
                normalized.mtime = 0
                normalized.uid = normalized.gid = 0
                normalized.uname = normalized.gname = ""
                handle = source.extractfile(member) if member.isreg() else None
                if member.name == "manifest.json" and handle is not None:
                    docker_manifest = json.loads(handle.read().decode("utf-8"))
                    for item in docker_manifest:
                        if isinstance(item.get("RepoTags"), list):
                            item["RepoTags"] = sorted(item["RepoTags"])
                    docker_manifest.sort(key=lambda item: (item.get("RepoTags") or [item.get("Config", "")])[0])
                    payload = json.dumps(docker_manifest, sort_keys=True, separators=(",", ":")).encode()
                    normalized.size = len(payload)
                    handle = _BytesReader(payload)
                else:
                    normalized.size = member.size if member.isreg() else 0
                target.addfile(normalized, handle)
        temporary.replace(path)
    except ReleaseValidationError:
        temporary.unlink(missing_ok=True)
        raise
    except (OSError, tarfile.TarError) as exc:
        temporary.unlink(missing_ok=True)
        raise ReleaseValidationError("не удалось нормализовать Docker image archive") from exc


def validate_release(path: Path) -> dict:
    """Проверяет структуру, hashes, платформу, source deploy и Docker archive."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ReleaseValidationError("release не найден") from exc
    if not 1024 <= size <= MAX_RELEASE_BYTES:
        raise ReleaseValidationError("размер release вне допустимого диапазона")
    try:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            names = [_safe_member_name(member.name) for member in members]
            if names != list(RELEASE_MEMBERS) or len(set(names)) != len(names):
                raise ReleaseValidationError(f"неверный состав release: {names}")
            if any(not member.isreg() for member in members):
                raise ReleaseValidationError("release может содержать только обычные файлы")
            by_name = dict(zip(names, members, strict=True))
            if by_name[SOURCE_NAME].size > MAX_SOURCE_BYTES or by_name[IMAGES_NAME].size > MAX_IMAGES_BYTES:
                raise ReleaseValidationError("внутренний артефакт превышает лимит")
            manifest_handle = archive.extractfile(by_name[MANIFEST_NAME])
            if manifest_handle is None or by_name[MANIFEST_NAME].size > 1024 * 1024:
                raise ReleaseValidationError("manifest release не читается")
            manifest = json.loads(manifest_handle.read().decode("utf-8"))
            if manifest.get("format") != 1 or manifest.get("platform") != PLATFORM:
                raise ReleaseValidationError("неверные format или platform release")
            if not BUILD_ID_RE.fullmatch(str(manifest.get("build_id", ""))):
                raise ReleaseValidationError("неверный build-id release")
            for key, expected_name in (("source", SOURCE_NAME), ("images", IMAGES_NAME)):
                record = manifest.get(key)
                if not isinstance(record, dict) or record.get("name") != expected_name:
                    raise ReleaseValidationError(f"неверная секция {key} в manifest")
                member = by_name[expected_name]
                if record.get("size") != member.size or record.get("sha256") != _member_sha256(archive, member):
                    raise ReleaseValidationError(f"hash/size не совпадает для {expected_name}")
            items = manifest["images"].get("items")
            if not isinstance(items, list):
                raise ReleaseValidationError("в manifest отсутствует список образов")
            refs = [item.get("ref") for item in items if isinstance(item, dict)]
            if refs != list(EXPECTED_IMAGE_REFS):
                raise ReleaseValidationError(f"неверный список image refs: {refs}")
            for item in items:
                if item.get("platform") != PLATFORM or not IMAGE_ID_RE.fullmatch(str(item.get("id", ""))):
                    raise ReleaseValidationError(f"неверные metadata образа: {item.get('ref', '')}")
                digests = item.get("repo_digests") or []
                if not item.get("ref", "").startswith("kvn-") and not any(
                    REPO_DIGEST_RE.fullmatch(value) for value in digests if isinstance(value, str)
                ):
                    raise ReleaseValidationError(
                        f"upstream-образ без immutable digest: {item.get('ref', '')}"
                    )
            with tempfile.TemporaryDirectory() as tmp:
                source_path = Path(tmp) / SOURCE_NAME
                images_path = Path(tmp) / IMAGES_NAME
                for name, destination in ((SOURCE_NAME, source_path), (IMAGES_NAME, images_path)):
                    handle = archive.extractfile(by_name[name])
                    if handle is None:
                        raise ReleaseValidationError(f"не удалось извлечь {name}")
                    with destination.open("wb") as target:
                        shutil.copyfileobj(handle, target)
                try:
                    inspect_archive(source_path)
                except ArchiveValidationError as exc:
                    raise ReleaseValidationError(f"source deploy отклонён: {exc}") from exc
                loaded_ids = _validate_image_archive(images_path, refs)
                for item in items:
                    if loaded_ids.get(item["ref"]) != item["id"]:
                        raise ReleaseValidationError(f"ID после docker load не совпадает: {item['ref']}")
    except ReleaseValidationError:
        raise
    except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReleaseValidationError("release повреждён или имеет неверный manifest") from exc
    return manifest


def extract_release(path: Path, target: Path) -> dict:
    """Проверяет release и атомарно извлекает три allowlisted файла."""
    manifest = validate_release(path)
    required_free = int(manifest["source"]["size"]) + int(manifest["images"]["size"]) + 256 * 1024 * 1024
    target.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(target.parent).free < required_free:
        raise ReleaseValidationError(f"недостаточно свободного места; требуется {required_free} bytes")
    temporary = target.with_name(target.name + ".part")
    if temporary.exists() or target.exists():
        raise ReleaseValidationError("каталог извлечения release уже существует")
    temporary.mkdir(mode=0o700)
    try:
        with tarfile.open(path, "r:gz") as archive:
            for name in RELEASE_MEMBERS:
                member = archive.getmember(name)
                handle = archive.extractfile(member)
                if handle is None:
                    raise ReleaseValidationError(f"не удалось извлечь {name}")
                destination = temporary / name
                with destination.open("xb") as output:
                    shutil.copyfileobj(handle, output, length=1024 * 1024)
                    output.flush()
            temporary.replace(target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return manifest


def verify_loaded_images(manifest_path: Path) -> dict[str, str]:
    """Сверяет локальные Docker tags с load-time IDs и платформой release."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        items = manifest["images"]["items"]
        refs = [item["ref"] for item in items]
        result = subprocess.run(
            ["docker", "image", "inspect", *refs], check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        )
        if result.returncode != 0:
            raise ReleaseValidationError("после docker load отсутствует обязательный image tag")
        inspected = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, KeyError, TypeError, json.JSONDecodeError) as exc:
        if isinstance(exc, ReleaseValidationError):
            raise
        raise ReleaseValidationError("не удалось проверить загруженные Docker images") from exc
    if len(inspected) != len(items):
        raise ReleaseValidationError("docker inspect вернул неверное число образов")
    verified: dict[str, str] = {}
    saved_config_ids: dict[str, str] = {}
    for expected, actual in zip(items, inspected, strict=True):
        platform = f"{actual.get('Os', '')}/{actual.get('Architecture', '')}"
        expected_digests = set(expected.get("repo_digests") or [])
        accepted_ids = {expected.get("id")}
        accepted_ids.update(
            digest.rsplit("@", 1)[1]
            for digest in expected_digests
            if isinstance(digest, str) and "@sha256:" in digest
        )
        actual_digests = set(actual.get("RepoDigests") or [])
        digest_id = actual.get("Id") in accepted_ids
        digest_provenance = (
            actual.get("Id") == expected.get("id")
            or bool(expected_digests & actual_digests)
        )
        identity_matches = digest_id and digest_provenance
        if not identity_matches:
            ref = expected["ref"]
            if ref not in saved_config_ids:
                # containerd image store после docker load может вернуть descriptor ID
                # и не восстановить RepoDigests. Экспорт одного tag даёт исходный
                # config digest без большого временного архива всех семи образов.
                saved_config_ids.update(_saved_image_config_ids([ref]))
            identity_matches = saved_config_ids.get(ref) == expected.get("id")
        if not identity_matches or platform != PLATFORM:
            raise ReleaseValidationError(f"загруженный образ не совпадает: {expected.get('ref', '')}")
        verified[expected["ref"]] = expected["id"]
    return verified


def _saved_image_config_ids(refs: list[str]) -> dict[str, str]:
    """Получает config digests загруженных local images независимо от image store Docker."""
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / "loaded-local-images.tar"
        try:
            result = subprocess.run(
                ["docker", "image", "save", "-o", str(archive_path), *refs],
                check=False,
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=180,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseValidationError(
                "не удалось проверить config digests локальных Docker images"
            ) from exc
        if result.returncode != 0:
            raise ReleaseValidationError(
                "не удалось экспортировать локальные Docker images для проверки"
            )
        return _validate_image_archive(archive_path, refs)


def _load_metadata(path: Path) -> list[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseValidationError("metadata образов не читаются") from exc
    if not isinstance(value, list):
        raise ReleaseValidationError("metadata образов должны быть списком")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Сборка и проверка офлайн-релиза KVN")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("create")
    create.add_argument("--build-id", required=True)
    create.add_argument("--source", type=Path, required=True)
    create.add_argument("--images", type=Path, required=True)
    create.add_argument("--metadata", type=Path, required=True)
    create.add_argument("--output", type=Path, required=True)
    inspect = subparsers.add_parser("inspect")
    inspect.add_argument("release", type=Path)
    normalize = subparsers.add_parser("normalize-images")
    normalize.add_argument("archive", type=Path)
    extract = subparsers.add_parser("extract")
    extract.add_argument("release", type=Path)
    extract.add_argument("target", type=Path)
    verify = subparsers.add_parser("verify-loaded")
    verify.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            manifest = create_release(
                args.output, args.build_id, args.source, args.images, _load_metadata(args.metadata),
            )
        elif args.command == "inspect":
            manifest = validate_release(args.release)
        elif args.command == "normalize-images":
            normalize_image_archive(args.archive)
            manifest = {"normalized": args.archive.name, "sha256": sha256_file(args.archive)}
        elif args.command == "extract":
            manifest = extract_release(args.release, args.target)
        else:
            manifest = {"verified": verify_loaded_images(args.manifest)}
        sys.stdout.write(json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n")
    except ReleaseValidationError as exc:
        sys.stderr.write(f"[ОШИБКА] Release отклонён: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
