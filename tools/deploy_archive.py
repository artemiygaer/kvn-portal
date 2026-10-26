#!/usr/bin/env python3
"""Проверяет release-архив KVN до распаковки и выполнения обновления.

Модуль не извлекает данные и не запускает код из архива. Он допускает только
обычные файлы в ``deploy/`` и чистый deploy-шаблон без runtime-данных.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_MEMBERS = 512
MANIFEST_NAME = ".kvn-canonical-files"
CANONICAL_SCHEMA_PATH = Path(__file__).with_name("canonical-files.txt")
DEPLOY_ONLY = {
    "DEPLOY.md",
    "users.json",
    "nginx/site/index.html",
    "nginx/web/.gitkeep",
    "hy2/.gitkeep",
    "mtg/.gitkeep",
    "telemt/.gitkeep",
    "xray/.gitkeep",
    "portal-data/.gitkeep",
    "portal-runtime/.gitkeep",
    # Нужен только для совместимости со старыми update.sh.
    "portal/build_info.py",
}
RUNTIME_EXACT = {
    "CLIENT_LINKS.md",
    ".env",
    "nginx/nginx.conf",
    "nginx/portal-gateway.conf",
    "xray/config.json",
    "hy2/config.yaml",
    "amneziawg/awg0.conf",
    "wireguard/wg0.conf",
    "telemt/config.toml",
    "mtg/config.toml",
    "ocserv/ocserv.conf",
    "ocserv/users.txt",
    "ocserv/ocserv.env",
}
RUNTIME_PREFIXES = ("clients/", "certs/", "site-certs/", "ocserv/certs/", "hy2/certs/", "backup/")
RUNTIME_DATA_PREFIXES = ("portal-data/", "portal-runtime/")
SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

# Bridge v4.1.2 сохраняет исходный inventory v4.1.1, но заранее знает только
# один следующий inventory. Это не разрешение путей из непроверенного архива.
LEGACY_V411_SCHEMA_SHA256 = "8afdf0869dd9e771193189ed34b1c52e602aee5831ae212d7b952df94e03f89d"
FORWARD_VERSION = "v4.2.0"
V420_WHEEL_REPLACEMENTS = {
    "portal/wheels/gunicorn-26.0.0-py3-none-any.whl": "portal/wheels/gunicorn-26.2.0-py3-none-any.whl",
    "portal/wheels/werkzeug-3.1.8-py3-none-any.whl": "portal/wheels/werkzeug-3.1.9-py3-none-any.whl",
}
V420_NEW_SOURCE_FILES = tuple(sorted((
    "tools/kvnlib/core/migration.py",
    "tools/kvnlib/exports/migration.py",
    "tools/kvnlib/runtime/migration.py",
    "portal/root_shell_helper.py",
    "portal/agent_handlers/migration.py",
    "portal/control/migration.py",
    "portal/app/routes/shell_stream.py",
    "portal/app/routes/migration.py",
    "portal/app/static/migration.js",
    "portal/app/templates/migration.html",
    "portal/app/static/vendor/xterm/SHA256SUMS",
    "portal/wheels/flask_sock-0.7.0-py3-none-any.whl",
    "portal/wheels/simple_websocket-1.1.0-py3-none-any.whl",
    "portal/wheels/wsproto-1.3.2-py3-none-any.whl",
    "portal/wheels/h11-0.16.0-py3-none-any.whl",
)))


class ArchiveValidationError(ValueError):
    """Архив не соответствует безопасному формату deploy."""


def forward_v420_schema(canonical: list[str]) -> list[str] | None:
    """Точная ограниченная миграция trusted inventory v4.1.1 → v4.2.0."""
    normalized = ("\n".join(canonical) + "\n").encode("utf-8")
    if hashlib.sha256(normalized).hexdigest() != LEGACY_V411_SCHEMA_SHA256:
        return None
    return [V420_WHEEL_REPLACEMENTS.get(path, path) for path in canonical] + list(V420_NEW_SOURCE_FILES)


def _load_canonical_schema() -> list[str]:
    try:
        lines = CANONICAL_SCHEMA_PATH.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ArchiveValidationError(
            "в bootstrap отсутствует tools/canonical-files.txt; пересоберите deploy-архив"
        ) from exc
    if not lines:
        raise ArchiveValidationError("канонический список исходников пуст")
    result: list[str] = []
    for relative in lines:
        safe = _safe_relative(relative)
        if _runtime_path(safe) or safe in result:
            raise ArchiveValidationError(f"ошибка канонического списка: {safe}")
        result.append(safe)
    return result


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ArchiveValidationError("недопустимое имя члена архива")
    path = PurePosixPath(value)
    if value.startswith("/") or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveValidationError("небезопасный путь в архиве")
    if not SAFE_PATH_RE.fullmatch(value):
        raise ArchiveValidationError("недопустимые символы в пути архива")
    return value


def _runtime_path(relative: str) -> bool:
    if relative in RUNTIME_EXACT or relative.startswith(RUNTIME_PREFIXES):
        return True
    if relative.startswith(RUNTIME_DATA_PREFIXES) and relative not in {"portal-data/.gitkeep", "portal-runtime/.gitkeep"}:
        return True
    return relative.startswith("kvn-vpn-backup-")


def _runtime_directory(relative: str) -> bool:
    return relative in {"clients", "certs", "site-certs", "backup"} or any(
        relative == prefix.removesuffix("/") for prefix in RUNTIME_PREFIXES
    )


def _parse_manifest(content: bytes) -> list[str]:
    if len(content) > 256 * 1024:
        raise ArchiveValidationError("manifest архива слишком большой")
    try:
        lines = content.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ArchiveValidationError("manifest архива должен быть UTF-8") from exc
    if not lines:
        raise ArchiveValidationError("manifest архива пуст")
    result: list[str] = []
    for relative in lines:
        safe = _safe_relative(relative)
        if _runtime_path(safe):
            raise ArchiveValidationError("runtime-путь запрещён в manifest")
        if safe in result:
            raise ArchiveValidationError("повторяющийся путь в manifest")
        result.append(safe)
    canonical = _load_canonical_schema()
    forward = forward_v420_schema(canonical)
    if forward is not None and result == forward:
        return result
    missing = [relative for relative in canonical if relative not in result]
    extra = [relative for relative in result if relative not in canonical]
    if missing:
        raise ArchiveValidationError(
            "в manifest отсутствуют канонические файлы: " + ", ".join(missing)
        )
    if extra:
        raise ArchiveValidationError(
            "в manifest есть неизвестные исходники: " + ", ".join(extra)
        )
    if result != canonical:
        raise ArchiveValidationError("порядок manifest не совпадает с tools/canonical-files.txt")
    return result


def _validate_template_users(archive: tarfile.TarFile, member: tarfile.TarInfo) -> None:
    handle = archive.extractfile(member)
    if handle is None:
        raise ArchiveValidationError("deploy/users.json не читается")
    try:
        state = json.loads(handle.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveValidationError("deploy/users.json должен быть корректным JSON") from exc
    if state.get("server") != "YOUR_SERVER_IP" or state.get("users") != [] or state.get("portal") != {"enabled": False}:
        raise ArchiveValidationError("deploy/users.json содержит runtime-данные или не является чистым шаблоном")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_archive(path: Path) -> dict[str, int | str]:
    """Возвращает безопасные метаданные или выбрасывает ``ArchiveValidationError``."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ArchiveValidationError("архив не найден") from exc
    if not 1024 <= size <= MAX_ARCHIVE_BYTES:
        raise ArchiveValidationError("размер архива вне допустимого диапазона")
    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"\x1f\x8b":
                raise ArchiveValidationError("архив не похож на gzip")
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            if not 1 <= len(members) <= MAX_MEMBERS:
                raise ArchiveValidationError("недопустимое число членов архива")
            files: dict[str, tarfile.TarInfo] = {}
            unpacked = 0
            for member in members:
                name = member.name.rstrip("/")
                if name == "deploy":
                    if not member.isdir():
                        raise ArchiveValidationError("корень deploy должен быть каталогом")
                    continue
                if not name.startswith("deploy/"):
                    raise ArchiveValidationError("в архиве допустим только корень deploy/")
                relative = _safe_relative(name.removeprefix("deploy/"))
                if member.isdir():
                    if _runtime_directory(relative):
                        raise ArchiveValidationError("runtime-каталог в архиве запрещён")
                    continue
                if member.issym() or member.islnk() or member.isdev() or member.isfifo() or not member.isreg():
                    raise ArchiveValidationError("ссылки и специальные файлы в архиве запрещены")
                if relative in files:
                    raise ArchiveValidationError("повторяющийся член архива")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise ArchiveValidationError("член архива превышает лимит")
                unpacked += member.size
                if unpacked > MAX_UNPACKED_BYTES:
                    raise ArchiveValidationError("распакованный архив превышает лимит")
                files[relative] = member

            manifest_member = files.get(MANIFEST_NAME)
            if manifest_member is None:
                raise ArchiveValidationError("в архиве отсутствует обязательный manifest")
            if manifest_member.size > 256 * 1024:
                raise ArchiveValidationError("manifest архива слишком большой")
            manifest_handle = archive.extractfile(manifest_member)
            if manifest_handle is None:
                raise ArchiveValidationError("manifest архива не читается")
            manifest_content = manifest_handle.read()
            manifest = _parse_manifest(manifest_content)
            expected = set(manifest) | DEPLOY_ONLY | {MANIFEST_NAME}
            unknown = set(files) - expected
            missing = set(manifest) - set(files)
            if unknown:
                raise ArchiveValidationError(
                    "в архиве есть неразрешённые файлы: " + ", ".join(sorted(unknown))
                )
            if missing:
                raise ArchiveValidationError(
                    "в архиве отсутствуют файлы из manifest: " + ", ".join(sorted(missing))
                )
            schema_member = files.get("tools/canonical-files.txt")
            if schema_member is None or schema_member.size > 256 * 1024:
                raise ArchiveValidationError("в архиве отсутствует допустимый канонический список")
            schema_handle = archive.extractfile(schema_member)
            if schema_handle is None or schema_handle.read() != manifest_content:
                raise ArchiveValidationError("manifest не совпадает со встроенным tools/canonical-files.txt")
            if manifest != _load_canonical_schema():
                version_member = files.get("VERSION")
                if version_member is None or version_member.size > 32:
                    raise ArchiveValidationError("новый inventory требует VERSION v4.2.0")
                version_handle = archive.extractfile(version_member)
                if version_handle is None or version_handle.read().strip() != FORWARD_VERSION.encode("ascii"):
                    raise ArchiveValidationError("новый inventory разрешён только для v4.2.0")
            users_member = files.get("users.json")
            if users_member is None:
                raise ArchiveValidationError("в архиве отсутствует deploy/users.json")
            _validate_template_users(archive, users_member)
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise ArchiveValidationError("архив повреждён или не является корректным tar.gz") from exc
    return {
        "name": path.name,
        "size": size,
        "sha256": _sha256(path),
        "member_count": len(files),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка безопасного KVN deploy-архива")
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_archive(args.archive), ensure_ascii=False, sort_keys=True))
    except ArchiveValidationError as exc:
        print(f"[ОШИБКА] Архив обновления отклонён: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
