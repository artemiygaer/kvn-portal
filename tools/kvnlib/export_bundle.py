"""Детерминированный приватный пакет клиентских конфигураций."""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


ALLOWED_ARTIFACTS = frozenset(
    {
        "amneziawg.conf",
        "happ-subscription.txt",
        "hysteria2.yaml",
        "karing-subscription.txt",
        "karing-wireguard.txt",
        "karing-wireguard.yaml",
        "links.txt",
        "mtg.txt",
        "openconnect.txt",
        "subscription-raw-all.txt",
        "subscription-raw.txt",
        "subscription.json",
        "subscription.txt",
        "telegram-proxy.txt",
        "telemt.txt",
        "wireguard.conf",
        "xray-hysteria2.json",
        "xray-reality-direct.json",
        "xray-reality-tcp-direct.json",
        "xray-reality-tcp.json",
        "xray-reality.json",
        "xray-vless-tls-direct.json",
        "xray-vless-tls.json",
    }
)
RESERVED_NAMES = frozenset({"README.txt", "send.txt", "manifest.json"})
SAFE_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{2,32}$")
MAX_FILE_COUNT = 32
MAX_FILE_BYTES = 96 * 1024
MAX_TOTAL_BYTES = 192 * 1024
MAX_ARCHIVE_BYTES = 192 * 1024
MAX_TEXT_BYTES = 64 * 1024
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class ExportBundleError(ValueError):
    """Безопасная ошибка формирования клиентского пакета."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class UserExportBundle:
    """Готовые данные RPC без временного файла на диске."""

    archive: bytes
    text: bytes
    manifest: dict[str, object]


def _source_bytes(
    name: str,
    source: bytes | bytearray | memoryview | Path,
    *,
    source_root: Path | None,
) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        content = bytes(source)
    elif isinstance(source, Path):
        if source_root is None:
            raise ExportBundleError(
                "unsafe_source",
                "Файловый источник требует явно заданный каталог пользователя.",
            )
        root = source_root.resolve()
        if source.is_symlink():
            raise ExportBundleError("unsafe_source", "Символические ссылки запрещены.")
        try:
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise ExportBundleError("missing_file", "Файл экспорта не найден.") from exc
        if resolved.parent != root or not resolved.is_file():
            raise ExportBundleError(
                "cross_user",
                "Файл находится вне каталога выбранного пользователя.",
            )
        try:
            if resolved.stat().st_size > MAX_FILE_BYTES:
                raise ExportBundleError(
                    "file_too_large",
                    f"Файл {name} превышает допустимый размер.",
                )
            content = resolved.read_bytes()
        except OSError as exc:
            raise ExportBundleError("read_failed", "Не удалось прочитать файл экспорта.") from exc
    else:
        raise ExportBundleError("invalid_source", "Некорректный источник файла экспорта.")
    if len(content) > MAX_FILE_BYTES:
        raise ExportBundleError(
            "file_too_large",
            f"Файл {name} превышает допустимый размер.",
        )
    return content


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info


def _readme(username: str, address_mode: str) -> bytes:
    mode = "публичный IPv4" if address_mode == "public-ip" else "основной адрес сервера"
    text = "\n".join(
        [
            f"KVN VPN — пакет пользователя {username}",
            "",
            f"Адрес подключения: {mode}.",
            "Начните с send.txt: в нём собраны ссылки и краткие подсказки.",
            "Файлы AmneziaWG и WireGuard не взаимозаменяемы.",
            "Для HAPP и Karing используйте соответствующие subscription-файлы.",
            "",
            "Пакет содержит приватные ключи и пароли клиента.",
            "Не публикуйте его и удалите из переписки после импорта.",
            "",
        ]
    )
    return text.encode("utf-8")


def build_user_export_bundle(
    *,
    username: str,
    address_mode: str,
    build_id: str,
    send_text: str,
    artifacts: Mapping[str, bytes | bytearray | memoryview | Path],
    source_root: Path | None = None,
) -> UserExportBundle:
    """Собирает ZIP в памяти и отклоняет всё вне точного allowlist."""
    if not isinstance(username, str) or not SAFE_USER_RE.fullmatch(username):
        raise ExportBundleError("invalid_user", "Некорректное имя пользователя.")
    if address_mode not in {"server", "public-ip"}:
        raise ExportBundleError("invalid_mode", "Режим адреса экспорта не разрешён.")
    if not isinstance(build_id, str) or not 1 <= len(build_id) <= 128:
        raise ExportBundleError("invalid_build", "Некорректный идентификатор сборки.")
    if not isinstance(send_text, str):
        raise ExportBundleError("invalid_text", "Текст экспорта должен быть строкой.")
    text = send_text.encode("utf-8")
    if len(text) > MAX_TEXT_BYTES:
        raise ExportBundleError("text_too_large", "Текст экспорта превышает лимит.")
    if not isinstance(artifacts, Mapping) or len(artifacts) > MAX_FILE_COUNT:
        raise ExportBundleError("too_many_files", "Слишком много файлов экспорта.")

    prepared: dict[str, bytes] = {}
    total = 0
    for name in sorted(artifacts):
        if (
            not isinstance(name, str)
            or name in RESERVED_NAMES
            or name not in ALLOWED_ARTIFACTS
        ):
            raise ExportBundleError(
                "file_not_allowed",
                f"Файл экспорта не разрешён: {name!r}",
            )
        content = _source_bytes(name, artifacts[name], source_root=source_root)
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise ExportBundleError(
                "bundle_too_large",
                "Суммарный размер файлов экспорта превышает лимит.",
            )
        prepared[name] = content

    readme = _readme(username, address_mode)
    payloads: dict[str, bytes] = {
        "README.txt": readme,
        "send.txt": text,
        **prepared,
    }
    manifest_files = [
        {
            "name": name,
            "size": len(payloads[name]),
            "sha256": hashlib.sha256(payloads[name]).hexdigest(),
        }
        for name in sorted(payloads)
    ]
    manifest: dict[str, object] = {
        "schema": 1,
        "build": build_id,
        "user": username,
        "address_mode": address_mode,
        "files": manifest_files,
    }
    manifest_bytes = (
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")

    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        ordered_names = [
            "README.txt",
            "send.txt",
            *sorted(prepared),
            "manifest.json",
        ]
        for name in ordered_names:
            content = manifest_bytes if name == "manifest.json" else payloads[name]
            archive.writestr(_zip_info(name), content)
    archive_bytes = output.getvalue()
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise ExportBundleError(
            "archive_too_large",
            "Итоговый ZIP превышает допустимый размер.",
        )
    return UserExportBundle(
        archive=archive_bytes,
        text=text,
        manifest=manifest,
    )
