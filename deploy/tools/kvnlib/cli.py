"""Узкие CLI-примитивы, не зависящие от runtime KVN."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from .client_export import ExportSection, render_export_document


def add_client_export_parsers(
    subparsers: Any,
    *,
    export_user_handler: Callable[[argparse.Namespace], None],
    export_links_handler: Callable[[argparse.Namespace], None],
) -> None:
    """Регистрирует новый export-user и совместимый export-links."""
    export_user = subparsers.add_parser(
        "export-user",
        help="Экспорт конфигурации пользователя для отправки",
    )
    export_user.add_argument("name", help="Имя пользователя")
    export_user.add_argument(
        "--address-mode",
        choices=("server", "public-ip"),
        help="Временный адрес: настройка сервера или публичный IPv4",
    )
    export_user.add_argument(
        "--public-ip",
        help="Публичный IPv4; обязателен с --address-mode public-ip",
    )
    export_user.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Формат результата",
    )
    export_user.add_argument(
        "--output",
        type=Path,
        help="Атомарно записать в файл с правами 0600 вместо stdout",
    )
    export_user.set_defaults(func=export_user_handler)

    legacy = subparsers.add_parser(
        "export-links",
        help="Ссылки для отправки (без markdown)",
    )
    legacy.add_argument("name", nargs="?")
    legacy.add_argument("--all", action="store_true", help="Показать всех пользователей")
    legacy.add_argument("--server", help="IP или домен сервера")
    legacy.set_defaults(func=export_links_handler)


def serialize_user_export(
    *,
    username: str,
    connection_host: str,
    sections: Sequence[ExportSection],
    output_format: str,
) -> str:
    """Сериализует structured export без побочных выводов."""
    if output_format == "json":
        return (
            json.dumps(
                {
                    "schema": 1,
                    "user": username,
                    "connection_host": connection_host,
                    "sections": [section.as_dict() for section in sections],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
    if output_format == "text":
        return render_export_document(
            f"KVN VPN — {username}",
            sections,
            markdown=False,
        )
    raise ValueError(f"Неизвестный формат экспорта: {output_format}")


def atomic_write_private(path: Path, content: str) -> None:
    """Атомарно пишет чувствительный export с итоговым mode 0600."""
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
