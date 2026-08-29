"""Каноническая версия портала и безопасное сравнение GitHub Release."""

from __future__ import annotations

import re


APP_VERSION = "v4.0.0"
VERSION_RE = re.compile(r"^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


def version_key(value: object) -> tuple[int, int, int] | None:
    """Возвращает числовой ключ стабильной версии или ``None``."""
    match = VERSION_RE.fullmatch(str(value).strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


def normalize_version(value: object) -> str:
    """Нормализует стабильную версию к виду ``vX.Y.Z``."""
    key = version_key(value)
    return "" if key is None else "v" + ".".join(str(part) for part in key)


def release_is_installed(installed: object, candidate: object) -> bool:
    """Считает установленными ту же или более новую стабильную версию."""
    installed_key = version_key(installed)
    candidate_key = version_key(candidate)
    if installed_key is None or candidate_key is None:
        raise ValueError("Некорректная версия Release.")
    return installed_key >= candidate_key
