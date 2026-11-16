"""Маркер поколений, импортированных вручную, без хранения ключей."""

import re
from pathlib import Path

from .queue import TLS_QUEUE, _write_json, read_json

PATH = TLS_QUEUE / 'imported.json'
_SLOT = re.compile(r'(?:dns|ip)-[a-z0-9_.-]{1,240}\Z', re.ASCII)
_HASH = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


def load(path: Path = PATH) -> dict[str, list[str]]:
    data = read_json(path, {})
    if (not isinstance(data, dict) or len(data) > 32
            or any(not isinstance(slot, str) or not _SLOT.fullmatch(slot)
                   or not isinstance(values, list) or not 1 <= len(values) <= 2
                   or any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in values)
                   or len(set(values)) != len(values) for slot, values in data.items())):
        raise ValueError('Некорректное состояние импортированных сертификатов')
    return data


def save(data: dict[str, list[str]], path: Path = PATH) -> None:
    _write_json(path, data)
