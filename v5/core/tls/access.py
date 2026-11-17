"""Проверенные параметры публичного адреса панели и безопасные значения по умолчанию."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat

ACCESS_FILE = Path('/etc/kvn-v5/access.json')
_PREFIX = re.compile(r'(?:/[A-Za-z0-9][A-Za-z0-9_-]{0,31}){1,4}\Z', re.ASCII)


@dataclass(frozen=True, slots=True)
class PortalAccess:
    port: int = 8443
    prefix: str = ''

    def __post_init__(self):
        if type(self.port) is not int or not 1024 <= self.port <= 65535 or self.port == 10443:
            raise ValueError('Укажите порт панели от 1024 до 65535, кроме 10443')
        if not isinstance(self.prefix, str) or (self.prefix and not _PREFIX.fullmatch(self.prefix)):
            raise ValueError('Путь панели должен состоять из компонентов с латинскими буквами, цифрами, _ или -')

    @classmethod
    def parse(cls, port, prefix):
        if type(port) not in (int, str):
            raise ValueError('Некорректный порт панели')
        try:
            number = int(port)
        except (ValueError, TypeError) as exc:
            raise ValueError('Некорректный порт панели') from exc
        if not isinstance(prefix, str):
            raise ValueError('Некорректный путь панели')
        path = prefix.strip()
        if path in ('', '/'):
            path = ''
        elif not path.startswith('/'):
            path = '/' + path
        if path:
            path = path.rstrip('/')
        return cls(number, path)


def load_access(path=ACCESS_FILE):
    """Старые установки без файла сохраняют прежний порт и корневой путь."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return PortalAccess()
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
            raise ValueError('Небезопасный файл адреса панели')
        raw = stream.read(1025)
    if len(raw) > 1024:
        raise ValueError('Некорректный файл адреса панели')
    data = json.loads(raw)
    if not isinstance(data, dict) or set(data) != {'port', 'prefix'}:
        raise ValueError('Некорректный файл адреса панели')
    return PortalAccess(data['port'], data['prefix'])
