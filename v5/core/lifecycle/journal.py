"""Незавершённая операция хранится отдельно от конфигов модулей и ключей."""

import json
import os
from pathlib import Path
import stat
from tempfile import NamedTemporaryFile

from v5.core.contracts import validate_module_id

_LIMIT = 2048
PENDING_NAME = "network.pending.json"


def _module_list(items: object) -> frozenset[str]:
    if not isinstance(items, list) or items != sorted({validate_module_id(item) for item in items}):
        raise ValueError("Повреждён журнал сетевой операции")
    return frozenset(items)


class IntentJournal:
    def __init__(self, path: Path):
        self.path = path

    def _check_directory(self) -> None:
        info = self.path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("Журнал сетевой операции должен быть в закрытом каталоге")

    def read(self) -> tuple[frozenset[str], frozenset[str]] | None:
        self._check_directory()
        try:
            descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("Недопустимые права журнала")
            data = handle.read(_LIMIT + 1)
        if len(data) > _LIMIT:
            raise ValueError("Журнал сетевой операции превышает лимит")
        record = json.loads(data)
        if (not isinstance(record, dict) or record.keys() != {"version", "previous", "desired"}
                or type(record["version"]) is not int or record["version"] != 1):
            raise ValueError("Повреждён журнал сетевой операции")
        return _module_list(record["previous"]), _module_list(record["desired"])

    def _sync(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def write(self, previous: frozenset[str], desired: frozenset[str]) -> None:
        self._check_directory()
        temp = None
        try:
            with NamedTemporaryFile(mode="wb", prefix=".network-", dir=self.path.parent, delete=False) as handle:
                temp = Path(handle.name)
                record = {"version": 1, "previous": sorted(previous), "desired": sorted(desired)}
                handle.write(json.dumps(record, separators=(",", ":")).encode("ascii") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            self._sync()
        finally:
            if temp is not None:
                temp.unlink(missing_ok=True)

    def clear(self) -> None:
        self._check_directory()
        self.path.unlink(missing_ok=True)
        self._sync()
