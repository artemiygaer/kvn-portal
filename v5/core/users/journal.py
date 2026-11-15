"""Закрытый журнал для восстановления interrupted apply пользовательских прав."""

import base64
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path

from v5.core.contracts import UserGrant
from v5.core.packages.manifest import canonical_json, json_object
from v5.core.private_files import private_directory, read_private, write_private

MAX_SNAPSHOT = 256 * 1024
MAX_JOURNAL = 360 * 1024


@dataclass(frozen=True, slots=True)
class PendingUserApply:
    grant: UserGrant
    revision: int
    previous: bytes = field(repr=False)

    def __post_init__(self):
        if (not isinstance(self.grant, UserGrant) or type(self.revision) is not int or self.revision < 1
                or not isinstance(self.previous, bytes) or not 1 <= len(self.previous) <= MAX_SNAPSHOT):
            raise ValueError("Некорректный журнал применения пользователя")


class UserApplyJournal:
    def __init__(self, path: Path):
        self.path = Path(path)

    def read(self) -> PendingUserApply | None:
        try:
            raw = read_private(self.path, MAX_JOURNAL)
        except FileNotFoundError:
            return None
        data = json_object(raw)
        if (data.keys() != {"schema", "user", "module", "enabled", "revision", "previous", "sha256"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or not isinstance(data["previous"], str) or not isinstance(data["sha256"], str)):
            raise ValueError("Некорректная схема журнала пользователя")
        try:
            previous = base64.b64decode(data["previous"], validate=True)
        except ValueError as exc:
            raise ValueError("Некорректный снимок журнала пользователя") from exc
        if (base64.b64encode(previous).decode("ascii") != data["previous"]
                or hashlib.sha256(previous).hexdigest() != data["sha256"]):
            raise ValueError("Нарушена целостность журнала пользователя")
        return PendingUserApply(UserGrant(data["user"], data["module"], data["enabled"]), data["revision"], previous)

    def write(self, pending: PendingUserApply) -> None:
        if not isinstance(pending, PendingUserApply):
            raise ValueError("Некорректное намерение пользователя")
        data = canonical_json({"schema": 1, "user": pending.grant.user_id, "module": pending.grant.module_id,
                               "enabled": pending.grant.enabled, "revision": pending.revision,
                               "previous": base64.b64encode(pending.previous).decode("ascii"),
                               "sha256": hashlib.sha256(pending.previous).hexdigest()})
        if len(data) > MAX_JOURNAL:
            raise ValueError("Слишком большой журнал пользователя")
        write_private(self.path, data, replace=False)

    def clear(self) -> None:
        private_directory(self.path.parent)
        self.path.unlink(missing_ok=True)
        fd = os.open(self.path.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
