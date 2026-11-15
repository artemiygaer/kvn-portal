"""Секрет закрытого режима Hysteria без действующих пользовательских прав."""

from pathlib import Path
from secrets import token_urlsafe

from v5.core.packages.manifest import canonical_json, json_object, reject
from v5.core.private_files import read_private, write_private

from .config import Account


def idle_secret(root: Path, *, create: bool = False) -> str:
    path = root / "idle-auth.json"
    try:
        raw = read_private(path, 1024)
    except FileNotFoundError:
        if not create:
            raise
        candidate = token_urlsafe(32)
        try:
            write_private(path, canonical_json({"schema": 1, "secret": candidate}), replace=False)
        except FileExistsError:
            pass
        raw = read_private(path, 1024)
    data = json_object(raw)
    if data.keys() != {"schema", "secret"} or type(data["schema"]) is not int or data["schema"] != 1:
        reject("hysteria_idle_secret_invalid")
    try:
        return Account("placeholder", data["secret"], False).password
    except (TypeError, ValueError):
        reject("hysteria_idle_secret_invalid")
