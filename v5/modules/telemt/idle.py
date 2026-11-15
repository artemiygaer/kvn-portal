"""Секрет закрытого режима Telemt; нет известного пользователю ключа."""

from v5.core.packages.manifest import canonical_json, json_object, reject
from v5.core.private_files import read_private, write_private
from v5.modules.mtproto_common.profiles import Secret


def idle_secret(root):
    path = root / "idle-auth.json"
    try:
        raw = read_private(path, 1024)
    except FileNotFoundError:
        try:
            write_private(path, canonical_json({"schema": 1, "secret": Secret.create().value}), replace=False)
        except FileExistsError:
            pass
        raw = read_private(path, 1024)
    value = json_object(raw)
    if value.keys() != {"schema", "secret"} or type(value["schema"]) is not int or value["schema"] != 1:
        reject("telemt_idle_secret_invalid")
    return Secret(value["secret"])
