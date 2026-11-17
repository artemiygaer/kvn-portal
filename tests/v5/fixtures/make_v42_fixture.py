"""Синтетический зашифрованный образец для проверок совместимости формата."""

import base64
import json
from pathlib import Path

from v5.core.migration.crypto import decrypt_archive, encrypt_archive
from v5.modules.host_tunnel.credentials import public_key

PHRASE = "only-a-synthetic-passphrase"
FIXTURE = Path(__file__).with_name("synthetic-v42.kvn")


def build_fixture(edit=None):
    """Возвращает только учебные данные без зависимости от старых исходников."""
    document = json.loads(decrypt_archive(FIXTURE.read_bytes(), PHRASE))
    for offset, name in enumerate(("wireguard", "amneziawg")):
        server, client = document["protocols"][name], document["users"][0][name]
        for index, record in enumerate((server, client)):
            record["private_key"] = base64.b64encode(bytes([31 + offset * 2 + index]) * 32).decode("ascii")
            record["public_key"] = public_key(record["private_key"])
        client["preshared_key"] = base64.b64encode(bytes([51 + offset]) * 32).decode("ascii")
    if edit is not None:
        edit(document)
    return encrypt_archive(json.dumps(document).encode("utf-8"), PHRASE)
