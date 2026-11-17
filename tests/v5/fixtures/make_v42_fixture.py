"""Синтетический зашифрованный образец для проверок совместимости формата."""

import json
from pathlib import Path

from v5.core.migration.crypto import decrypt_archive, encrypt_archive

PHRASE = "only-a-synthetic-passphrase"
FIXTURE = Path(__file__).with_name("synthetic-v42.kvn")


def build_fixture(edit=None):
    """Возвращает только учебные данные без зависимости от старых исходников."""
    encrypted = FIXTURE.read_bytes()
    if edit is None:
        return encrypted
    document = json.loads(decrypt_archive(encrypted, PHRASE))
    edit(document)
    return encrypt_archive(json.dumps(document).encode("utf-8"), PHRASE)
