"""Создать синтетический .kvn существующим экспортёром v4.2 для тестов v5."""

import base64
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from tests.test_migration import MigrationSchemaTests
from tools.kvnlib.exports.migration import build_migration
from tools.kvnlib.runtime.migration import encrypt_migration
from v5.modules.host_tunnel.credentials import public_key


def build_fixture(edit=None):
    """Создать шифрованный архив только на синтетическом состоянии теста."""
    fixture = MigrationSchemaTests(methodName="runTest")
    fixture.setUp()
    for offset, module in enumerate(("wireguard", "amneziawg")):
        server, client = fixture.state[module], fixture.state["users"][0][module]
        for index, record in enumerate((server, client)):
            record["private_key"] = base64.b64encode(bytes([31 + offset * 2 + index]) * 32).decode("ascii")
            record["public_key"] = public_key(record["private_key"])
        client["preshared_key"] = base64.b64encode(bytes([51 + offset]) * 32).decode("ascii")
    if edit is not None:
        edit(fixture.state)
    return encrypt_migration(build_migration(fixture.state), "only-a-synthetic-passphrase")


def main():
    result = build_fixture()
    output = Path(__file__).with_name("synthetic-v42.kvn")
    output.write_bytes(result)
    print(f"synthetic fixture sha256={hashlib.sha256(result).hexdigest()}")


if __name__ == "__main__":
    main()
