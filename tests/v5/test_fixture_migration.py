"""Контракт synthetic .kvn, сформированного экспортёром v4.2."""

import importlib.util
from pathlib import Path
import unittest

from tools.kvnlib.core.migration import parse_migration
from tools.kvnlib.runtime.migration import decrypt_migration, MigrationCryptoError


FILE = Path(__file__).resolve().parent / "fixtures" / "make_v42_fixture.py"
SPEC = importlib.util.spec_from_file_location("make_v42_synthetic_fixture", FILE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class SyntheticFixtureTests(unittest.TestCase):
    def test_v42_archive_is_encrypted_and_excludes_portal_secrets(self):
        encrypted = FIXTURE.build_fixture()
        payload = decrypt_migration(encrypted, "only-a-synthetic-passphrase")
        self.assertNotIn(b"synthetic-portal-secret", payload)
        self.assertNotIn(b"synthetic-github-secret", payload)
        self.assertTrue(parse_migration(payload)["users"])
        with self.assertRaises(MigrationCryptoError):
            decrypt_migration(encrypted, "not-the-synthetic-passphrase")
