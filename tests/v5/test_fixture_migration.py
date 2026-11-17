"""Контракт synthetic .kvn, сформированного экспортёром v4.2."""

import importlib.util
from pathlib import Path
import unittest

from v5.core.migration.legacy import parse_legacy
from v5.core.migration.crypto import decrypt_archive, ArchiveError


FILE = Path(__file__).resolve().parent / "fixtures" / "make_v42_fixture.py"
SPEC = importlib.util.spec_from_file_location("make_v42_synthetic_fixture", FILE)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class SyntheticFixtureTests(unittest.TestCase):
    def test_v42_archive_is_encrypted_and_excludes_portal_secrets(self):
        encrypted = FIXTURE.build_fixture()
        payload = decrypt_archive(encrypted, "only-a-synthetic-passphrase")
        self.assertNotIn(b"synthetic-portal-secret", payload)
        self.assertNotIn(b"synthetic-github-secret", payload)
        self.assertTrue(parse_legacy(payload).users)
        with self.assertRaises(ArchiveError):
            decrypt_archive(encrypted, "not-the-synthetic-passphrase")
