import json
import importlib.util
import tempfile
import unittest
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parents[1] / "portal" / "app" / "hysteria_auth.py"
_SPEC = importlib.util.spec_from_file_location("kvn_hysteria_auth", _MODULE_PATH)
_MODULE = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(_MODULE)
HysteriaUserCache = _MODULE.HysteriaUserCache


class HysteriaAuthTests(unittest.TestCase):
    def test_http_auth_requires_name_password_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            users_file = Path(tmp) / "users.json"
            users_file.write_text(
                json.dumps(
                    {
                        "users": [
                            {
                                "name": "Alice",
                                "enabled": True,
                                "systems": ["hysteria"],
                                "hysteria_password": "StrongPass123",
                            },
                            {
                                "name": "Bob",
                                "enabled": False,
                                "systems": ["hysteria"],
                                "hysteria_password": "DisabledPass123",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            cache = HysteriaUserCache(users_file)

            self.assertEqual(cache.authenticate("Alice:StrongPass123"), "Alice")
            self.assertIsNone(cache.authenticate("StrongPass123"))
            self.assertIsNone(cache.authenticate("Alice:WrongPass123"))
            self.assertIsNone(cache.authenticate("Bob:DisabledPass123"))


if __name__ == "__main__":
    unittest.main()
