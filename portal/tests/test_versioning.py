import unittest

from app.versioning import normalize_version, release_is_installed, version_key


class VersioningTests(unittest.TestCase):
    def test_normalization_and_numeric_order(self):
        self.assertEqual(normalize_version("3.1.1"), "v3.1.1")
        self.assertEqual(normalize_version("v3.1.1"), "v3.1.1")
        self.assertEqual(version_key("v10.2.0"), (10, 2, 0))
        self.assertTrue(release_is_installed("v3.1.1", "v3.1.1"))
        self.assertTrue(release_is_installed("v3.1.1", "v3.1.0"))
        self.assertFalse(release_is_installed("v3.1.1", "v3.1.2"))

    def test_malformed_versions_are_rejected(self):
        for value in ("", "dev", "v3.1", "v3.1.1-beta", "v03.1.1"):
            with self.subTest(value=value):
                self.assertEqual(normalize_version(value), "")
                with self.assertRaises(ValueError):
                    release_is_installed("v3.1.1", value)


if __name__ == "__main__":
    unittest.main()
