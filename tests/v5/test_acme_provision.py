"""Безопасное переключение окружения Certbot и проверяемый transport."""

from pathlib import Path
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch

from v5.core.tls import provision


class CertbotProvisionTests(unittest.TestCase):
    def test_timeout_stops_descendants_before_cleanup(self):
        started = time.monotonic()
        with self.assertRaises(provision.ProvisionError):
            provision._run(("/bin/sh", "-c", "sleep 30 & wait"), 0.2)
        self.assertLess(time.monotonic() - started, 3)

    def test_offline_install_checks_hashes_and_is_idempotent(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "requirements.lock"
            lock.write_text("fixture", encoding="ascii")
            wheels = root / "wheels"
            wheels.mkdir()
            with patch.object(provision, "_run", return_value=b"certbot 5.9.0\n") as run:
                current = provision.install_runtime(root=root, lockfile=lock, wheels=wheels)
                self.assertEqual(current, root / "kvn-v5-acme/bin/certbot")
                self.assertTrue(current.parents[1].is_symlink())
                command = run.call_args_list[1].args[0]
                self.assertIn("--require-hashes", command)
                self.assertIn("--only-binary", command)
                self.assertIn("--no-index", command)
                self.assertIn(str(wheels), command)
                self.assertNotIn("--index-url", command)
                self.assertEqual(run.call_count, 4)
                self.assertEqual(provision.install_runtime(root=root, lockfile=lock, wheels=wheels), current)
                self.assertEqual(run.call_count, 5)

    def test_failed_update_never_moves_current_link_and_ignores_unmanaged_environment(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "requirements.lock"
            lock.write_text("fixture first", encoding="ascii")
            active = root / "kvn-v5-acme"
            active.mkdir()
            with patch.object(provision, "_run") as run, self.assertRaises(provision.ProvisionError):
                provision.install_runtime(root=root, lockfile=lock)
            run.assert_not_called()
            active.rmdir()
            with patch.object(provision, "_run", return_value=b"certbot 5.9.0\n"):
                provision.install_runtime(root=root, lockfile=lock)
            previous = active.resolve()
            lock.write_text("fixture changed", encoding="ascii")
            with patch.object(provision, "_run", side_effect=provision.ProvisionError("fixture")), \
                    self.assertRaises(provision.ProvisionError):
                provision.install_runtime(root=root, lockfile=lock)
            self.assertEqual(active.resolve(), previous)
            self.assertEqual({item for item in previous.parent.iterdir() if item.is_dir()}, {previous})
