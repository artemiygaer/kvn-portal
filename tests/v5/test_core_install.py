"""Проверки отказа установки до любых изменений системы."""

import contextlib
import io
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from v5.install import setup
from v5.install.preflight import DEFAULT_INSTALL_DIR, InstallIdentity, InstallPreflightError, check_ports, reject_legacy


class InstallerPreflightTests(unittest.TestCase):
    def test_default_root_and_dns_normalization(self):
        self.assertEqual(DEFAULT_INSTALL_DIR, Path("/root/portal"))
        identity = InstallIdentity.parse("2001:db8::1", "Portal.example. portal.example Сайт.example")
        self.assertEqual(identity.ip, "2001:db8::1")
        self.assertEqual(identity.names, ("portal.example", "xn--80aswg.example"))

    def test_rejects_injection_and_non_unicast(self):
        for ip, names in (("0.0.0.0", ""), ("ff02::1", ""), ("fe80::1%eth0", ""),
                          ("192.0.2.1", "a.example;evil"), ("192.0.2.1", "192.0.2.2"),
                          ("192.0.2.1", "../etc")):
            with self.subTest(ip=ip, names=names), self.assertRaises(InstallPreflightError):
                InstallIdentity.parse(ip, names)

    def test_legacy_fixture_refused_without_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reject_legacy(root)
            unit = root / "etc/systemd/system/kvn-portal-agent.service"
            unit.parent.mkdir(parents=True)
            contents = "fixture, не запускать".encode()
            unit.write_bytes(contents)
            with self.assertRaises(InstallPreflightError):
                reject_legacy(root)
            self.assertEqual(unit.read_bytes(), contents)
            self.assertFalse((root / "root/portal").exists())

    def test_reports_occupied_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            with self.assertRaises(InstallPreflightError):
                check_ports((listener.getsockname()[1],))

    def test_bootstrap_has_public_http01_and_only_local_admin(self):
        identity = InstallIdentity.parse("192.0.2.8", "one.example two.example")
        config = setup.bootstrap_config(identity, ipv6=True)
        self.assertNotIn("@HTTP01@", config)
        self.assertIn("listen 80 default_server", config)
        self.assertIn('"two.example:80" "two.example";', config)
        self.assertIn("listen 127.0.0.1:8443 ssl reuseport;", config)
        self.assertNotIn("listen 443", config)

    def test_private_extraction_umask_does_not_block_web_code(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            previous = os.umask(0o077)
            try:
                source = base / "source"
                source.mkdir()
                (source / "app.py").write_text("# код панели\n", encoding="utf-8")
                target = base / "runtime"
                setup.copy_runtime_code(source, target)
                setup.mkdir_mode(base / "public", 0o755)
                self.assertEqual(source.stat().st_mode & 0o777, 0o700)
                self.assertEqual(target.stat().st_mode & 0o777, 0o755)
                self.assertEqual((target / "app.py").stat().st_mode & 0o777, 0o644)
                self.assertEqual((base / "public").stat().st_mode & 0o777, 0o755)
            finally:
                os.umask(previous)

    def test_cancel_does_not_install_or_hash_password(self):
        ask = Mock(side_effect=["", "192.0.2.8", "test.example", "", "нет"])
        secret = Mock(return_value="синтетический пароль")
        with patch.multiple(setup, check_platform=Mock(), reject_legacy=Mock(), preflight_new=Mock(),
                            read_existing=Mock(return_value=None), provision=Mock(), hash_admin_password=Mock()):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.main([], ask=ask, password_prompt=secret), 1)
            setup.reject_legacy.assert_called_once_with(install_dir=DEFAULT_INSTALL_DIR)
            setup.provision.assert_not_called()
            setup.hash_admin_password.assert_not_called()
            self.assertEqual(secret.call_count, 2)

    def test_legacy_rejection_precedes_password_and_provision(self):
        with patch.multiple(setup, check_platform=Mock(), provision=Mock(),
                            reject_legacy=Mock(side_effect=InstallPreflightError("fixture v4.2"))):
            secret = Mock()
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(setup.main([], ask=Mock(return_value=""), password_prompt=secret), 1)
            self.assertIn("fixture v4.2", stderr.getvalue())
            secret.assert_not_called()
            setup.provision.assert_not_called()

    @unittest.skipUnless(os.geteuid() == 0, "Маркер установки доступен только root")
    def test_unknown_install_marker_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            marker = target / "install.json"
            marker.write_text("[]", encoding="utf-8")
            with self.assertRaises(InstallPreflightError):
                setup.read_existing(target)
            self.assertEqual(marker.read_text(encoding="utf-8"), "[]")
