"""Подпись, отказ до переключения, устойчивый журнал и точный откат ядра."""

import io
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock

from tests.v5.test_packages import new_key
from v5.core.console import AGENT_UNIT, SOCKET_UNIT, WEB_SOCKET_UNIT, WEB_UNIT
from v5.core.maintenance.core_stage import stage_archive
from v5.core.maintenance.core_update import CoreUpdate, UpdateError
from v5.core.packages.manifest import PackageError, canonical_json
from v5.core.release import ARCHIVE, MANIFEST, SIGNATURE, UNIT_FILES, installed_version
from v5.tools.build_installer import build, sign_release

WEB = "kvn-v5-web.service"


def publisher(root):
    key = root / "key.pem"
    identity = new_key(key)
    pin = root / "pin.json"
    pin.write_bytes(canonical_json({"public_der": identity.public_der.hex(), "sha256": identity.fingerprint}))
    return identity, key, pin


def artifact(root, key, pin, version, *, break_web=False):
    root.mkdir()
    archive = root / ARCHIVE
    build(archive, pin, version=version)
    if break_web:
        candidate = root / "broken.tar.gz"
        with tarfile.open(archive, "r:gz") as source, tarfile.open(candidate, "w:gz") as target:
            for member in source:
                with source.extractfile(member) as content:
                    data = content.read()
                if member.name == "v5/portal/app.py":
                    data = b'raise RuntimeError("controlled test: web boot fails")\n'
                    member.size = len(data)
                target.addfile(member, io.BytesIO(data))
        candidate.replace(archive)
    sign_release(archive, key, pin, version)
    return root


class CoreUpdateTests(TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.live = self.root / "live"
        self.live.mkdir()
        (self.live / "core-version").write_text("5.0.0\n")
        self.marker = self.live / "old-only"
        self.marker.write_bytes(b"legacy runtime")
        self.units = self.root / "units"
        self.units.mkdir()
        self.old_unit = b"[Service]\n# original\n"
        for unit in UNIT_FILES:
            path = self.units / unit
            path.write_bytes(self.old_unit)
            path.chmod(0o644)
        self.identity, key, pin = publisher(self.root)
        self.source = artifact(self.root / "release", key, pin, "5.0.1")
        self.system = Mock()
        self.system.triggers.return_value = ("kvn-v5-package.socket",)
        self.updater = CoreUpdate(self.live, self.units, system=self.system)

    def test_untrusted_signature_and_changed_archive_never_touch_live(self):
        signature = (self.source / SIGNATURE).read_bytes()
        (self.source / SIGNATURE).write_bytes(bytes([signature[0] ^ 1]) + signature[1:])
        with self.assertRaises(PackageError):
            self.updater.apply(self.source, self.identity, 654)
        self.system.assert_not_called()
        (self.source / SIGNATURE).write_bytes(signature)
        raw = (self.source / ARCHIVE).read_bytes()
        (self.source / ARCHIVE).write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.updater.apply(self.source, self.identity, 654)
        self.assertTrue(self.marker.is_file())
        self.assertFalse(self.updater.pending.exists())
        self.system.validate.assert_not_called()
        self.system.quiesce.assert_not_called()

    def test_update_preserves_and_replays_previous_runtime_and_units(self):
        self.assertEqual(self.updater.apply(self.source, self.identity, 654), "5.0.1")
        self.assertEqual(installed_version(self.live), "5.0.1")
        self.assertIn(b"--web-uid 654", (self.units / "kvn-v5-agent.service").read_bytes())
        self.assertFalse(self.marker.exists())
        self.assertTrue((self.updater.previous / "tree/old-only").is_file())
        self.assertEqual(self.updater.previous.stat().st_mode & 0o777, 0o700)
        with self.assertRaisesRegex(UpdateError, "понижение"):
            self.updater.apply(self.source, self.identity, 654)
        self.updater.recover(previous=True)
        self.assertEqual(installed_version(self.live), "5.0.0")
        self.assertEqual((self.units / WEB).read_bytes(), self.old_unit)
        self.assertTrue(self.marker.is_file())

    def test_update_adds_optional_console_units_and_rollback_removes_them(self):
        new_units = (AGENT_UNIT, SOCKET_UNIT, WEB_SOCKET_UNIT, WEB_UNIT)
        for unit in new_units:
            (self.units / unit).unlink()
        self.assertEqual(self.updater.apply(self.source, self.identity, 654), "5.0.1")
        self.assertTrue(all((self.units / unit).is_file() for unit in new_units))
        self.updater.recover(previous=True)
        self.assertTrue(all(not (self.units / unit).exists() for unit in new_units))
        self.assertEqual(installed_version(self.live), "5.0.0")

    def test_rollback_preserves_explicitly_enabled_forwarding(self):
        unit = self.units / 'kvn-v5-forwarding.service'
        unit.unlink()
        self.assertEqual(self.updater.apply(self.source, self.identity, 654), '5.0.1')
        installed = unit.read_bytes()
        self.updater.recover(previous=True)
        self.assertEqual(unit.read_bytes(), installed)
        self.assertNotIn(b'-m v5.', installed)
        self.assertEqual(installed_version(self.live), '5.0.0')

    def test_failed_activation_rolls_back_and_unconfirmed_rollback_is_recoverable(self):
        self.system.activate.side_effect = [RuntimeError("candidate"), RuntimeError("temporary failure")]
        with self.assertRaisesRegex(UpdateError, "Откат не подтверждён"):
            self.updater.apply(self.source, self.identity, 654)
        self.assertEqual(installed_version(self.live), "5.0.0")
        self.assertTrue(self.updater.pending.is_dir())
        self.system.activate.side_effect = None
        self.updater.recover()
        self.assertFalse(self.updater.pending.exists())
        self.assertEqual((self.units / WEB).read_bytes(), self.old_unit)
        self.assertTrue(self.marker.is_file())

    def test_busy_worker_preserves_live_and_restores_triggers(self):
        self.system.quiesce.side_effect = RuntimeError("busy")
        with self.assertRaisesRegex(RuntimeError, "busy"):
            self.updater.apply(self.source, self.identity, 654)
        self.system.activate.assert_called_once_with(("kvn-v5-package.socket",))
        self.system.reload.assert_not_called()
        self.assertTrue(self.marker.is_file())
        self.assertFalse(self.updater.pending.exists())

    def test_archive_rejects_links_and_traversal_even_after_envelope_verification(self):
        for index, (name, kind) in enumerate((("v5/core/../escape.py", tarfile.REGTYPE),
                                              ("v5/core/agent.py", tarfile.SYMTYPE))):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                info = tarfile.TarInfo(name)
                info.type = kind
                archive.addfile(info, io.BytesIO())
            target = self.root / f"staged-{index}"
            target.mkdir()
            with self.assertRaisesRegex(ValueError, "небезопасная"):
                stage_archive(buffer.getvalue(), "5.0.1", target, 654)
        self.assertFalse((self.root / "escape.py").exists())
        self.assertTrue((self.source / MANIFEST).is_file())
