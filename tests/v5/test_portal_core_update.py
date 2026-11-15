"""Контракт подготовки обновления ядра без изменения live-дерева."""

import io
from pathlib import Path
import json
import os
import socket
from tempfile import TemporaryDirectory
import threading
from unittest import TestCase
from unittest.mock import Mock, patch

from tests.v5.test_core_update import artifact, publisher
from v5.core.maintenance.core_bundle import build
from v5.core.maintenance.portal_store import PortalUpdateStore, UpdateStoreError
from v5.core.maintenance.portal_rpc import PortalUpdateApplication, _job_active
from v5.core.maintenance.portal_apply import install_location, perform
from v5.core.packages.manifest import PackageError
from v5.core.release import SIGNATURE


class PortalCoreUpdateTests(TestCase):
    def test_apply_service_keeps_ability_to_verify_rpc_as_web_uid(self):
        unit = (Path(__file__).resolve().parents[2] /
                "v5/install/systemd/kvn-v5-core-apply@.service").read_text(encoding="utf-8")
        settings = {line.partition("=")[0] for line in unit.splitlines()
                    if line and not line.startswith(("#", "[")) and "=" in line}
        self.assertNotIn("User", settings)
        self.assertNotIn("Group", settings)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=full", unit)

    @classmethod
    def setUpClass(cls):
        cls.temporary = TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        _, key, cls.pin = publisher(cls.root)
        cls.source = artifact(cls.root / "release", key, cls.pin, "5.0.1")
        cls.bundle = cls.root / "update.tar"
        build(cls.source, cls.bundle)
        cls.raw = cls.bundle.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        temporary = TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.store_dir, self.live = self.work / "store", self.work / "live"
        self.store_dir.mkdir(mode=0o700)
        self.live.mkdir(mode=0o755)
        (self.live / "core-version").write_text("5.0.0\n")
        (self.live / "sentinel").write_text("не менять")
        self.checker = Mock()
        self.store = PortalUpdateStore(654, root=self.store_dir, pin=self.pin, live=self.live,
                                       clock=lambda: 2000, checker=self.checker)

    def test_signed_bundle_is_ready_before_apply_and_does_not_change_live(self):
        result = self.store.prepare(io.BytesIO(self.raw), len(self.raw))
        self.assertEqual((result["version"], result["status"]), ("5.0.1", "ready"))
        self.assertEqual(self.store.record(result["ticket"]), result)
        self.assertEqual(self.store.records(), [result])
        self.assertEqual((self.live / "sentinel").read_text(), "не менять")
        self.assertEqual((self.live / "core-version").read_text(), "5.0.0\n")
        self.assertEqual(self.checker.call_count, 1)
        self.store.discard(result["ticket"])
        self.assertEqual(self.store.records(), [])

    def test_bad_signature_and_version_are_rejected_before_ready(self):
        altered = self.work / "tampered"
        altered.mkdir()
        for path in self.source.iterdir():
            (altered / path.name).write_bytes(path.read_bytes())
        signature = altered / SIGNATURE
        data = signature.read_bytes()
        signature.write_bytes(bytes([data[0] ^ 1]) + data[1:])
        bad = self.work / "bad.tar"
        build(altered, bad)
        with self.assertRaises(PackageError):
            self.store.prepare(io.BytesIO(bad.read_bytes()), bad.stat().st_size)
        (self.live / "core-version").write_text("5.0.1\n")
        with self.assertRaisesRegex(UpdateStoreError, "core_version_not_newer"):
            self.store.prepare(io.BytesIO(self.raw), len(self.raw))
        self.assertEqual(self.store.records(), [])
        self.assertTrue((self.live / "sentinel").exists())

    def test_ticket_size_and_directory_validation(self):
        for ticket in ("../../etc", "0" * 63, "g" * 64, None):
            with self.subTest(ticket=ticket), self.assertRaises(UpdateStoreError):
                self.store.record(ticket)
        for size, data in ((0, b""), (2, b"x"), (1, b"xy")):
            with self.subTest(size=size), self.assertRaises(UpdateStoreError):
                self.store.prepare(io.BytesIO(data), size)
        self.assertEqual(self.store.records(), [])

    def test_queue_is_separate_and_worker_survives_request_lifetime(self):
        ready = self.store.prepare(io.BytesIO(self.raw), len(self.raw))
        launch = Mock()
        app = PortalUpdateApplication(654, self.store, launch=launch)
        request = {"version": 1, "method": "core.start", "params": {"ticket": ready["ticket"]}}
        result = app.dispatch(request, io.BytesIO())
        self.assertEqual(result["status"], "queued")
        launch.assert_called_once_with(ready["ticket"])
        self.assertEqual((self.live / "core-version").read_text(), "5.0.0\n")
        executor = Mock(return_value="5.0.1")
        with patch("v5.core.maintenance.portal_apply.audit.record"):
            self.assertTrue(perform(ready["ticket"], self.store, executor=executor))
        self.assertEqual(self.store.record(ready["ticket"])["status"], "applied")
        self.assertEqual(executor.call_count, 1)
        with self.assertRaisesRegex(UpdateStoreError, "core_not_ready"):
            app.dispatch(request, io.BytesIO())

    def test_failed_launch_or_worker_does_not_pretend_to_succeed(self):
        ready = self.store.prepare(io.BytesIO(self.raw), len(self.raw))
        request = {"version": 1, "method": "core.start", "params": {"ticket": ready["ticket"]}}
        app = PortalUpdateApplication(654, self.store, launch=Mock(side_effect=OSError("fixture")))
        with self.assertRaisesRegex(UpdateStoreError, "core_start_unavailable"):
            app.dispatch(request, io.BytesIO())
        self.assertEqual(self.store.record(ready["ticket"])["status"], "ready")
        app.launch = Mock()
        app.dispatch(request, io.BytesIO())
        with patch("v5.core.maintenance.portal_apply.audit.record"), self.assertRaises(RuntimeError):
            perform(ready["ticket"], self.store, executor=Mock(side_effect=RuntimeError("fixture")))
        self.assertEqual(self.store.record(ready["ticket"])["status"], "failed")
        self.assertEqual((self.live / "core-version").read_text(), "5.0.0\n")

    def test_install_location_is_root_owned_and_not_browser_controlled(self):
        directory = self.work / "configuration"
        directory.mkdir(mode=0o700)
        path = directory / "location.json"
        path.write_text(json.dumps({"format": 1, "path": "/root/custom"}))
        path.chmod(0o600)
        self.assertEqual(install_location(path), Path("/root/custom"))
        for value in ("/tmp/other", "/root/../etc", "/root/custom/nested"):
            path.write_text(json.dumps({"format": 1, "path": value}))
            with self.assertRaises(UpdateStoreError):
                install_location(path)
        path.unlink()
        with self.assertRaisesRegex(UpdateStoreError, "core_install_location_missing"):
            install_location(path)

    def test_real_socket_requires_web_uid_and_refuses_extra_body(self):
        def request(uid, raw):
            server, client = socket.socketpair()
            worker = threading.Thread(target=PortalUpdateApplication(uid, self.store).handle, args=(server,))
            try:
                worker.start()
                client.settimeout(5)
                client.sendall(raw)
                client.shutdown(socket.SHUT_WR)
                with client.makefile("rb") as response:
                    return json.loads(response.readline())
            finally:
                worker.join(5)
                server.close()
                client.close()
        body = b'{"version":1,"method":"core.status","params":{}}\n'
        self.assertEqual(request(os.getuid() + 1, body)["error"], "forbidden")
        self.assertTrue(request(os.getuid(), body)["ok"])
        self.assertEqual(request(os.getuid(), body + b"extra")["error"], "invalid_request")

    def test_interrupted_job_can_be_reconciled_only_after_manager_confirms_idle(self):
        ready = self.store.prepare(io.BytesIO(self.raw), len(self.raw))
        ticket = ready["ticket"]
        probe = Mock(return_value=False)
        app = PortalUpdateApplication(654, self.store, launch=Mock(), probe=probe)
        request = lambda method: {"version": 1, "method": method, "params": {"ticket": ticket}}
        app.dispatch(request("core.start"), io.BytesIO())
        with self.assertRaisesRegex(UpdateStoreError, "core_update_busy"):
            app.dispatch(request("core.reconcile"), io.BytesIO())
        self.store.clock = lambda: 2020
        probe.return_value = True
        with self.assertRaisesRegex(UpdateStoreError, "core_update_busy"):
            app.dispatch(request("core.reconcile"), io.BytesIO())
        probe.return_value = None
        with self.assertRaisesRegex(UpdateStoreError, "core_update_busy"):
            app.dispatch(request("core.reconcile"), io.BytesIO())
        probe.return_value = False
        self.assertEqual(app.dispatch(request("core.reconcile"), io.BytesIO())["status"], "failed")
        self.assertEqual(self.store.record(ticket)["status"], "failed")
        self.store.discard(ticket)
        self.assertEqual(self.store.records(), [])

    def test_manager_job_state_never_trusts_unrecognised_response(self):
        ticket = "a" * 64
        with patch("v5.core.maintenance.portal_rpc.subprocess.run") as run:
            run.return_value = Mock(returncode=0, stdout=b"LoadState=loaded\nActiveState=inactive\nJob=\n")
            self.assertIs(_job_active(ticket), False)
            run.return_value.stdout = b"LoadState=loaded\nActiveState=inactive\nJob=42 /unit/job/42\n"
            self.assertIs(_job_active(ticket), True)
            run.return_value.stdout = b"LoadState=loaded\nActiveState=unknown\nJob=\n"
            self.assertIsNone(_job_active(ticket))

    def test_ready_package_does_not_stay_ready_after_other_update(self):
        ready = self.store.prepare(io.BytesIO(self.raw), len(self.raw))
        (self.live / "core-version").write_text("5.0.1\n")
        app = PortalUpdateApplication(654, self.store, launch=Mock())
        status = app.dispatch({"version": 1, "method": "core.status", "params": {}}, io.BytesIO())
        self.assertEqual(status["records"][0]["status"], "obsolete")
        request = {"version": 1, "method": "core.start", "params": {"ticket": ready["ticket"]}}
        with self.assertRaisesRegex(UpdateStoreError, "core_version_not_newer"):
            app.dispatch(request, io.BytesIO())
        app.launch.assert_not_called()
