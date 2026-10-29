"""Локальные тесты переноса; все данные синтетические и не содержат production."""

import base64
import contextlib
import io
import os
import copy
import json
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from portal.agent import AgentApplication, ThreadingUnixServer
from portal.agent_client import AgentClient, AgentClientError
from portal.agent_protocol import ProtocolError
from portal.app.routes.migration import MAX_ARCHIVE_BYTES, issue_ticket, verify_ticket, save_upload, open_archive
from portal.agent_handlers.dispatcher import AgentDispatcher
from portal.agent_handlers.migration import MigrationHandler, _apply_outcome, cleanup_expired_archives
from portal.control.migration import MigrationPreviewError, MigrationPreviews
from tests.test_baseline_contracts import fixture_state, fixture_user
from tools.kvnlib.core.errors import StateRevisionConflict
from tools.kvnlib.core.io import JsonStateStore
from tools.kvnlib.core.migration import MigrationValidationError, parse_migration, plan_migration
from tools.kvnlib.core.state import state_revision
from tools.kvnlib.exports.migration import build_migration
from tools.kvnlib.runtime.migration import (
    MAX_ENCRYPTED_BYTES,
    MAX_PLAINTEXT_BYTES,
    MigrationCryptoError,
    commit_migration,
    decrypt_migration,
    encrypt_migration,
    restore_migration_backup,
)


class MigrationSchemaTests(unittest.TestCase):
    def setUp(self):
        private = base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("=")
        key = base64.b64encode(b"k" * 32).decode()
        self.state = fixture_state()
        self.state["users"] = [fixture_user()]
        self.state["portal"] = {"password_hash": "synthetic-portal-secret"}
        self.state["updates"] = {"token": "synthetic-github-secret"}
        self.state["reality"]["privateKey"] = private
        self.state["reality_tcp"]["privateKey"] = private
        for system in ("amneziawg", "wireguard"):
            self.state[system]["private_key"] = key
            self.state[system]["public_key"] = base64.b64encode(b"s" * 32).decode()
            for field in ("private_key", "public_key", "preshared_key"):
                self.state["users"][0][system][field] = key
            self.state["users"][0][system]["private_key"] = base64.b64encode(b"p" * 32).decode()
        self.state["amneziawg"]["v3"] = {"header_protection_key": key}

    def test_apply_outcome_distinguishes_fallback_and_failure(self):
        self.assertEqual(_apply_outcome({"outcome": "fallback", "reconcile_required": False}), ("fallback", False))
        self.assertEqual(_apply_outcome({"outcome": "applied", "failed": ["xray"]}), ("degraded", True))
        self.assertEqual(_apply_outcome({"outcome": "applied", "reconcile_required": True}), ("degraded", True))
        self.assertEqual(_apply_outcome(None), ("degraded", True))

    def test_file_ticket_binds_session_purpose_and_expiry(self):
        owner = "a" * 64
        file_id = "b" * 32
        ticket = issue_ticket("synthetic-proxy-secret", owner, file_id, "download", now=1000)
        self.assertEqual(verify_ticket("synthetic-proxy-secret", owner, ticket, "download", now=1100), file_id)
        for other_owner, purpose, timestamp in (("c" * 64, "download", 1100),
                                                 (owner, "upload", 1100),
                                                 (owner, "download", 1600)):
            with self.subTest(purpose=purpose, timestamp=timestamp), self.assertRaises(ValueError):
                verify_ticket("synthetic-proxy-secret", other_owner, ticket, purpose, now=timestamp)
        with self.assertRaises(ValueError):
            verify_ticket("synthetic-proxy-secret", owner, ticket[:-1] + "x", "download", now=1100)

    @unittest.skipUnless(os.name == "posix", "Безопасные файловые дескрипторы требуют Linux")
    def test_staged_upload_is_bounded_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "migration"
            identifier, size = save_upload(directory, io.BytesIO(b"synthetic-ciphertext"))
            self.assertEqual(size, len(b"synthetic-ciphertext"))
            with open_archive(directory, identifier) as stream:
                self.assertEqual(stream.read(), b"synthetic-ciphertext")
            with self.assertRaises(ValueError):
                save_upload(directory, io.BytesIO(b"x" * (MAX_ARCHIVE_BYTES + 1)))
            self.assertEqual(len(list(directory.iterdir())), 1)
            alias = "c" * 32
            (directory / (alias + ".kvn")).symlink_to(directory / (identifier + ".kvn"))
            with self.assertRaises(OSError):
                open_archive(directory, alias)

    @unittest.skipUnless(os.name == "posix", "Блокировки каталогов доступны в Linux")
    def test_staged_upload_serializes_writers_and_cleans_only_expired_files(self):
        import fcntl
        import time

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "migration"
            first, _ = save_upload(directory, io.BytesIO(b"old-ciphertext"))
            old = directory / (first + ".kvn")
            os.utime(old, (time.time() - 4000, time.time() - 4000))
            unrelated = directory / "keep.txt"
            unrelated.write_text("synthetic", encoding="utf-8")
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaises(ValueError):
                    save_upload(directory, io.BytesIO(b"concurrent"))
            finally:
                os.close(fd)
            current, _ = save_upload(directory, io.BytesIO(b"new-ciphertext"))
            self.assertFalse(old.exists())
            self.assertTrue(unrelated.exists())
            self.assertTrue((directory / (current + ".kvn")).is_file())

    @unittest.skipUnless(os.name == "posix", "Очистка работает только в Linux")
    def test_agent_cleanup_removes_only_expired_private_archives(self):
        import fcntl
        import time

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parent = root / "portal-data"
            parent.mkdir(mode=0o700)
            directory = parent / "migration"
            old_id, _ = save_upload(directory, io.BytesIO(b"old"))
            new_id, _ = save_upload(directory, io.BytesIO(b"new"))
            old = directory / (old_id + ".kvn")
            newer = directory / (new_id + ".kvn")
            os.utime(old, (time.time() - 4000, time.time() - 4000))
            link = directory / (("c" * 32) + ".kvn")
            link.symlink_to(old)
            outsider = directory / "keep.txt"
            outsider.write_text("keep", encoding="utf-8")
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(cleanup_expired_archives(root), 0)
                self.assertTrue(old.exists())
            finally:
                os.close(fd)
            self.assertEqual(cleanup_expired_archives(root), 1)
            self.assertFalse(old.exists())
            self.assertTrue(newer.exists())
            self.assertTrue(link.is_symlink())
            self.assertTrue(outsider.exists())

    def test_legacy_apply_reports_failed_docker_restart_as_degraded(self):
        from tools import kvnctl

        state = {"users": [], "services": {"amneziawg": {"enabled": False}, "wireguard": {"enabled": False}}}
        with mock.patch.object(kvnctl.shutil, "which", return_value="/usr/bin/docker"), \
             mock.patch.object(kvnctl, "_restart_docker_services", return_value=False):
            report = kvnctl.restart_services(True, before_state=state, after_state=state)
        self.assertEqual(report["outcome"], "failed")
        self.assertTrue(report["reconcile_required"])
        self.assertIn("xray", report["failed"])
        self.assertEqual(_apply_outcome(report), ("degraded", True))

    @unittest.skipUnless(os.name == "posix" and shutil.which("docker"), "Docker CLI доступен в Linux")
    def test_actual_docker_connection_failure_is_reported_without_touching_real_daemon(self):
        from tools import kvnctl

        disabled = {name: {"enabled": False} for name in ("nginx", "hysteria", "telemt", "mtg", "ocserv", "amneziawg", "wireguard")}
        state = {"users": [], "services": disabled}
        with tempfile.TemporaryDirectory(prefix="kvn-migration-failure-") as temporary:
            root = Path(temporary)
            (root / "docker-compose.yml").write_text("services:\n  xray:\n    image: fixture.invalid/xray\n", encoding="utf-8")
            absent_socket = "unix://" + str(root / "nonexistent.sock")
            with mock.patch.object(kvnctl, "ROOT", root), mock.patch.dict(os.environ, {"DOCKER_HOST": absent_socket}), \
                 mock.patch.object(kvnctl, "warn"):
                report = kvnctl.restart_services(True, before_state=state, after_state=state)
        self.assertEqual(report["outcome"], "failed")
        self.assertEqual(report["failed"], ["xray"])
        self.assertTrue(report["reconcile_required"])

    def test_exact_allowlist_roundtrip_excludes_portal_and_update_secrets(self):
        data = build_migration(self.state)
        archive = parse_migration(data)
        self.assertEqual(archive["users"], self.state["users"])
        self.assertEqual(archive["protocols"]["reality"]["privateKey"], self.state["reality"]["privateKey"])
        self.assertEqual(archive["protocols"]["amneziawg"]["v3"]["header_protection_key"], self.state["amneziawg"]["v3"]["header_protection_key"])
        self.assertNotIn(b"synthetic-portal-secret", data)
        self.assertNotIn(b"synthetic-github-secret", data)

    def test_selected_export_excludes_other_users_and_extra_telemt_accounts(self):
        second = copy.deepcopy(self.state["users"][0])
        second["name"] = "SecondFixture"
        second["uuid"] = "00000000-0000-4000-8000-000000000002"
        second["sub_token"] = "123456789abcdef0123456789abcdef0"
        for system, address in (("amneziawg", "10.66.66.3/32"), ("wireguard", "10.67.67.3/32")):
            second[system]["public_key"] = base64.b64encode(b"b" * 32).decode()
            second[system]["address"] = address
        self.state["users"].append(second)
        self.state["telemt"] = {"extra_users": {"OtherFixture": "0" * 32}}
        before = copy.deepcopy(self.state)
        result = parse_migration(build_migration(self.state, ["secondfixture"]))
        self.assertEqual(result["users"], [second])
        self.assertNotIn("extra_users", result["protocols"]["telemt"])
        self.assertEqual(self.state, before)
        for selection in ([], ["missing"], ["SecondFixture", "secondfixture"]):
            with self.subTest(selection=selection), self.assertRaises(MigrationValidationError):
                build_migration(self.state, selection)

    def test_reject_duplicate_json_version_unknown_fields_and_conflicts(self):
        data = build_migration(self.state)
        with self.assertRaises(MigrationValidationError):
            parse_migration(b'{"format":"x","format":"y"}')
        for change in ("version", "unknown", "name", "ip", "uuid", "token", "public_key"):
            archive = json.loads(data)
            if change == "version":
                archive["version"] = 99
            elif change == "unknown":
                archive["protocols"]["amneziawg"]["v3"]["unknown"] = "x"
            else:
                second = copy.deepcopy(archive["users"][0])
                second["name"] = "second"
                second["uuid"] = "00000000-0000-4000-8000-000000000002"
                second["sub_token"] = "123456789abcdef0123456789abcdef0"
                second["amneziawg"]["address"] = "10.66.66.3/32"
                second["wireguard"]["address"] = "10.67.67.3/32"
                second["amneziawg"]["public_key"] = base64.b64encode(b"a" * 32).decode()
                second["wireguard"]["public_key"] = base64.b64encode(b"b" * 32).decode()
                if change == "name":
                    second["name"] = archive["users"][0]["name"].lower()
                if change == "ip":
                    second["amneziawg"]["address"] = "10.66.66.2/24"
                if change == "uuid":
                    second["uuid"] = archive["users"][0]["uuid"]
                if change == "token":
                    second["sub_token"] = archive["users"][0]["sub_token"]
                if change == "public_key":
                    second["wireguard"]["public_key"] = archive["users"][0]["wireguard"]["public_key"]
                archive["users"].append(second)
            with self.subTest(change=change), self.assertRaises(MigrationValidationError):
                parse_migration(json.dumps(archive).encode())

    def test_unknown_nested_fields_and_bounds_are_rejected_before_export(self):
        self.state["users"][0]["unexpected"] = "not exported"
        with self.assertRaises(MigrationValidationError):
            build_migration(self.state)
        self.state["users"][0].pop("unexpected")
        self.state["users"][0]["description"] = "x" * 4097
        with self.assertRaises(MigrationValidationError):
            build_migration(self.state)

    def test_rejects_conflicting_telemt_names_and_server_peer_keys(self):
        self.state["telemt"] = {"extra_users": {self.state["users"][0]["name"].lower(): "0" * 32}}
        with self.assertRaises(MigrationValidationError):
            build_migration(self.state)
        self.state["telemt"] = {"extra_users": {}}
        self.state["users"][0]["wireguard"]["public_key"] = self.state["wireguard"]["public_key"]
        with self.assertRaises(MigrationValidationError):
            build_migration(self.state)

    def test_restore_preserves_endpoint_portal_and_merge_detects_address_conflicts(self):
        self.state["wireguard"]["network"] = "10.67.67.0/24"
        envelope = parse_migration(build_migration(self.state))
        target = {"server": "destination.example.test", "users": [],
                  "portal": {"password_hash": "target-only"}, "ocserv": {"enabled": False}}
        restored = plan_migration(target, envelope, "restore")
        self.assertEqual(restored["server"], target["server"])
        self.assertEqual(restored["portal"], target["portal"])
        self.assertFalse(restored["ocserv"]["enabled"])
        self.assertEqual(restored["users"], self.state["users"])
        with self.assertRaises(MigrationValidationError):
            plan_migration(restored, envelope, "restore")
        with self.assertRaises(MigrationValidationError):
            plan_migration(restored, envelope, "merge")

    def test_missing_identity_is_rejected_before_export_or_commit(self):
        self.state["wireguard"]["network"] = "10.67.67.0/24"
        envelope = parse_migration(build_migration(self.state))
        del self.state["users"][0]["sub_token"]
        with self.assertRaises(MigrationValidationError):
            build_migration(self.state)
        del envelope["protocols"]["reality"]["privateKey"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = {"server": "destination.example.test", "users": []}
            path = root / "users.json"
            original = json.dumps(target).encode()
            path.write_bytes(original)
            with self.assertRaises(MigrationValidationError):
                commit_migration(JsonStateStore(path), envelope, mode="restore", revision=state_revision(target),
                                 backup_dir=root / "backup", validate=lambda _: None)
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((root / "backup").exists())

    def test_real_prepare_accepts_prepared_source_without_rotating_identity(self):
        from tools import kvnctl

        self.state["wireguard"]["network"] = "10.67.67.0/24"
        self.state["wireguard"]["server_address"] = "10.67.67.1/24"
        self.state["portal"] = {"enabled": False}
        self.state.pop("updates")
        with mock.patch.object(kvnctl, "read_reality_private_key", side_effect=AssertionError("Чтение runtime запрещено")):
            kvnctl.prepare_state(self.state)
            envelope = parse_migration(build_migration(self.state))
            target = {"server": "target.example.test", "portal": {"enabled": False}, "users": []}
            candidate = plan_migration(target, envelope, "restore")
            dispatcher = SimpleNamespace(_control=lambda: SimpleNamespace(kvnctl=kvnctl))
            MigrationHandler(dispatcher)._validate(candidate)
            kvnctl._migration_validate(candidate)
        self.assertEqual(candidate["users"], self.state["users"])
        self.assertEqual(candidate["reality"], self.state["reality"])
        self.assertEqual(candidate["wireguard"]["private_key"], self.state["wireguard"]["private_key"])

    def test_merge_real_prepare_preserves_target_identity_and_existing_user(self):
        from tools import kvnctl

        self.state["wireguard"]["network"] = "10.67.67.0/24"
        self.state["wireguard"]["server_address"] = "10.67.67.1/24"
        self.state["portal"] = {"enabled": False}
        self.state.pop("updates")
        with mock.patch.object(kvnctl, "read_reality_private_key", side_effect=AssertionError("Чтение runtime запрещено")):
            kvnctl.prepare_state(self.state)
            target = copy.deepcopy(self.state)
            incoming = copy.deepcopy(self.state)
            user = incoming["users"][0]
            user["name"] = "SecondFixture"
            user["uuid"] = "00000000-0000-4000-8000-000000000002"
            user["sub_token"] = "123456789abcdef0123456789abcdef0"
            for system, address in (("amneziawg", "10.66.66.3/32"), ("wireguard", "10.67.67.3/32")):
                peer = user[system]
                peer["private_key"] = kvnctl.random_wg_private_key()
                peer["public_key"] = kvnctl.wg_public_key(peer["private_key"])
                peer["address"] = address
            envelope = parse_migration(build_migration(incoming))
            result = plan_migration(target, envelope, "merge")
            dispatcher = SimpleNamespace(_control=lambda: SimpleNamespace(kvnctl=kvnctl))
            MigrationHandler(dispatcher)._validate(result)
        self.assertEqual(result["users"][0], target["users"][0])
        self.assertEqual(result["users"][1], incoming["users"][0])
        for section in ("reality", "reality_tcp", "amneziawg", "wireguard", "mtg"):
            self.assertEqual(result[section], target[section])

    def test_self_steal_requires_target_site_identity_without_silent_rewrite(self):
        from tools import kvnctl

        self.state["wireguard"]["network"] = "10.67.67.0/24"
        self.state["wireguard"]["server_address"] = "10.67.67.1/24"
        self.state["portal"] = {"enabled": False}
        self.state.pop("updates")
        self.state["letsencrypt"] = {"enabled": True, "domain": "source.example.test"}
        self.state["sni_routes"]["reality-tcp"] = {"default": "source.example.test",
                                                      "aliases": ["source.example.test"],
                                                      "dest": "xray:2054",
                                                      "reality_mode": "self-steal"}
        with mock.patch.object(kvnctl, "read_reality_private_key", side_effect=AssertionError("Чтение runtime запрещено")):
            kvnctl.prepare_state(self.state)
            envelope = parse_migration(build_migration(self.state))
            target = {"server": "target.example.test", "portal": {"enabled": False}, "users": [],
                      "letsencrypt": {"enabled": True, "domain": "target.example.test"}}
            candidate = plan_migration(target, envelope, "restore")
            self.assertEqual(candidate["letsencrypt"], target["letsencrypt"])
            self.assertEqual(candidate["sni_routes"]["reality-tcp"]["default"], "source.example.test")
            dispatcher = SimpleNamespace(_control=lambda: SimpleNamespace(kvnctl=kvnctl))
            with self.assertRaises(ProtocolError):
                MigrationHandler(dispatcher)._validate(candidate)

    def test_transaction_backup_revision_and_failure_leave_original_unchanged(self):
        self.state["wireguard"]["network"] = "10.67.67.0/24"
        envelope = parse_migration(build_migration(self.state))
        target = {"server": "destination.example.test", "users": [], "portal": {"password_hash": "target-only"}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "users.json"
            original = (json.dumps(target) + "\n").encode()
            path.write_bytes(original)
            store = JsonStateStore(path)
            revision = state_revision(target)
            def reject(_state):
                raise ValueError("synthetic validation failure")
            with self.assertRaises(ValueError):
                commit_migration(store, envelope, mode="restore", revision=revision, backup_dir=root / "backup", validate=reject)
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((root / "backup").exists())
            with mock.patch("tools.kvnlib.runtime.migration._private_backup", side_effect=OSError("synthetic backup failure")):
                with self.assertRaises(OSError):
                    commit_migration(store, envelope, mode="restore", revision=revision,
                                     backup_dir=root / "backup", validate=lambda _: None)
            self.assertEqual(path.read_bytes(), original)
            self.assertFalse((root / "backup").exists())
            result = commit_migration(store, envelope, mode="restore", revision=revision,
                                      backup_dir=root / "backup", validate=lambda _: None)
            self.assertTrue(result.changed)
            backups = list((root / "backup").iterdir())
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            if os.name == "posix":
                self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
                self.assertEqual((root / "backup").stat().st_mode & 0o777, 0o700)
            changed = path.read_bytes()
            with self.assertRaises(StateRevisionConflict):
                commit_migration(store, envelope, mode="restore", revision=revision,
                                 backup_dir=root / "backup", validate=lambda _: None)
            self.assertEqual(path.read_bytes(), changed)
            self.assertEqual(len(list((root / "backup").iterdir())), 1)
            with self.assertRaises(StateRevisionConflict):
                restore_migration_backup(store, backup_dir=root / "backup", name=backups[0].name,
                                         revision=revision, validate=lambda _: None)
            self.assertEqual(path.read_bytes(), changed)
            restored = restore_migration_backup(store, backup_dir=root / "backup", name=backups[0].name,
                                                revision=result.after_revision, validate=lambda _: None)
            self.assertTrue(restored.changed)
            self.assertEqual(store.load(), target)
            self.assertEqual(len(list((root / "backup").iterdir())), 2)
            with self.assertRaises(MigrationCryptoError):
                restore_migration_backup(store, backup_dir=root / "backup", name="../users.json",
                                         revision=restored.after_revision, validate=lambda _: None)
            if os.name == "posix":
                link = root / "backup" / "migration-aaaaaaaa.json"
                link.symlink_to(path)
                before = path.read_bytes()
                with self.assertRaises(OSError):
                    restore_migration_backup(store, backup_dir=root / "backup", name=link.name,
                                             revision=restored.after_revision, validate=lambda _: None)
                self.assertEqual(path.read_bytes(), before)

    def test_preview_binds_owner_hash_revision_ttl_and_is_single_use(self):
        self.state["wireguard"]["network"] = "10.67.67.0/24"
        plaintext = build_migration(self.state)
        target = {"server": "destination.example.test", "users": []}
        fake_clock = [100.0]
        previews = MigrationPreviews(ttl=30, capacity=2, clock=lambda: fake_clock[0])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "users.json"
            path.write_text(json.dumps(target), encoding="utf-8")
            store = JsonStateStore(path)
            preview = previews.preview(store, owner="session-a", encrypted=b"encrypted-a", plaintext=plaintext,
                                       mode="restore", validate=lambda _: None)
            text = json.dumps(preview)
            for secret in (self.state["amneziawg"]["v3"]["header_protection_key"], self.state["reality"]["privateKey"], "fixture-password"):
                self.assertNotIn(secret, text)
            options = dict(store=store, identifier=preview["preview_id"], owner="session-a", encrypted=b"encrypted-a",
                           backup_dir=root / "backup", validate=lambda _: None, commit=commit_migration)
            with self.assertRaises(MigrationPreviewError):
                previews.commit(**{**options, "owner": "session-b"})
            with self.assertRaises(MigrationPreviewError):
                previews.commit(**{**options, "encrypted": b"changed"})
            with self.assertRaises(MigrationPreviewError):
                previews.cancel(identifier=preview["preview_id"], owner="session-b")
            self.assertTrue(previews.commit(**options).changed)
            with self.assertRaises(MigrationPreviewError):
                previews.commit(**options)
            path.write_text(json.dumps(target), encoding="utf-8")
            expiring = previews.preview(store, owner="session-a", encrypted=b"encrypted-b", plaintext=plaintext,
                                        mode="restore", validate=lambda _: None)
            previews.cancel(identifier=expiring["preview_id"], owner="session-a")
            with self.assertRaises(MigrationPreviewError):
                previews.cancel(identifier=expiring["preview_id"], owner="session-a")
            expiring = previews.preview(store, owner="session-a", encrypted=b"encrypted-b", plaintext=plaintext,
                                        mode="restore", validate=lambda _: None)
            fake_clock[0] += 31
            with self.assertRaises(MigrationPreviewError):
                previews.commit(**{**options, "identifier": expiring["preview_id"], "encrypted": b"encrypted-b"})

    @unittest.skipUnless(os.name == "posix", "Восстановление доступно на Linux")
    def test_cli_recovery_applies_restored_state_and_reports_reconcile_failure(self):
        from tools import kvnctl

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = {"server": "target.example.test", "users": []}
            changed = {"server": "target.example.test", "users": [{"name": "synthetic"}]}
            path = root / "users.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            backup_dir = root / "backups"
            backup_dir.mkdir(mode=0o700)
            backup = backup_dir / "migration-aaaaaaaa.json"
            backup.write_text(json.dumps(original), encoding="utf-8")
            backup.chmod(0o600)
            store = JsonStateStore(path)
            def local_restore(*args, **kwargs):
                kwargs["backup_dir"] = backup_dir
                return restore_migration_backup(*args, **kwargs)
            with mock.patch.object(kvnctl, "STATE_STORE", store), mock.patch.object(kvnctl, "validate_state_inputs"), \
                 mock.patch.object(kvnctl, "cmd_reconcile", side_effect=RuntimeError("synthetic failure")), \
                 mock.patch("tools.kvnlib.runtime.migration.restore_migration_backup", side_effect=local_restore), \
                 mock.patch.object(kvnctl.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(SystemExit, "восстановлена, но применение не завершено"):
                    kvnctl.cmd_migration_restore_backup(SimpleNamespace(name=backup.name))
            self.assertEqual(store.load(), original)
            path.write_text(json.dumps(changed), encoding="utf-8")
            with mock.patch.object(kvnctl, "STATE_STORE", store), mock.patch.object(kvnctl, "validate_state_inputs"), \
                 mock.patch.object(kvnctl, "cmd_reconcile") as reconcile, \
                 mock.patch("tools.kvnlib.runtime.migration.restore_migration_backup", side_effect=local_restore), \
                 mock.patch.object(kvnctl.os, "geteuid", return_value=0), mock.patch.object(kvnctl, "ok"):
                kvnctl.cmd_migration_restore_backup(SimpleNamespace(name=backup.name))
            reconcile.assert_called_once()
            self.assertEqual(store.load(), original)
    @unittest.skipUnless(os.name == "posix" and shutil.which("gpg"), "Нужен Linux и GnuPG")
    def test_cli_export_preview_import_uses_shared_plan(self):
        from tools import kvnctl

        self.state["wireguard"]["network"] = "10.67.67.0/24"
        with tempfile.TemporaryDirectory(prefix="kvn-cli-migration-") as temporary:
            root = Path(temporary)
            source_path = root / "source.json"
            target_path = root / "target.json"
            archive = root / "transfer.kvn"
            backup = root / "backups"
            source_path.write_text(json.dumps(self.state), encoding="utf-8")
            target = copy.deepcopy(self.state)
            target["users"] = []
            target["server"] = "target.example.test"
            target_path.write_text(json.dumps(target), encoding="utf-8")
            source, destination = JsonStateStore(source_path), JsonStateStore(target_path)
            phrase = "synthetic-test-phrase"
            def local_commit(*args, **kwargs):
                kwargs["backup_dir"] = backup
                return commit_migration(*args, **kwargs)
            with mock.patch.object(kvnctl.os, "geteuid", return_value=0), \
                 mock.patch.object(kvnctl, "STATE_STORE", source), \
                 mock.patch.object(kvnctl.getpass, "getpass", side_effect=[phrase, phrase]), \
                 mock.patch.object(kvnctl, "ok"):
                kvnctl.cmd_migration_transfer(SimpleNamespace(migration_action="export", archive=str(archive), user=None))
            self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
            expected = plan_migration(target, parse_migration(decrypt_migration(archive.read_bytes(), phrase)), "restore")
            with mock.patch.object(kvnctl, "STATE_STORE", destination), \
                 mock.patch.object(kvnctl, "_migration_validate"), \
                 mock.patch.object(kvnctl.getpass, "getpass", return_value=phrase), \
                 mock.patch("tools.kvnlib.runtime.migration.commit_migration", side_effect=local_commit), \
                 mock.patch("builtins.input", return_value="ДА"), mock.patch.object(kvnctl, "cmd_reconcile"), \
                 mock.patch.object(kvnctl, "ok"), contextlib.redirect_stdout(io.StringIO()):
                args = SimpleNamespace(migration_action="preview", archive=str(archive), mode="restore")
                kvnctl.cmd_migration_transfer(args)
                self.assertEqual(destination.load(), target)
                args.migration_action = "import"
                kvnctl.cmd_migration_transfer(args)
            self.assertEqual(destination.load(), expected)
            with mock.patch.object(kvnctl, "STATE_STORE", destination), \
                 mock.patch.object(kvnctl.getpass, "getpass", return_value="incorrect-synthetic-phrase"):
                with self.assertRaises(SystemExit):
                    kvnctl.cmd_migration_transfer(SimpleNamespace(migration_action="preview", archive=str(archive), mode="restore"))
            self.assertEqual(destination.load(), expected)
            link = root / "link.kvn"
            link.symlink_to(archive)
            with self.assertRaises(OSError):
                kvnctl._migration_read(link)


@unittest.skipUnless(os.name == "posix", "GnuPG/passphrase-fd требует Linux")
class MigrationCryptoTests(unittest.TestCase):
    def test_export_over_real_unix_socket_requires_agent_and_root_auth(self):
        source = MigrationSchemaTests()
        source.setUp()
        with tempfile.TemporaryDirectory(prefix="kvn-migration-socket-") as temporary:
            project = Path(temporary)
            (project / "portal-data").mkdir(mode=0o700)
            (project / "users.json").write_text(json.dumps(source.state), encoding="utf-8")
            control = SimpleNamespace(kvnctl=SimpleNamespace(STATE_STORE=JsonStateStore(project / "users.json")))
            dispatcher = AgentDispatcher(project, control=control)
            dispatcher._verify_root_password = lambda value: value == "synthetic-root-password"
            socket_path = project / "control.sock"
            server = ThreadingUnixServer(socket_path, AgentApplication("synthetic-agent-token", dispatcher))
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            credentials = {"session_owner": "a" * 64, "root_password": "synthetic-root-password",
                           "passphrase": "only-a-synthetic-passphrase"}
            try:
                with self.assertRaises(AgentClientError):
                    AgentClient(socket_path, "wrong-token").call("migration.export", credentials)
                client = AgentClient(socket_path, "synthetic-agent-token", timeout=30)
                with self.assertRaises(AgentClientError):
                    client.call("migration.export", {**credentials, "root_password": "wrong"})
                log = io.StringIO()
                with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                    result = client.call("migration.export", credentials)
                self.assertTrue(result["ok"])
                self.assertNotIn(credentials["passphrase"], json.dumps(result))
                self.assertNotIn(source.state["reality"]["privateKey"], json.dumps(result))
                for secret in (credentials["passphrase"], credentials["root_password"],
                               source.state["reality"]["privateKey"], source.state["amneziawg"]["v3"]["header_protection_key"]):
                    self.assertNotIn(secret, log.getvalue())
                directory = project / "portal-data" / "migration"
                self.assertTrue((directory / (result["archive_id"] + ".kvn")).is_file())
                import fcntl
                lock_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(AgentClientError) as blocked:
                        client.call("migration.export", credentials)
                    self.assertEqual(blocked.exception.code, "migration_storage_busy")
                finally:
                    os.close(lock_fd)
                for number in range(7):
                    (directory / (f"{number:032x}" + ".kvn")).write_bytes(b"ciphertext")
                with self.assertRaises(AgentClientError) as full:
                    client.call("migration.export", credentials)
                self.assertEqual(full.exception.code, "migration_storage_full")
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())

    def test_actual_gpg_aes256_roundtrip_and_authenticated_ciphertext(self):
        plaintext = b'{"format":"fixture","header_protection_key":"synthetic-only"}'
        password = "only-a-synthetic-passphrase"
        encrypted = encrypt_migration(plaintext, password)
        self.assertNotIn(b"header_protection_key", encrypted)
        self.assertEqual(decrypt_migration(encrypted, password), plaintext)
        with self.assertRaises(MigrationCryptoError):
            decrypt_migration(encrypted, "wrong-synthetic-passphrase")
        modified = bytearray(encrypted)
        modified[-10] ^= 1
        with self.assertRaises(MigrationCryptoError):
            decrypt_migration(bytes(modified), password)

    def test_bounds_and_unsafe_passphrases_fail_closed(self):
        for phrase in ("short", "bad\npassphrase", "n" * 257):
            with self.subTest(phrase_length=len(phrase)), self.assertRaises(MigrationCryptoError):
                encrypt_migration(b"{}", phrase)
        with self.assertRaises(MigrationCryptoError):
            encrypt_migration(b"x" * (MAX_PLAINTEXT_BYTES + 1), "only-a-synthetic-passphrase")
        with self.assertRaises(MigrationCryptoError):
            decrypt_migration(b"x" * (MAX_ENCRYPTED_BYTES + 1), "only-a-synthetic-passphrase")

    def test_client_zip_and_project_backup_are_not_migration_archives(self):
        import zipfile

        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("wireguard.conf", "synthetic client configuration")
        for archive in (content.getvalue(), b"synthetic project backup"):
            with self.subTest(kind=archive[:2]), self.assertRaises(MigrationCryptoError):
                decrypt_migration(archive, "only-a-synthetic-passphrase")

    def test_compressed_decompression_bomb_is_rejected(self):
        with tempfile.TemporaryDirectory() as home:
            os.chmod(home, 0o700)
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, b"only-a-synthetic-passphrase\n")
                os.close(write_fd)
                write_fd = -1
                result = subprocess.run(["gpg", "--no-options", "--homedir", home, "--batch", "--yes",
                                         "--pinentry-mode", "loopback", "--passphrase-fd", str(read_fd),
                                         "--symmetric", "--cipher-algo", "AES256", "--compress-algo", "zlib",
                                         "--s2k-count", "1024", "--output", "-"],
                                        input=b"x" * (MAX_PLAINTEXT_BYTES + 1), stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, pass_fds=(read_fd,), timeout=30, check=True)
                self.assertLess(len(result.stdout), MAX_ENCRYPTED_BYTES)
                with self.assertRaises(MigrationCryptoError):
                    decrypt_migration(result.stdout, "only-a-synthetic-passphrase")
            finally:
                if write_fd >= 0:
                    os.close(write_fd)
                os.close(read_fd)
                subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3, check=False)

    def test_encrypted_archive_moves_between_independent_synthetic_servers(self):
        source = MigrationSchemaTests()
        source.setUp()
        source.state["wireguard"]["network"] = "10.67.67.0/24"
        source.state["amneziawg"]["protocol_version"] = "3.1"
        archive = encrypt_migration(build_migration(source.state), "only-a-synthetic-passphrase")
        envelope = parse_migration(decrypt_migration(archive, "only-a-synthetic-passphrase"))
        target = {"server": "destination.example.test", "users": [], "portal": {"login": "target"}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "users.json"
            path.write_text(json.dumps(target), encoding="utf-8")
            commit_migration(JsonStateStore(path), envelope, mode="restore", revision=state_revision(target),
                             backup_dir=root / "backup", validate=lambda _: None)
            result = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result["server"], target["server"])
        self.assertEqual(result["portal"], target["portal"])
        self.assertEqual(result["users"], source.state["users"])
        for system in ("reality", "reality_tcp", "amneziawg", "wireguard", "sni_routes", "telemt", "mtg", "ocserv"):
            if system in source.state:
                self.assertEqual(result[system], source.state[system])

    def test_imported_state_renders_in_isolated_deploy_tree(self):
        from tools import kvnctl

        fixture = MigrationSchemaTests()
        fixture.setUp()
        fixture.state["wireguard"]["network"] = "10.67.67.0/24"
        fixture.state["wireguard"]["server_address"] = "10.67.67.1/24"
        fixture.state["portal"] = {"enabled": False}
        fixture.state.pop("updates")
        with mock.patch.object(kvnctl, "read_reality_private_key", side_effect=AssertionError("Чтение runtime запрещено")):
            kvnctl.prepare_state(fixture.state)
        password = "only-a-synthetic-passphrase"
        ciphertext = encrypt_migration(build_migration(fixture.state), password)
        envelope = parse_migration(decrypt_migration(ciphertext, password))
        target = {"server": "target.example.test", "portal": {"enabled": False}, "users": []}
        imported = plan_migration(target, envelope, "restore")
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix="kvn-migration-render-") as temporary:
            directory = Path(temporary)
            archive = directory / "isolated-deploy.tar.gz"
            subprocess.run(["bash", "tools/build-deploy.sh", str(archive)], cwd=repository,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=120)
            with tarfile.open(archive) as bundle:
                bundle.extractall(directory, filter="data")
            project = directory / "deploy"
            (project / "users.json").write_text(json.dumps(imported), encoding="utf-8")
            result = subprocess.run(["python3", "tools/kvnctl.py", "render"], cwd=project,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            self.assertEqual(result.returncode, 0, "Генерация тестового проекта завершилась ошибкой.")
            saved = json.loads((project / "users.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["users"], imported["users"])
            self.assertEqual(saved["reality"], imported["reality"])
            self.assertTrue((project / "xray" / "config.json").is_file())
            self.assertTrue((project / "amneziawg" / "awg0.conf").is_file())
            self.assertTrue((project / "wireguard" / "wg0.conf").is_file())
            xray = (project / "xray" / "config.json").read_text(encoding="utf-8")
            self.assertIn(imported["users"][0]["uuid"], xray)
            self.assertIn(imported["reality"]["privateKey"], xray)
            for system, filename in (("amneziawg", "awg0.conf"), ("wireguard", "wg0.conf")):
                rendered = (project / system / filename).read_text(encoding="utf-8")
                self.assertIn(imported[system]["private_key"], rendered)
                self.assertIn(imported["users"][0][system]["public_key"], rendered)
                client = (project / "clients" / imported["users"][0]["name"] / (system + ".conf")).read_text(encoding="utf-8")
                self.assertIn(imported["users"][0][system]["private_key"], client)
                self.assertIn(imported[system]["public_key"], client)
                self.assertIn("target.example.test", client)
            links = (project / "clients" / imported["users"][0]["name"] / "links.txt").read_text(encoding="utf-8")
            self.assertIn(imported["users"][0]["uuid"], links)
            self.assertIn("target.example.test", links)
            if os.environ.get("KVN_MIGRATION_WG_E2E") == "1":
                script = ('set -e; ip link add wg0 type wireguard; '
                          'wg syncconf wg0 <(wg-quick strip "$1"); '
                          'test "$(wg show wg0 peers | wc -l)" -eq 1')
                checked = subprocess.run(["unshare", "--net", "--", "bash", "-c", script, "--",
                                          str(project / "wireguard" / "wg0.conf")],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                self.assertEqual(checked.returncode, 0, "Изолированное применение WireGuard не прошло.")
            if os.environ.get("KVN_MIGRATION_DOCKER_E2E") == "1":
                certs = subprocess.run(["python3", "tools/kvnctl.py", "render", "--certs"], cwd=project,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
                self.assertEqual(certs.returncode, 0, "Не удалось создать синтетический сертификат.")
                name = "kvn-migration-e2e-" + os.urandom(6).hex()
                argv = ["docker", "run", "-d", "--name", name, "--network", "none",
                        "--mount", f"type=bind,src={project / 'xray/config.json'},dst=/etc/xray/config.json,readonly",
                        "--mount", f"type=bind,src={project / 'certs'},dst=/etc/xray/certs,readonly",
                        "ghcr.io/xtls/xray-core:26.3.27", "run", "-c", "/etc/xray/config.json"]
                try:
                    started = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                    self.assertEqual(started.returncode, 0, "Не удалось запустить изолированный тестовый Xray.")
                    import time
                    time.sleep(2)
                    status = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", name],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
                    self.assertEqual(status.stdout.strip(), b"true", "Тестовый Xray не остался запущенным.")
                finally:
                    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=30, check=False)

    def test_agent_rpc_export_preview_commit_and_degraded_apply(self):
        source = MigrationSchemaTests()
        source.setUp()
        source.state["wireguard"]["network"] = "10.67.67.0/24"
        target = {"server": "destination.example.test", "users": []}
        password = "only-a-synthetic-passphrase"
        owner = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            applications = []
            for name, state in (("source", source.state), ("target", target)):
                project = root / name
                project.mkdir()
                (project / "portal-data").mkdir(mode=0o700)
                (project / "users.json").write_text(json.dumps(state), encoding="utf-8")
                kvnctl = SimpleNamespace(STATE_STORE=JsonStateStore(project / "users.json"),
                                         prepare_state=lambda _: None, render_all=lambda _: object(),
                                         restart_services=lambda *args, **kwargs: {"outcome": "failed", "reconcile_required": True})
                control = SimpleNamespace(kvnctl=kvnctl, _state_host_sync_services=lambda _: set())
                dispatcher = AgentDispatcher(project, control=control)
                dispatcher._verify_root_password = lambda value: value == "synthetic-root-password"
                applications.append(AgentApplication("synthetic-agent-token", dispatcher))

            def call(application, method, params):
                request = {"version": 1, "id": "fixture", "secret": "synthetic-agent-token", "method": method, "params": params}
                return json.loads(application.handle_line((json.dumps(request) + "\n").encode()))

            credentials = {"session_owner": owner, "root_password": "synthetic-root-password"}
            exported = call(applications[0], "migration.export", {**credentials, "passphrase": password})
            self.assertTrue(exported["ok"])
            archive_id = exported["data"]["archive_id"]
            encrypted = (root / "source" / "portal-data" / "migration" / (archive_id + ".kvn")).read_bytes()
            self.assertNotIn(source.state["reality"]["privateKey"].encode(), encrypted)
            target_directory = root / "target" / "portal-data" / "migration"
            target_directory.mkdir(mode=0o700)
            (target_directory / (archive_id + ".kvn")).write_bytes(encrypted)
            preview = call(applications[1], "migration.preview", {**credentials, "archive_id": archive_id, "passphrase": password, "mode": "restore"})
            self.assertTrue(preview["ok"])
            for secret in (password, credentials["root_password"], source.state["reality"]["privateKey"], source.state["amneziawg"]["v3"]["header_protection_key"]):
                self.assertNotIn(secret, json.dumps(preview))
            commit_params = {**credentials, "archive_id": archive_id, "preview_id": preview["data"]["preview_id"]}
            def local_commit(*args, **kwargs):
                kwargs["backup_dir"] = root / "backups"
                return commit_migration(*args, **kwargs)
            with mock.patch("portal.agent_handlers.migration.commit_migration", side_effect=local_commit):
                committed = call(applications[1], "migration.commit", commit_params)
                replay = call(applications[1], "migration.commit", commit_params)
            self.assertTrue(committed["ok"])
            self.assertEqual(committed["data"]["outcome"], "degraded")
            self.assertTrue(committed["data"]["reconcile_required"])
            self.assertFalse(replay["ok"])
            self.assertEqual(len(list((root / "backups").iterdir())), 1)
            expected = plan_migration(target, parse_migration(decrypt_migration(encrypted, password)), "restore")
            self.assertEqual(json.loads((root / "target" / "users.json").read_text()), expected)
            for mode in ("restore", "merge"):
                conflict = call(applications[1], "migration.preview", {**credentials, "archive_id": archive_id,
                                                                        "passphrase": password, "mode": mode})
                self.assertFalse(conflict["ok"])
                self.assertEqual(conflict["error"]["code"], "migration_conflict")
                self.assertEqual(json.loads((root / "target" / "users.json").read_text())["users"], source.state["users"])
            backup_name = next((root / "backups").iterdir()).name
            store = applications[1].dispatcher._control().kvnctl.STATE_STORE
            recovery = restore_migration_backup(store, backup_dir=root / "backups", name=backup_name,
                                                revision=committed["data"]["revision"], validate=lambda _: None)
            self.assertTrue(recovery.changed)
            self.assertEqual(store.load(), target)
            self.assertEqual(len(list((root / "backups").iterdir())), 2)

            preview2 = call(applications[1], "migration.preview", {**credentials, "archive_id": archive_id, "passphrase": password, "mode": "restore"})
            self.assertTrue(preview2["ok"])
            archive_file = target_directory / (archive_id + ".kvn")
            archive_file.write_bytes(encrypted + b"tampered")
            before = (root / "target" / "users.json").read_bytes()
            with mock.patch("portal.agent_handlers.migration.commit_migration", side_effect=local_commit):
                rejected = call(applications[1], "migration.commit", {**credentials, "archive_id": archive_id, "preview_id": preview2["data"]["preview_id"]})
            self.assertFalse(rejected["ok"])
            self.assertEqual((root / "target" / "users.json").read_bytes(), before)
            self.assertEqual(len(list((root / "backups").iterdir())), 2)

            denied = call(applications[0], "migration.export", {**credentials, "root_password": "wrong", "passphrase": password})
            self.assertFalse(denied["ok"])
            self.assertNotIn(password, json.dumps(denied))
            symlink_id = "b" * 32
            (target_directory / (symlink_id + ".kvn")).symlink_to(root / "target" / "users.json")
            bad = call(applications[1], "migration.preview", {**credentials, "archive_id": symlink_id, "passphrase": password, "mode": "restore"})
            self.assertFalse(bad["ok"])
            fifo_id = "c" * 32
            os.mkfifo(target_directory / (fifo_id + ".kvn"))
            bad = call(applications[1], "migration.preview", {**credentials, "archive_id": fifo_id, "passphrase": password, "mode": "restore"})
            self.assertFalse(bad["ok"])


if __name__ == "__main__":
    unittest.main()
