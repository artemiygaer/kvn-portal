"""Безопасность on-demand экспорта пользовательских конфигураций."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from portal.agent import AgentDispatcher
from portal.agent_protocol import ProtocolError, RpcRequest
from portal.control import KvnControl
from tests.test_baseline_contracts import fixture_state, fixture_user
from tools.kvnlib.export_bundle import (
    MAX_FILE_BYTES,
    ExportBundleError,
    build_user_export_bundle,
)


ROOT = Path(__file__).resolve().parents[1]


class ExportBundleTests(unittest.TestCase):
    def test_zip_is_deterministic_allowlisted_and_manifest_is_redacted(self):
        artifacts = {
            "links.txt": b"vless://client-secret",
            "wireguard.conf": b"[Interface]\nPrivateKey = client-only\n",
        }
        kwargs = {
            "username": "Alice",
            "address_mode": "public-ip",
            "build_id": "20260724-test",
            "send_text": "Передайте эти данные пользователю.",
            "artifacts": artifacts,
        }
        first = build_user_export_bundle(**kwargs)
        second = build_user_export_bundle(**kwargs)
        self.assertEqual(first.archive, second.archive)

        with zipfile.ZipFile(io.BytesIO(first.archive)) as archive:
            names = archive.namelist()
            self.assertEqual(
                names,
                [
                    "README.txt",
                    "send.txt",
                    "links.txt",
                    "wireguard.conf",
                    "manifest.json",
                ],
            )
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["build"], "20260724-test")
            self.assertEqual(manifest["user"], "Alice")
            self.assertEqual(manifest["address_mode"], "public-ip")
            for item in manifest["files"]:
                payload = archive.read(item["name"])
                self.assertEqual(item["size"], len(payload))
                self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest())

        serialized = json.dumps(first.manifest, ensure_ascii=False)
        for forbidden in (
            "users.json", "server_private", "root_password",
            "portal.db", ".env", "agent.secret",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_negative_matrix_rejects_unknown_traversal_and_oversize(self):
        cases = {
            "../users.json": "file_not_allowed",
            "server.key": "file_not_allowed",
            "unknown.txt": "file_not_allowed",
        }
        for filename, expected_code in cases.items():
            with self.subTest(filename=filename):
                with self.assertRaises(ExportBundleError) as caught:
                    build_user_export_bundle(
                        username="Alice",
                        address_mode="server",
                        build_id="test",
                        send_text="x",
                        artifacts={filename: b"x"},
                    )
                self.assertEqual(caught.exception.code, expected_code)

        with self.assertRaises(ExportBundleError) as caught:
            build_user_export_bundle(
                username="Alice",
                address_mode="server",
                build_id="test",
                send_text="x",
                artifacts={"links.txt": b"x" * (MAX_FILE_BYTES + 1)},
            )
        self.assertEqual(caught.exception.code, "file_too_large")

    def test_path_sources_reject_symlink_and_cross_user(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            alice = root / "Alice"
            bob = root / "Bob"
            alice.mkdir()
            bob.mkdir()
            own = alice / "links.txt"
            other = bob / "links.txt"
            own.write_text("alice", encoding="utf-8")
            other.write_text("bob", encoding="utf-8")

            with self.assertRaises(ExportBundleError) as caught:
                build_user_export_bundle(
                    username="Alice",
                    address_mode="server",
                    build_id="test",
                    send_text="x",
                    artifacts={"links.txt": other},
                    source_root=alice,
                )
            self.assertEqual(caught.exception.code, "cross_user")

            link = alice / "wireguard.conf"
            try:
                link.symlink_to(own)
            except OSError:
                self.skipTest("Создание symlink недоступно в текущей Windows-среде.")
            with self.assertRaises(ExportBundleError) as caught:
                build_user_export_bundle(
                    username="Alice",
                    address_mode="server",
                    build_id="test",
                    send_text="x",
                    artifacts={"wireguard.conf": link},
                    source_root=alice,
                )
            self.assertEqual(caught.exception.code, "unsafe_source")

    def test_in_memory_build_leaves_runtime_directories_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            protected = [
                root / "clients",
                root / "nginx" / "web",
                root / "portal-data" / "updates",
                root / "logs",
            ]
            for directory in protected:
                directory.mkdir(parents=True)
                (directory / "sentinel").write_text("keep", encoding="utf-8")
            before = sorted(
                path.relative_to(root).as_posix()
                for path in root.rglob("*") if path.is_file()
            )
            build_user_export_bundle(
                username="Alice",
                address_mode="server",
                build_id="test",
                send_text="x",
                artifacts={"links.txt": b"vless://fixture"},
            )
            after = sorted(
                path.relative_to(root).as_posix()
                for path in root.rglob("*") if path.is_file()
            )
            self.assertEqual(after, before)
            self.assertFalse(list(root.rglob("*.zip")))


class _ExportControl:
    def __init__(self):
        self.calls = []

    def user_export(self, name, address_mode):
        self.calls.append((name, address_mode))
        return {"ok": True}


class ExportRpcTests(unittest.TestCase):
    def setUp(self):
        self.control = _ExportControl()
        self.dispatcher = AgentDispatcher(
            ROOT,
            control=self.control,
        )

    def dispatch(self, params):
        return self.dispatcher.dispatch(
            RpcRequest("export-test", "user.export", params),
        )

    def test_exact_rpc_contract_and_invalid_params_precede_control(self):
        self.assertEqual(
            self.dispatch({"name": "Alice", "address_mode": "server"}),
            {"ok": True},
        )
        self.assertEqual(self.control.calls, [("Alice", "server")])

        invalid = [
            {},
            {"name": "Alice"},
            {"name": "Alice", "address_mode": "dns"},
            {"name": 7, "address_mode": "server"},
            {"name": "../Alice", "address_mode": "server"},
            {"name": "Alice", "address_mode": "server", "extra": True},
        ]
        for params in invalid:
            with self.subTest(params=params):
                before = list(self.control.calls)
                with self.assertRaises(ProtocolError) as caught:
                    self.dispatch(params)
                self.assertEqual(caught.exception.code, "invalid_params")
                self.assertEqual(self.control.calls, before)

    def test_control_generates_public_ip_bundle_without_persisting_archive(self):
        state = fixture_state()
        state["users"] = [fixture_user()]
        state["client_export"] = {
            "address_mode": "server",
            "public_ip": "8.8.4.4",
            "include_alternate": False,
        }
        control = KvnControl(ROOT)
        with (
            mock.patch.object(control.kvnctl.STATE_STORE, "load", return_value=state),
            mock.patch.object(
                control.kvnctl,
                "ensure_reality_public_key",
                return_value=("fixture-reality-public", False),
            ),
            mock.patch.object(control.kvnctl, "certificate_sha256_hex", return_value=""),
            mock.patch.object(control.kvnctl, "certificate_pin_sha256", return_value=""),
            mock.patch.object(
                control.kvnctl, "certificate_sans", return_value=["8.8.4.4"],
            ),
        ):
            result = control.user_export("AuditFixture", "public-ip")

        self.assertEqual(result["archive_content_type"], "application/zip")
        self.assertEqual(result["address_mode"], "public-ip")
        archive = io.BytesIO(base64.b64decode(result["archive_base64"]))
        with zipfile.ZipFile(archive) as payload:
            links = payload.read("links.txt").decode("utf-8")
            self.assertIn("8.8.4.4", links)
            self.assertNotIn("vpn.example.test", links)
        self.assertFalse(list(ROOT.glob("kvn-AuditFixture-*.zip")))


if __name__ == "__main__":
    unittest.main()
