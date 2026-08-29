"""Архитектурные и security-контракты exports package."""

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.test_baseline_contracts import fixture_state, fixture_user
from tools import kvnctl
from tools.kvnlib.client_export import ClientExportPolicy as LegacyPolicy
from tools.kvnlib.export_bundle import build_user_export_bundle as legacy_bundle
from tools.kvnlib.exports import (
    ALLOWED_ARTIFACTS,
    ClientExportPolicy,
    ExportBundleError,
    RendererRegistry,
    build_user_export_bundle,
)

class ExportCompatibilityTests(unittest.TestCase):
    def test_legacy_imports_are_identity_compatible(self):
        self.assertIs(LegacyPolicy, ClientExportPolicy)
        self.assertIs(legacy_bundle, build_user_export_bundle)

    def test_renderer_registry_covers_cross_protocol_exports(self):
        registry = kvnctl.client_renderer_registry()
        self.assertIsInstance(registry, RendererRegistry)
        self.assertEqual(set(registry.names()), {"happ", "karing", "subscription", "openconnect", "amneziawg", "wireguard"})

    def test_ip_mode_changes_endpoint_but_not_reality_identity(self):
        state = fixture_state()
        user = fixture_user()
        domain = kvnctl.vless_reality_link(state, user, "public-key")
        state["client_export"] = {"address_mode": "public-ip", "public_ip": "8.8.4.4", "include_alternate": False}
        by_ip = kvnctl.vless_reality_link(state, user, "public-key")
        self.assertIn("@8.8.4.4:443", by_ip)
        for identity in ("sni=xhttp.example.test", "pbk=public-key", "sid=a3f9c1b82d4e6f90"):
            self.assertIn(identity, domain)
            self.assertIn(identity, by_ip)

class ExportBundleSecurityTests(unittest.TestCase):
    def test_bundle_is_memory_only_and_allowlisted(self):
        bundle = build_user_export_bundle(username="alice", address_mode="server", build_id="test", artifacts={"links.txt": b"safe"}, send_text="safe")
        with zipfile.ZipFile(io.BytesIO(bundle.archive)) as archive:
            members = set(archive.namelist())
        self.assertEqual(members, {"README.txt", "send.txt", "links.txt", "manifest.json"})
        self.assertTrue(members - {"README.txt", "send.txt", "manifest.json"} <= ALLOWED_ARTIFACTS)

    def test_cross_user_and_unsafe_filename_are_denied_without_secret_echo(self):
        secret = "NEVER_ECHO_THIS_SECRET"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alice = root / "alice"
            bob = root / "bob"
            alice.mkdir(); bob.mkdir()
            target = bob / "links.txt"
            target.write_text(secret, encoding="utf-8")
            with self.assertRaises(ExportBundleError) as cross:
                build_user_export_bundle(username="alice", address_mode="server", build_id="test", artifacts={"links.txt": target}, send_text="safe", source_root=alice)
            self.assertEqual(cross.exception.code, "cross_user")
            self.assertNotIn(secret, str(cross.exception))
        with self.assertRaises(ExportBundleError):
            build_user_export_bundle(username="alice", address_mode="server", build_id="test", artifacts={"../escape": b"x"}, send_text="safe")

if __name__ == "__main__":
    unittest.main()
