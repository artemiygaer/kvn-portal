"""Контракты модульного release pipeline и перехода v3→v4."""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import tools.deploy_archive as deploy_validation
from tools.release.artifact import inspect_update_artifact
from tools.release.migrations import (
    LEGACY_BOOTSTRAP_FILES,
    MigrationError,
    extract_legacy_bootstrap,
    plan_migration,
    portal_upgrade_steps,
)


ROOT = Path(__file__).resolve().parents[1]


def add_file(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))


class ReleasePipelineArchitectureTests(unittest.TestCase):
    def test_safe_deploy_templates_are_versioned_for_clean_clone_build(self):
        import json
        import subprocess
        required = (
            "packaging/deploy-template/users.json",
            "packaging/deploy-template/portal-data/.gitkeep",
            "packaging/deploy-template/portal-runtime/.gitkeep",
        )
        state = json.loads((ROOT / required[0]).read_text(encoding="utf-8"))
        self.assertEqual(state["server"], "YOUR_SERVER_IP")
        self.assertEqual(state["users"], [])
        self.assertEqual(state["portal"], {"enabled": False})
        if (ROOT / ".git").exists():
            result = subprocess.run(["git", "-c", f"safe.directory={ROOT}", "ls-files", "--error-unmatch", *required],
                                    cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/relay", (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())

    def test_portal_upgrade_uses_explicit_compatibility_bridge(self):
        self.assertEqual(portal_upgrade_steps("v4.1.1", "v4.2.0"), ("v4.1.2", "v4.2.0"))
        self.assertEqual(portal_upgrade_steps("v4.1.1", "v4.1.2"), ("v4.1.2",))
        self.assertEqual(portal_upgrade_steps("v4.1.2", "v4.2.0"), ("v4.2.0",))
        self.assertEqual(portal_upgrade_steps("v4.2.0", "v4.2.0"), ())
        with self.assertRaises(MigrationError):
            portal_upgrade_steps("v4.1.1", "v4.3.0")

    def test_release_facades_are_small_and_package_is_canonical(self):
        for relative in (
            "tools/build_deploy_tree.py",
            "tools/release_archive.py",
            "tools/publication_manifest.py",
        ):
            self.assertLessEqual(len((ROOT / relative).read_text(encoding="utf-8").splitlines()), 16)
        canonical = (ROOT / "tools/canonical-files.txt").read_text(encoding="utf-8").splitlines()
        required = {
            "tools/release/__init__.py",
            "tools/release/artifact.py",
            "tools/release/canonical.py",
            "tools/release/deploy_archive.py",
            "tools/release/full_archive.py",
            "tools/release/migrations.py",
            "tools/release/publication.py",
        }
        self.assertTrue(required.issubset(canonical))
        self.assertTrue((ROOT / "tools/bootstrap-v4.sh").is_file())
        self.assertNotIn("tools/bootstrap-v4.sh", canonical)

    def test_v3_to_v4_matrix_supports_both_artifacts_and_entrypoints(self):
        matrix = {
            (artifact, entrypoint): plan_migration("v3.1.3", artifact, entrypoint)
            for artifact in ("source", "full")
            for entrypoint in ("cli", "portal")
        }
        self.assertEqual(len(matrix), 4)
        self.assertTrue(all(plan.bootstrap_required for plan in matrix.values()))
        self.assertTrue(all(
            plan.external_bridge_required is (entrypoint == "portal")
            for (_artifact, entrypoint), plan in matrix.items()
        ))
        with self.assertRaises(MigrationError):
            plan_migration("v2.9.0", "source", "cli")

    def test_legacy_bootstrap_extracts_only_allowlisted_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "kvn-vpn-deploy.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for relative in LEGACY_BOOTSTRAP_FILES:
                    add_file(archive, f"deploy/{relative}", relative.encode("utf-8"))
                add_file(archive, "deploy/users.json", b'{"password":"secret"}')
            extracted = extract_legacy_bootstrap(archive_path, root / "bootstrap")
            self.assertEqual(
                {path.relative_to(root / "bootstrap").as_posix() for path in extracted},
                set(LEGACY_BOOTSTRAP_FILES),
            )
            self.assertFalse((root / "bootstrap/users.json").exists())

    def test_portal_and_cli_share_artifact_inspection_contract(self):
        path = Path("kvn-vpn-deploy.tar.gz")
        metadata = {"name": path.name, "size": 2048, "sha256": "a" * 64, "member_count": 200}
        with mock.patch("tools.release.artifact.inspect_archive", return_value=metadata) as inspect:
            cli_result = inspect_update_artifact(path, "deploy")
            portal_result = inspect_update_artifact(path, "deploy")
        self.assertEqual(cli_result, portal_result)
        self.assertEqual(inspect.call_count, 2)
        self.assertEqual(cli_result["archive_kind"], "deploy")

    def test_update_uses_module_with_legacy_fallback_before_mutation(self):
        update = (ROOT / "update.sh").read_text(encoding="utf-8")
        module_call = "python3 -m tools.release.migrations extract-bootstrap"
        self.assertIn(module_call, update)
        self.assertIn("Legacy fallback", update)
        self.assertLess(update.index(module_call), update.index("SOURCES_INSTALLED=1"))
        self.assertLess(update.index("INSPECTOR="), update.index("SOURCES_INSTALLED=1"))


class CompatibilityBridgeArchiveTests(unittest.TestCase):
    """Новые имена разрешает trusted policy хоста, а не содержимое архива."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        current = (ROOT / "tools/canonical-files.txt").read_text(encoding="utf-8").splitlines()
        reverse = {new: old for old, new in deploy_validation.V420_WHEEL_REPLACEMENTS.items()}
        self.legacy = [reverse.get(path, path) for path in current
                       if path not in deploy_validation.V420_NEW_SOURCE_FILES]
        self.schema_path = self.root / "trusted-canonical.txt"
        self.schema_path.write_text("\n".join(self.legacy) + "\n", encoding="utf-8")
        patcher = mock.patch.object(deploy_validation, "CANONICAL_SCHEMA_PATH", self.schema_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.forward = deploy_validation.forward_v420_schema(self.legacy)
        self.assertIsNotNone(self.forward)

    def make_archive(self, manifest=None, *, version="v4.2.0", embedded=None, extra="", symlink=""):
        manifest = self.forward if manifest is None else manifest
        manifest_text = "\n".join(manifest) + "\n"
        schema_text = manifest_text if embedded is None else embedded
        path = self.root / "update.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            add_file(archive, "deploy/.kvn-canonical-files", manifest_text.encode())
            for name in manifest:
                payload = b"source\n"
                if name == "VERSION":
                    payload = (version + "\n").encode()
                elif name == "tools/canonical-files.txt":
                    payload = schema_text.encode()
                elif name == "portal/Dockerfile":
                    payload += os.urandom(2048)
                add_file(archive, "deploy/" + name, payload)
            add_file(archive, "deploy/users.json",
                     b'{"server":"YOUR_SERVER_IP","users":[],"portal":{"enabled":false}}')
            if extra:
                add_file(archive, "deploy/" + extra, b"unexpected")
            if symlink:
                member = tarfile.TarInfo("deploy/" + symlink)
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/shadow"
                archive.addfile(member)
        return path

    def test_exact_approved_forward_inventory_is_accepted_without_execution(self):
        self.assertEqual(len(self.legacy), 214)
        self.assertEqual(len(self.forward), 229)
        with mock.patch("subprocess.run") as execution:
            result = deploy_validation.inspect_archive(self.make_archive())
        execution.assert_not_called()
        self.assertGreater(result["member_count"], 229)

    def test_bridge_keeps_legacy_inventory_accepted(self):
        result = deploy_validation.inspect_archive(self.make_archive(self.legacy, version="v4.1.2"))
        self.assertEqual(result["member_count"], len(self.legacy) + 2)

    def test_other_host_schema_does_not_gain_forward_permissions(self):
        self.assertIsNone(deploy_validation.forward_v420_schema(self.legacy + ["unknown.py"]))

    def test_unapproved_module_wheel_missing_file_and_reordering_are_rejected(self):
        cases = [self.forward + ["portal/unchecked.py"],
                 [path.replace("wsproto-1.3.2", "wsproto-9.9.9") for path in self.forward],
                 self.forward[:-1], list(reversed(self.forward))]
        for manifest in cases:
            with self.subTest(manifest=manifest[-1]), self.assertRaises(deploy_validation.ArchiveValidationError):
                deploy_validation.inspect_archive(self.make_archive(manifest))

    def test_forward_inventory_is_version_gated(self):
        for version in ("v4.1.2", "v4.2.1", "v9.0.0", "v4.2.0" * 10):
            with self.subTest(version=version), self.assertRaises(deploy_validation.ArchiveValidationError):
                deploy_validation.inspect_archive(self.make_archive(version=version))

    def test_embedded_schema_must_match_verified_manifest(self):
        with self.assertRaisesRegex(deploy_validation.ArchiveValidationError, "не совпадает"):
            deploy_validation.inspect_archive(self.make_archive(embedded="\n".join(self.legacy) + "\n"))

    def test_runtime_secrets_extra_files_and_links_are_rejected(self):
        for extra in ("users-secret.json", "clients/Alice/awg.conf", "certs/server.key", ".env"):
            with self.subTest(extra=extra), self.assertRaises(deploy_validation.ArchiveValidationError):
                deploy_validation.inspect_archive(self.make_archive(extra=extra))
        with self.assertRaises(deploy_validation.ArchiveValidationError):
            deploy_validation.inspect_archive(self.make_archive(symlink="portal/unexpected-link"))


if __name__ == "__main__":
    unittest.main()
