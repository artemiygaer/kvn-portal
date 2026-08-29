"""Контракты модульного release pipeline и перехода v3→v4."""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.release.artifact import inspect_update_artifact
from tools.release.migrations import (
    LEGACY_BOOTSTRAP_FILES,
    MigrationError,
    extract_legacy_bootstrap,
    plan_migration,
)


ROOT = Path(__file__).resolve().parents[1]


def add_file(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    archive.addfile(member, io.BytesIO(payload))


class ReleasePipelineArchitectureTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
