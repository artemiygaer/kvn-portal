import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.publication_manifest import (
    DEPLOY_NAME,
    PUBLICATION_NAMES,
    RELEASE_NAME,
    build_publication_manifest,
)
from tools.source_safety import denied_path, validate


ROOT = Path(__file__).resolve().parents[1]


class SourceSafetyTests(unittest.TestCase):
    def test_runtime_matrix_is_denied_and_clean_templates_are_allowed(self):
        for relative in [
            "users.json",
            "clients/admin/wireguard.conf",
            "certs/server.key",
            "portal-data/portal.db",
            ".env",
            "output/debug.log",
            "kvn-vpn-release-linux-amd64.tar.gz",
            ".supergoal/STATE.md",
        ]:
            with self.subTest(relative=relative):
                self.assertTrue(denied_path(relative))
        for relative in [
            "deploy/users.json",
            "deploy/nginx/site/index.html",
            "deploy/portal-data/.gitkeep",
            "README.md",
        ]:
            self.assertEqual(denied_path(relative), "")

    def test_content_scan_rejects_private_key_without_echoing_payload(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            relative = Path(tmp).relative_to(ROOT) / "candidate.txt"
            path = ROOT / relative
            path.write_bytes(b"-----BEGIN " + b"PRIVATE KEY-----\nfixture\n")
            errors, _ = validate([relative.as_posix()])
            self.assertEqual(len(errors), 1)
            self.assertIn("private key", errors[0])
            self.assertNotIn("fixture", errors[0])


class PublicationManifestTests(unittest.TestCase):
    def test_manifest_requires_external_deploy_to_match_release_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            release = root / RELEASE_NAME
            deploy = root / DEPLOY_NAME
            release.write_bytes(b"release")
            deploy.write_bytes(b"deploy")
            deploy_hash = __import__("hashlib").sha256(b"deploy").hexdigest()
            release_metadata = {
                "build_id": "20260726-test1",
                "source": {"sha256": deploy_hash, "size": len(b"deploy")},
            }
            with (
                mock.patch("tools.publication_manifest.validate_release", return_value=release_metadata),
                mock.patch(
                    "tools.publication_manifest.inspect_archive",
                    return_value={"member_count": 130},
                ),
            ):
                manifest = build_publication_manifest(release, deploy)
            self.assertEqual(manifest["repository"], "artemiygaer/kvn-portal")
            self.assertEqual(manifest["publication_files"], list(PUBLICATION_NAMES))
            self.assertEqual([item["name"] for item in manifest["assets"]], [RELEASE_NAME, DEPLOY_NAME])


class WorkflowContractTests(unittest.TestCase):
    def test_ci_and_release_workflows_keep_exact_safety_contract(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        for marker in [
            "tools/source_safety.py --mode tracked",
            "tools/docs_check.py",
            "python3 -m unittest discover -s tests -v",
            "docker build --target test -t kvn-portal:test portal",
            "bash tools/build-deploy.sh",
            "actions/upload-artifact@v4",
        ]:
            self.assertIn(marker, ci)
        for name in PUBLICATION_NAMES:
            self.assertIn(name, release)
        for marker in [
            "workflow_dispatch:",
            "type: boolean",
            "inputs.publish",
            "tools/publication_manifest.py",
            'gh release create "$TAG"',
            "--draft",
            'gh release upload "$TAG"',
            'gh release view "$TAG" --json assets',
            'gh release edit "$TAG" --draft=false',
        ]:
            self.assertIn(marker, release)
        self.assertNotRegex(release, r"(?m)^\s+(?:push|schedule):\s*$")
        self.assertNotIn("pull_request_target", ci + release)
        self.assertNotIn("repository_dispatch", ci + release)
        self.assertNotIn("id-token: write", release)
        self.assertNotIn("attestations: write", release)


if __name__ == "__main__":
    unittest.main()
