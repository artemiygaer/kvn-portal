"""Контракты закреплённых runtime-образов и опубликованных портов."""

from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.release_archive import (
    EXPECTED_IMAGE_REFS,
    ReleaseValidationError,
    create_release,
    validate_release,
    verify_loaded_images,
)


ROOT = Path(__file__).resolve().parents[1]


class RuntimeImageContractsTests(unittest.TestCase):
    def test_runtime_images_are_pinned_without_floating_tags(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        for image in [
            "ghcr.io/telemt/telemt:3.4.24",
            "nineseconds/mtg:2.2.8",
            "tobyxdd/hysteria:v2.10.0",
            "ghcr.io/xtls/xray-core:26.3.27",
        ]:
            self.assertIn(image, compose)
        self.assertNotRegex(compose, r"image:\s*[^\s]+:(?:latest|stable)\b")

    def test_hysteria_restrictions_and_direct_ports_remain_explicit(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        hysteria = compose.split("  hysteria:\n", 1)[1].split("\n  ocserv:\n", 1)[0]
        for marker in ["read_only: true", "cap_drop:", "- ALL", "no-new-privileges:true", '"443:443/udp"']:
            self.assertIn(marker, hysteria)
        for port in ["2096:2096/tcp", "2443:443/tcp", "2444:2053/tcp", "2445:2054/tcp", "2446:3129/tcp", "2447:3128/tcp", "2448:443/tcp", "4443:4443/udp"]:
            self.assertIn(port, compose)
        for path in ["amneziawg/install-host-service.sh", "wireguard/install-host-service.sh"]:
            self.assertTrue((ROOT / path).is_file())

    def test_ocserv_base_is_digest_pinned_and_checks_installed_binary(self):
        dockerfile = (ROOT / "ocserv/Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(dockerfile.splitlines()[0], r"^FROM debian:trixie-slim@sha256:[0-9a-f]{64}$")
        self.assertIn("ocserv --version", dockerfile)

    def test_portal_base_is_tag_and_digest_pinned(self):
        dockerfile = (ROOT / "portal/Dockerfile").read_text(encoding="utf-8")
        self.assertRegex(
            dockerfile.splitlines()[1],
            r"^FROM python:3\.13-alpine@sha256:[0-9a-f]{64} AS base$",
        )

    def test_portal_runtime_stage_precedes_test_stage(self):
        dockerfile = (ROOT / "portal/Dockerfile").read_text(encoding="utf-8")
        self.assertLess(
            dockerfile.index("FROM base AS runtime"),
            dockerfile.index("FROM base AS test"),
        )
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        portal = compose.split("  portal:\n", 1)[1].split("\n  portal-gateway:\n", 1)[0]
        self.assertIn("target: runtime", portal)

    def test_release_builder_exports_all_and_only_compose_runtime_images(self):
        import re

        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        compose_refs = set(re.findall(r"^\s+image:\s*([^\s]+)\s*$", compose, re.MULTILINE))
        self.assertEqual(compose_refs, set(EXPECTED_IMAGE_REFS))
        builder = (ROOT / "tools/build-release.sh").read_text(encoding="utf-8")
        for ref in EXPECTED_IMAGE_REFS:
            self.assertIn(f'"{ref}"', builder)
        self.assertIn("--platform linux/amd64", builder)

    def test_release_builder_has_validated_offline_mode(self):
        builder = (ROOT / "tools/build-release.sh").read_text(encoding="utf-8")
        self.assertIn('OFFLINE="${KVN_RELEASE_OFFLINE:-0}"', builder)
        self.assertIn('if [ "$OFFLINE" = "1" ]', builder)
        self.assertIn('docker image inspect "$ref"', builder)
        self.assertIn('portal_build_id="$(docker image inspect', builder)
        self.assertIn('if [ "$portal_build_id" != "$BUILD_ID" ]', builder)

    def test_portal_image_accepts_release_build_id(self):
        dockerfile = (ROOT / "portal/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("ARG KVN_BUILD_ID=dev", dockerfile)
        self.assertIn("KVN_BUILD_ID=${KVN_BUILD_ID}", dockerfile)
        builder = (ROOT / "tools/build-release.sh").read_text(encoding="utf-8")
        self.assertIn('--build-arg "KVN_BUILD_ID=$BUILD_ID"', builder)

    def test_portal_healthcheck_is_lightweight_for_single_cpu_host(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        portal = compose.split("  portal:\n", 1)[1].split("\n  portal-gateway:\n", 1)[0]
        self.assertIn('["CMD", "wget"', portal)
        self.assertNotIn("urllib.request", portal)


class ReleaseArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "kvn-vpn-deploy.tar.gz"
        self.images = self.root / "kvn-vpn-images-linux-amd64.tar"
        self.release = self.root / "kvn-vpn-release-linux-amd64.tar.gz"
        self._make_source()
        self._make_images()
        self.metadata = [{
            "ref": ref,
            "id": "sha256:" + "f" * 64,
            "platform": "linux/amd64",
            "repo_digests": (
                [] if ref.startswith("kvn-")
                else [ref.split(":", 1)[0] + "@sha256:" + "e" * 64]
            ),
        } for ref in EXPECTED_IMAGE_REFS]

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _add(archive, name, payload):
        data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        info = tarfile.TarInfo(name)
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    def _make_source(self):
        schema = (ROOT / "tools/canonical-files.txt").read_text(encoding="utf-8")
        with tarfile.open(self.source, "w:gz") as archive:
            self._add(archive, "deploy/.kvn-canonical-files", schema)
            for relative in schema.splitlines():
                payload = schema if relative == "tools/canonical-files.txt" else "source\n"
                if relative == "portal/Dockerfile":
                    payload = os.urandom(2048)
                self._add(archive, f"deploy/{relative}", payload)
            self._add(
                archive, "deploy/users.json",
                '{"server":"YOUR_SERVER_IP","users":[],"portal":{"enabled":false}}',
            )

    def _make_images(self):
        config_id = "f" * 64
        docker_manifest = [{
            "Config": f"{config_id}.json",
            "RepoTags": list(EXPECTED_IMAGE_REFS),
            "Layers": [],
        }]
        with tarfile.open(self.images, "w:") as archive:
            self._add(archive, "manifest.json", json.dumps(docker_manifest))
            self._add(archive, f"{config_id}.json", "{}")

    def _rewrite(self, output, *, manifest_change=None, extra_name="", symlink=False):
        with tarfile.open(self.release, "r:gz") as source:
            payloads = {member.name: source.extractfile(member).read() for member in source.getmembers()}
        if manifest_change:
            manifest = json.loads(payloads["release-manifest.json"])
            manifest_change(manifest)
            payloads["release-manifest.json"] = json.dumps(manifest).encode()
        with tarfile.open(output, "w:gz") as archive:
            for name in ("release-manifest.json", "kvn-vpn-deploy.tar.gz", "kvn-vpn-images-linux-amd64.tar"):
                self._add(archive, name, payloads[name])
            if extra_name:
                if symlink:
                    info = tarfile.TarInfo(extra_name)
                    info.type = tarfile.SYMTYPE
                    info.linkname = "../outside"
                    archive.addfile(info)
                else:
                    self._add(archive, extra_name, "secret")

    def test_manifest_and_release_are_logically_deterministic(self):
        first = create_release(self.release, "build-20260713", self.source, self.images, self.metadata)
        second_path = self.root / "second.tar.gz"
        second = create_release(second_path, "build-20260713", self.source, self.images, self.metadata)
        self.assertEqual(first, second)
        self.assertEqual(self.release.read_bytes(), second_path.read_bytes())
        validated = validate_release(self.release)
        self.assertEqual(validated["platform"], "linux/amd64")
        self.assertEqual([item["ref"] for item in validated["images"]["items"]], list(EXPECTED_IMAGE_REFS))

    def test_manifest_rejects_upstream_image_without_repo_digest(self):
        metadata = [dict(item) for item in self.metadata]
        for item in metadata:
            if not item["ref"].startswith("kvn-"):
                item["repo_digests"] = []
                break
        with self.assertRaisesRegex(ReleaseValidationError, "immutable digest"):
            create_release(self.release, "build-20260713", self.source, self.images, metadata)

    def test_loaded_image_verification_supports_classic_and_containerd_ids(self):
        config_id = "sha256:" + "a" * 64
        manifest_id = "sha256:" + "b" * 64
        repo_digest = f"kvn-portal@{manifest_id}"
        manifest_path = self.root / "release-manifest.json"
        manifest_path.write_text(json.dumps({
            "images": {"items": [{
                "ref": "kvn-portal:local",
                "id": config_id,
                "platform": "linux/amd64",
                "repo_digests": [repo_digest],
            }]},
        }), encoding="utf-8")

        for image_id, repo_digests in (
            (config_id, []),
            (manifest_id, [repo_digest]),
        ):
            inspected = [{
                "Id": image_id,
                "Os": "linux",
                "Architecture": "amd64",
                "RepoDigests": repo_digests,
            }]
            completed = mock.Mock(returncode=0, stdout=json.dumps(inspected), stderr="")
            with self.subTest(image_id=image_id), mock.patch(
                "tools.release_archive.subprocess.run", return_value=completed,
            ):
                self.assertEqual(
                    verify_loaded_images(manifest_path),
                    {"kvn-portal:local": config_id},
                )

        bad = mock.Mock(returncode=0, stdout=json.dumps([{
            "Id": manifest_id,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": ["kvn-portal@sha256:" + "c" * 64],
        }]), stderr="")
        with mock.patch("tools.release_archive.subprocess.run", return_value=bad):
            with self.assertRaises(ReleaseValidationError):
                verify_loaded_images(manifest_path)

    def test_loaded_local_image_uses_saved_config_digest_with_containerd_store(self):
        config_id = "sha256:" + "a" * 64
        descriptor_id = "sha256:" + "b" * 64
        manifest_path = self.root / "release-manifest.json"
        manifest_path.write_text(json.dumps({
            "images": {"items": [{
                "ref": "kvn-portal:local",
                "id": config_id,
                "platform": "linux/amd64",
                "repo_digests": [],
            }]},
        }), encoding="utf-8")
        inspected = mock.Mock(returncode=0, stdout=json.dumps([{
            "Id": descriptor_id,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": [],
        }]), stderr="")
        with (
            mock.patch("tools.release_archive.subprocess.run", return_value=inspected),
            mock.patch(
                "tools.release_archive._saved_image_config_ids",
                return_value={"kvn-portal:local": config_id},
            ) as saved,
        ):
            self.assertEqual(
                verify_loaded_images(manifest_path),
                {"kvn-portal:local": config_id},
            )
            saved.assert_called_once_with(["kvn-portal:local"])

    def test_loaded_upstream_image_uses_saved_config_digest_without_repo_digests(self):
        config_id = "sha256:" + "a" * 64
        descriptor_id = "sha256:" + "b" * 64
        manifest_path = self.root / "release-manifest.json"
        manifest_path.write_text(json.dumps({
            "images": {"items": [{
                "ref": "nginx:1.31.1-alpine",
                "id": config_id,
                "platform": "linux/amd64",
                "repo_digests": ["nginx@sha256:" + "c" * 64],
            }]},
        }), encoding="utf-8")
        inspected = mock.Mock(returncode=0, stdout=json.dumps([{
            "Id": descriptor_id,
            "Os": "linux",
            "Architecture": "amd64",
            "RepoDigests": [],
        }]), stderr="")
        with (
            mock.patch("tools.release_archive.subprocess.run", return_value=inspected),
            mock.patch(
                "tools.release_archive._saved_image_config_ids",
                return_value={"nginx:1.31.1-alpine": config_id},
            ) as saved,
        ):
            self.assertEqual(
                verify_loaded_images(manifest_path),
                {"nginx:1.31.1-alpine": config_id},
            )
            saved.assert_called_once_with(["nginx:1.31.1-alpine"])

    def test_validator_rejects_hash_platform_member_runtime_symlink_and_oversize(self):
        create_release(self.release, "build-20260713", self.source, self.images, self.metadata)
        cases = {
            "hash": lambda value: value["source"].update(sha256="0" * 64),
            "platform": lambda value: value.update(platform="linux/arm64"),
        }
        for name, change in cases.items():
            candidate = self.root / f"{name}.tar.gz"
            self._rewrite(candidate, manifest_change=change)
            with self.subTest(name=name), self.assertRaises(ReleaseValidationError):
                validate_release(candidate)
        for name, symlink in (("clients/admin.conf", False), ("unsafe-link", True)):
            candidate = self.root / ("member-" + name.replace("/", "-") + ".tar.gz")
            self._rewrite(candidate, extra_name=name, symlink=symlink)
            with self.subTest(name=name), self.assertRaises(ReleaseValidationError):
                validate_release(candidate)
        with mock.patch("tools.release_archive.MAX_RELEASE_BYTES", 1):
            with self.assertRaises(ReleaseValidationError):
                validate_release(self.release)


if __name__ == "__main__":
    unittest.main()
