"""Интеграционные контракты offline apply для setup/update/портала."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.release_archive import EXPECTED_IMAGE_REFS, create_release


ROOT = Path(__file__).resolve().parents[1]


def add_member(archive, name: str, payload: bytes | str) -> None:
    data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    info = tarfile.TarInfo(name)
    info.size = len(data)
    archive.addfile(info, io.BytesIO(data))


def make_release(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    source = root / "kvn-vpn-deploy.tar.gz"
    images = root / "kvn-vpn-images-linux-amd64.tar"
    schema = (ROOT / "tools/canonical-files.txt").read_text(encoding="utf-8")
    with tarfile.open(source, "w:gz") as archive:
        add_member(archive, "deploy/.kvn-canonical-files", schema)
        for relative in schema.splitlines():
            payload = (ROOT / relative).read_bytes()
            if relative == "tools/canonical-files.txt":
                payload = schema.encode()
            add_member(archive, f"deploy/{relative}", payload)
        add_member(
            archive, "deploy/users.json",
            '{"server":"YOUR_SERVER_IP","users":[],"portal":{"enabled":false}}',
        )
    config_id = "f" * 64
    with tarfile.open(images, "w:") as archive:
        add_member(archive, "manifest.json", json.dumps([{
            "Config": f"{config_id}.json", "RepoTags": list(EXPECTED_IMAGE_REFS), "Layers": [],
        }]))
        add_member(archive, f"{config_id}.json", "{}")
    metadata = [{
        "ref": ref,
        "id": f"sha256:{config_id}",
        "platform": "linux/amd64",
        "repo_digests": (
            [] if ref.startswith("kvn-")
            else [ref.split(":", 1)[0] + "@sha256:" + "e" * 64]
        ),
    } for ref in EXPECTED_IMAGE_REFS]
    release = root / "kvn-vpn-release-linux-amd64.tar.gz"
    create_release(release, "offline-test", source, images, metadata)
    return release


class OfflineReleaseTests(unittest.TestCase):
    def test_three_entry_paths_share_release_contract_and_offline_compose(self):
        update = (ROOT / "update.sh").read_text(encoding="utf-8")
        setup = (ROOT / "setup.sh").read_text(encoding="utf-8")
        agent = (ROOT / "portal/agent.py").read_text(encoding="utf-8")
        portal = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "portal/app/__init__.py",
                ROOT / "portal/app/blueprints/views.py",
            )
        )
        gateway = (ROOT / "tools/kvnctl.py").read_text(encoding="utf-8")
        for source in (update, setup):
            self.assertIn("tools.release_archive", source)
            self.assertIn("docker image load", source)
            self.assertIn("verify-loaded", source)
            self.assertIn("--no-build --pull never", source)
        self.assertLess(update.index("docker image load"), update.index("SOURCES_INSTALLED=1"))
        self.assertIn("validate_release(archive_path)", agent)
        self.assertIn('"release" if is_release else "deploy"', agent)
        for marker in ["upload_stream.read(1024 * 1024)", "os.fsync", "os.replace", "disk_usage"]:
            self.assertIn(marker, portal)
        self.assertNotIn("upload.save(upload_path)", portal)
        self.assertIn('request.mimetype == "application/octet-stream"', portal)
        self.assertIn("SpooledTemporaryFile", portal)
        for marker in ["client_max_body_size 2g", "proxy_request_buffering off", "proxy_read_timeout 30m"]:
            self.assertIn(marker, gateway)
        self.assertNotIn("client_max_body_size 128m", (ROOT / "tools/kvnctl.py").read_text(encoding="utf-8"))

    @unittest.skipIf(os.name == "nt", "Исполняемый rollback-тест запускается в Linux-контейнере")
    @unittest.skipUnless(shutil.which("bash"), "В образе нет bash")
    def test_release_load_failure_precedes_source_mutation_and_preserves_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = make_release(base)
            installed = base / "installed"
            installed.mkdir()
            for relative in [
                "update.sh", "tools/deploy_archive.py", "tools/release_archive.py",
                "tools/canonical-files.txt", "tools/__init__.py",
            ]:
                source = ROOT / relative
                destination = installed / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.exists():
                    shutil.copy2(source, destination)
            marker = installed / "portal/agent.py"
            marker.parent.mkdir(parents=True)
            marker.write_bytes(b"old-agent\n")
            runtime = {
                "users.json": b'{"server":"runtime.example","users":[],"portal":{"enabled":false}}',
                "clients/admin/private.conf": b"client-secret",
                "certs/site/key.pem": b"private-key",
                "portal-data/portal.db": b"runtime-db",
            }
            for relative, payload in runtime.items():
                path = installed / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            fake_bin = base / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n"
                "if [ \"$1 $2\" = \"image load\" ]; then exit 73; fi\nexit 0\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            log = base / "docker.log"
            env = os.environ.copy()
            env.update({"PATH": f"{fake_bin}:{env['PATH']}", "DOCKER_LOG": str(log)})
            result = subprocess.run(
                ["bash", "update.sh", str(release)], cwd=installed, env=env,
                text=True, encoding="utf-8", errors="replace",
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, check=False,
            )
            self.assertEqual(result.returncode, 73, result.stdout)
            self.assertIn("image load", log.read_text(encoding="utf-8"))
            self.assertNotIn("compose", log.read_text(encoding="utf-8"))
            self.assertEqual(marker.read_bytes(), b"old-agent\n")
            for relative, payload in runtime.items():
                self.assertEqual((installed / relative).read_bytes(), payload)

    def test_source_only_fallback_is_explicit(self):
        update = (ROOT / "update.sh").read_text(encoding="utf-8")
        settings = (ROOT / "portal/app/templates/settings.html").read_text(encoding="utf-8")
        self.assertIn("Source-only архив", update)
        self.assertIn("online build/pull", update)
        self.assertIn("Source deploy совместим", settings)
        self.assertIn("не рекомендуется для сервера 1 ГБ", settings)

    @unittest.skipIf(os.name == "nt", "Переходный e2e запускается в Linux-контейнере")
    @unittest.skipUnless(shutil.which("bash"), "В образе нет bash")
    def test_legacy_bootstrap_then_full_release_has_no_build_or_pull(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = make_release(base / "builder")
            source_archive = base / "source.tar.gz"
            with tarfile.open(release, "r:gz") as outer:
                source_archive.write_bytes(outer.extractfile("kvn-vpn-deploy.tar.gz").read())
            bootstrap = base / "bootstrap"
            with tarfile.open(source_archive, "r:gz") as source:
                for relative in ["update.sh", "tools/deploy_archive.py", "tools/canonical-files.txt"]:
                    destination = bootstrap / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(source.extractfile(f"deploy/{relative}").read())
            installed = base / "legacy"
            installed.mkdir()
            shutil.copy2(ROOT / "tests/fixtures/legacy-deploy/update.sh", installed / "update.sh")
            (installed / "users.json").write_text(
                '{"server":"legacy.example","users":[],"portal":{"enabled":false}}', encoding="utf-8",
            )
            env = os.environ.copy()
            env.update({
                "KVN_UPDATE_WORKER": "1", "KVN_UPDATE_ROOT": str(installed),
                "KVN_UPDATE_INSPECTOR": str(bootstrap / "tools/deploy_archive.py"),
                "KVN_UPDATE_MODE": "bootstrap-only",
            })
            boot = subprocess.run(
                ["bash", str(bootstrap / "update.sh"), str(source_archive)], cwd=installed, env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60, check=False,
            )
            self.assertEqual(boot.returncode, 0, boot.stdout)
            self.assertTrue((installed / "tools/release_archive.py").is_file())

            (installed / "users.json").write_text("not-json\n", encoding="utf-8")
            fake_bin = base / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\n"
                "if [ \"$1 $2\" = \"image inspect\" ]; then printf '%s' \"$FAKE_INSPECT_JSON\"; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            fake_inspect = json.dumps([{
                "Id": "sha256:" + "f" * 64, "Os": "linux", "Architecture": "amd64",
            } for _ref in EXPECTED_IMAGE_REFS])
            log = base / "docker.log"
            env = os.environ.copy()
            env.update({
                "PATH": f"{fake_bin}:{env['PATH']}", "DOCKER_LOG": str(log),
                "FAKE_INSPECT_JSON": fake_inspect,
            })
            full = subprocess.run(
                ["bash", "update.sh", str(release)], cwd=installed, env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90, check=False,
            )
            self.assertNotEqual(full.returncode, 0, full.stdout)
            transcript = log.read_text(encoding="utf-8")
            self.assertIn("image load", transcript)
            self.assertIn("image inspect", transcript)
            self.assertNotIn("build", transcript)
            self.assertNotIn("pull", transcript)
            self.assertNotIn("compose", transcript)


if __name__ == "__main__":
    unittest.main()
