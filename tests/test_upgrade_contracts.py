"""Характеристические контракты старого updater и будущего full release."""

from __future__ import annotations

import io
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path, PurePosixPath

from tools.deploy_archive import ArchiveValidationError, inspect_archive


ROOT = Path(__file__).resolve().parents[1]
LEGACY_FIXTURE = ROOT / "tests" / "fixtures" / "legacy-deploy"
RUNTIME_PREFIXES = ("clients/", "certs/", "portal-data/", "portal-runtime/", "backup/")


def validate_release_fixture(members: list[dict]) -> None:
    """Минимальный тестовый контракт формата, который реализует фаза image bundle."""
    names: set[str] = set()
    manifest = None
    for member in members:
        name = member.get("name")
        if not isinstance(name, str) or not name or "\\" in name:
            raise ValueError("небезопасный путь")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("небезопасный путь")
        if member.get("type", "file") != "file":
            raise ValueError("ссылки запрещены")
        if name in names:
            raise ValueError("повторяющийся член")
        if name.startswith(RUNTIME_PREFIXES) or name in {"users.json", ".env", "CLIENT_LINKS.md"}:
            raise ValueError("runtime-путь запрещён")
        names.add(name)
        if name == "release-manifest.json":
            manifest = member.get("content")
    if not isinstance(manifest, dict):
        raise ValueError("manifest отсутствует")
    if manifest.get("platform") != "linux/amd64":
        raise ValueError("неверная platform")


class UpgradeContractTests(unittest.TestCase):
    @staticmethod
    def _tar_gz_bytes(files: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            for name, payload in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o700 if name.endswith(".sh") else 0o600
                archive.addfile(info, io.BytesIO(payload))
        return buffer.getvalue()

    @unittest.skipUnless(os.name == "posix", "нужен POSIX shell")
    def test_v3_bridge_verifies_full_release_then_runs_bootstrap_and_full_update(self):
        fake_update = b"""#!/usr/bin/env bash
set -euo pipefail
root="${KVN_UPDATE_ROOT:?}"
if [ "${KVN_UPDATE_MODE:-full}" = "bootstrap-only" ]; then
    cp "$0" "$root/update.sh"
    printf 'bootstrap\\n' >> "$root/steps"
else
    printf 'full:%s\\n' "$(basename "$1")" >> "$root/steps"
fi
"""
        deploy = self._tar_gz_bytes({
            "deploy/update.sh": fake_update,
            "deploy/tools/deploy_archive.py": b"# fixture validator\n",
            "deploy/tools/canonical-files.txt": b"update.sh\n",
        })
        images = b"fixture-images"
        manifest = {
            "format": 1,
            "platform": "linux/amd64",
            "source": {
                "name": "kvn-vpn-deploy.tar.gz",
                "size": len(deploy),
                "sha256": hashlib.sha256(deploy).hexdigest(),
            },
            "images": {
                "name": "kvn-vpn-images-linux-amd64.tar",
                "size": len(images),
                "sha256": hashlib.sha256(images).hexdigest(),
            },
        }
        release = self._tar_gz_bytes({
            "release-manifest.json": (json.dumps(manifest) + "\n").encode(),
            "kvn-vpn-deploy.tar.gz": deploy,
            "kvn-vpn-images-linux-amd64.tar": images,
        })

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            project.mkdir()
            (project / "update.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            archive = root / "kvn-vpn-release-linux-amd64.tar.gz"
            archive.write_bytes(release)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_id = fake_bin / "id"
            fake_id.write_text("#!/bin/sh\nprintf 0\n", encoding="utf-8")
            fake_id.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            result = subprocess.run(
                [
                    "bash", str(ROOT / "tools/bootstrap-v4.sh"), "--sha256",
                    hashlib.sha256(release).hexdigest(), str(archive), str(project),
                ],
                cwd=root, env=env, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(
                (project / "steps").read_text(encoding="utf-8").splitlines(),
                ["bootstrap", "full:kvn-vpn-release-linux-amd64.tar.gz"],
            )

            (project / "steps").unlink()
            rejected = subprocess.run(
                [
                    "bash", str(ROOT / "tools/bootstrap-v4.sh"), "--sha256",
                    "0" * 64, str(archive), str(project),
                ],
                cwd=root, env=env, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=10, check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("SHA-256 архива не совпадает", rejected.stdout)
            self.assertFalse((project / "steps").exists())

    def test_maintenance_operations_share_bounded_flock_before_mutation(self):
        cases = {
            "setup.sh": "apt-get update",
            "update.sh": 'WORKER_DIR="$(mktemp -d "$UPDATE_TMP_ROOT/worker.XXXXXXXXXX")"',
            "tools/project-backup.sh": 'staging="$(mktemp -d)"',
            "tools/restore-backup.sh": 'staging="$(mktemp -d)"',
        }
        for relative, mutation in cases.items():
            with self.subTest(script=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("/run/lock/kvn-vpn-maintenance.lock", text)
                self.assertIn("flock -w", text)
                self.assertLess(text.index("flock -w"), text.index(mutation))

    def test_update_large_temporaries_use_project_filesystem(self):
        source = (ROOT / "update.sh").read_text(encoding="utf-8")
        self.assertIn('UPDATE_TMP_ROOT="${KVN_UPDATE_TMP_ROOT:-$ROOT_DIR/.update-tmp}"', source)
        self.assertIn('export TMPDIR="$UPDATE_TMP_ROOT"', source)
        self.assertIn('mktemp -d "$UPDATE_TMP_ROOT/worker.XXXXXXXXXX"', source)
        self.assertIn('mktemp -d "$UPDATE_TMP_ROOT/source.XXXXXXXXXX"', source)

    @unittest.skipUnless(os.name == "posix" and shutil.which("flock"), "нужен Linux flock")
    def test_maintenance_lock_rejects_concurrent_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = str(Path(tmp) / "maintenance.lock")
            owner = subprocess.Popen(
                ["flock", "-x", lock, "sh", "-c", "printf ready; sleep 1"],
                stdout=subprocess.PIPE,
                text=True,
            )
            try:
                self.assertEqual(owner.stdout.read(5), "ready")
                contender = subprocess.run(
                    ["flock", "-n", lock, "true"],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(contender.returncode, 0)
            finally:
                owner.wait(timeout=3)
                if owner.stdout is not None:
                    owner.stdout.close()

    def test_setup_and_update_use_effective_targeted_service_plan(self):
        for relative in ("setup.sh", "update.sh"):
            with self.subTest(script=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("service-plan --format lines", text)
                self.assertIn("EFFECTIVE_DOCKER_SERVICES", text)
                self.assertIn('stop "${DISABLED_DOCKER_SERVICES[@]}"', text)
                self.assertIn('"${EFFECTIVE_DOCKER_SERVICES[@]}"', text)

    def test_script_runtime_paths_are_bounded_and_service_specific(self):
        setup = (ROOT / "setup.sh").read_text(encoding="utf-8")
        update = (ROOT / "update.sh").read_text(encoding="utf-8")
        awg_installer = (
            ROOT / "amneziawg" / "install-kernel-module.sh"
        ).read_text(encoding="utf-8")

        compose_function = setup.split("ensure_compose() {", 1)[1].split(
            "\n}\n", 1
        )[0]
        compose_ready_branch = compose_function.split(
            "if docker compose version", 1
        )[1].split("fi", 1)[0]
        self.assertNotIn("apt-get update", compose_ready_branch)
        self.assertNotIn("apt-get install", compose_ready_branch)
        for marker in [
            "--connect-timeout 10",
            "--max-time 60",
            "--retry 3",
            "--retry-all-errors",
        ]:
            self.assertIn(marker, setup)

        worker_bootstrap = update.split(
            'if [ "${KVN_UPDATE_WORKER:-0}" != "1" ]; then', 1
        )[1].split("fi\nROOT_DIR=", 1)[0]
        self.assertIn('trap \'rm -rf -- "$WORKER_DIR"\' EXIT', worker_bootstrap)
        package_gate = update.split(
            'if service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}"',
            1,
        )[1].split("fi", 1)[0]
        self.assertIn("wireguard-tools", package_gate)

        self.assertIn(
            'trap \'rm -rf -- "$GNUPG_HOME"\' EXIT',
            awg_installer,
        )
        self.assertIn("--keyserver-options timeout=15", awg_installer)

    def test_management_export_commands_share_state_and_user_lookup(self):
        source = (ROOT / "tools/kvnlib/commands/implementation.py").read_text(encoding="utf-8")
        command_block = source.split(
            "def client_export_command_state(", 1
        )[1].split("def cmd_interactive(", 1)[0]
        self.assertIn("def enabled_user_by_name(", command_block)
        self.assertEqual(
            command_block.count("ensure_reality_public_key(state"),
            2,
        )
        self.assertEqual(
            command_block.count("client_export_command_state("),
            3,
        )
        self.assertEqual(command_block.count("enabled_user_by_name("), 4)

    def test_legacy_fixture_reproduces_missing_deploy_archive_validator(self):
        manifest = (LEGACY_FIXTURE / ".kvn-canonical-files").read_text(encoding="utf-8").splitlines()
        self.assertNotIn("tools/deploy_archive.py", manifest)
        self.assertIn("tools/deploy_archive.py", (LEGACY_FIXTURE / "update.sh").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "kvn-vpn-deploy-legacy.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                for name, payload in {
                    "deploy/.kvn-canonical-files": "\n".join(manifest) + "\n",
                    "deploy/docker-compose.yml": "services: {}\n",
                    "deploy/setup.sh": "#!/bin/sh\n",
                    "deploy/update.sh": (LEGACY_FIXTURE / "update.sh").read_text(encoding="utf-8"),
                    "deploy/tools/kvnctl.py": "# fixture\n",
                    "deploy/portal/Dockerfile": os.urandom(4096),
                    "deploy/portal/app/__init__.py": "# fixture\n",
                    "deploy/users.json": json.dumps({
                        "server": "YOUR_SERVER_IP", "users": [], "portal": {"enabled": False},
                    }),
                }.items():
                    data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(
                ArchiveValidationError, "manifest отсутствуют канонические файлы:.*tools/deploy_archive.py",
            ):
                inspect_archive(archive_path)

    def test_release_manifest_rejects_security_matrix(self):
        valid_manifest = {
            "format": 1,
            "platform": "linux/amd64",
            "source": {"name": "kvn-vpn-deploy.tar.gz", "sha256": "a" * 64, "size": 1},
            "images": {"name": "kvn-vpn-images-linux-amd64.tar", "sha256": "b" * 64, "size": 1},
        }
        base = [
            {"name": "release-manifest.json", "content": valid_manifest},
            {"name": "kvn-vpn-deploy.tar.gz"},
            {"name": "kvn-vpn-images-linux-amd64.tar"},
        ]
        validate_release_fixture(base)
        cases = {
            "traversal": base + [{"name": "../outside"}],
            "symlink": base + [{"name": "unsafe", "type": "symlink"}],
            "duplicate": base + [{"name": "kvn-vpn-deploy.tar.gz"}],
            "runtime": base + [{"name": "clients/admin/private.conf"}],
            "platform": [
                {"name": "release-manifest.json", "content": {**valid_manifest, "platform": "linux/arm64"}},
                *base[1:],
            ],
        }
        for name, members in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_release_fixture(members)


if __name__ == "__main__":
    unittest.main()
