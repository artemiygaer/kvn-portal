"""Границы файлов и воспроизводимость архива установщика."""

from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from tests.v5.debian_core_e2e import release_asset
from v5.core.packages.manifest import PackageError, canonical_json
from v5.tools.build_installer import build, NAME

GUIDE = Path(__file__).resolve().parents[2] / "v5/install/README.md"


class InstallerArtifactTests(unittest.TestCase):
    def test_release_transport_is_pinned_to_project_and_v5(self):
        self.assertEqual(release_asset("v5.0.0-rc.1"),
                         "https://github.com/artemiygaer/kvn-portal/releases/download/"
                         "v5.0.0-rc.1/kvn-portal-v5-installer.tar.gz")
        for tag in ("v4.2.0", "main", "latest", "v5.0.0/../../", "https://example.com/v5.0.0", "v5.0.0\n"):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release_asset(tag)

    def test_archive_contains_only_phase_core_source_and_reproduces(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / NAME, Path(directory) / "repeat.tar.gz"
            self.assertEqual(build(first), build(second))
            with tarfile.open(first, "r:gz") as archive:
                members = archive.getmembers()
            names = {item.name for item in members}
            self.assertIn("v5/install/install.sh", names)
            self.assertIn("v5/install/systemd/kvn-v5-web.service", names)
            self.assertIn("v5/portal/templates/login.html", names)
            self.assertIn("v5/portal/templates/users/detail.html", names)
            self.assertIn("v5/core/users/rpc.py", names)
            self.assertNotIn("v5/core/users/users.sqlite3", names)
            self.assertIn("v5/core/tls/requirements-acme.lock", names)
            self.assertIn("v5/install/systemd/kvn-v5-tls-renew.timer", names)
            self.assertIn("v5/install/systemd/kvn-v5-package.socket", names)
            self.assertIn("v5/install/systemd/kvn-v5-reconcile.service", names)
            self.assertIn("v5/install/systemd/kvn-v5-lifecycle.socket", names)
            self.assertIn("v5/install/systemd/kvn-v5-module-wireguard.service", names)
            self.assertIn("v5/install/systemd/kvn-v5-module-amneziawg.service", names)
            self.assertIn("v5/install/systemd/kvn-v5-module-hysteria.service", names)
            self.assertIn("v5/install/systemd/kvn-v5-module-tls-sync.service", names)
            self.assertIn("v5/install/systemd/kvn-v5-module-telemt.service", names)
            self.assertIn("v5/install/systemd/kvn-v5-module-mtg.service", names)
            self.assertFalse(any("ocserv" in name.lower() or "openconnect" in name.lower() for name in names))
            self.assertEqual(len(names), len(members))
            self.assertTrue(all(item.isfile() and not item.name.startswith("/")
                                and ".." not in Path(item.name).parts and item.uid == item.gid == 0
                                and item.mtime == 0 for item in members))
            self.assertTrue(all(item.name.startswith(("v5/core/", "v5/portal/", "v5/install/", "v5/modules/"))
                                for item in members))
            self.assertIn("v5/modules/xray/worker.py", names)
            self.assertTrue(all(name.endswith(".py") for name in names if name.startswith("v5/modules/")))

    def test_bundles_only_explicit_public_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = bytes.fromhex("302a300506032b6570032100") + bytes(range(32))
            pin = root / "publisher.json"
            content = canonical_json({"public_der": key.hex(), "sha256": hashlib.sha256(key).hexdigest()})
            pin.write_bytes(content)
            destination = root / NAME
            build(destination, pin)
            with tarfile.open(destination, "r:gz") as archive:
                item = archive.extractfile("v5/install/publisher.json")
                self.assertEqual(item.read(), content)
            pin.write_bytes(b"unexpected fields")
            with self.assertRaises(PackageError):
                build(root / "rejected.tar.gz", pin)
            self.assertFalse((root / "rejected.tar.gz").exists())

    @unittest.skipUnless(all(shutil.which(cmd) for cmd in ("bash", "sha256sum", "tar")),
                         "Для прогона команд установки нужны Bash, sha256sum и tar")
    def test_documented_commands_never_install_on_download_or_checksum_failure(self):
        bash = shutil.which("bash")
        snippet = GUIDE.read_text(encoding="utf-8").split("```bash\n", 1)[1].split("\n```", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / NAME
            digest = build(artifact)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            curl = fake_bin / "curl"
            # Сеть подменена; tar, sha256sum и сам фрагмент README выполняются без подмены.
            curl.write_text("""#!/bin/sh
set -eu
test "$1" = --disable
test "$2" = --fail
test "$3" = --location
test "$4:$5:$6:$7" = --proto:=https:--proto-redir:=https
test "$8" = -o
test "$9" = kvn-portal-v5-installer.tar.gz
test "${10}" = "$KVN_TEST_URL"
test "$KVN_TEST_NETWORK" = available || exit 22
cp -- "$KVN_TEST_ARTIFACT" "$9"
""", encoding="utf-8")
            curl.chmod(0o700)
            install = fake_bin / "bash"
            install.write_text("""#!/bin/sh
set -eu
test "$1" = v5/install/install.sh
test -r "$1"
test -r v5/core/agent.py
touch -- "$KVN_TEST_MARKER"
""", encoding="utf-8")
            install.chmod(0o700)
            marker = root / "started"
            for network, expected_hash, expected_code in (("unavailable", digest, 22),
                                                           ("available", "0" * 64, 1),
                                                           ("available", digest, 0)):
                with self.subTest(network=network, expected_code=expected_code):
                    staging = root / f"staging-{expected_code}"
                    staging.mkdir()
                    env = {"PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
                           "LC_ALL": "C.UTF-8", "TMPDIR": str(staging),
                           "KVN_TEST_URL": release_asset("v5.0.0-rc.1"), "KVN_TEST_ARTIFACT": str(artifact),
                           "KVN_TEST_NETWORK": network, "KVN_TEST_MARKER": str(marker)}
                    result = subprocess.run([bash, "-c", snippet], input=f"v5.0.0-rc.1\n{expected_hash}\n",
                                            env=env, text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, expected_code, result.stderr)
                    self.assertEqual(marker.exists(), expected_code == 0)
                    self.assertEqual(bool(list(staging.glob("*/v5/install/install.sh"))), expected_code == 0)
