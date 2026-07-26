import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BackupScriptSourceTests(unittest.TestCase):
    def test_project_backup_contract_is_strict_and_secret_safe(self):
        source = (ROOT / "tools/project-backup.sh").read_text(encoding="utf-8")
        for marker in [
            "KVN_BACKUP_DIR:-/backup",
            "umask 077",
            "id -u",
            "mktemp -d",
            "kvn-vpn-backup-${timestamp}-${host}.tar",
            "docker compose",
            "config --images",
            "docker save -o",
            "project.tar",
            "docker-images.tar",
            "README_RESTORE.md",
            "manifest.json",
            "contains_runtime_secrets",
            "Docker daemon недоступен; архив не создан",
        ]:
            self.assertIn(marker, source)
        for excluded in [
            "./.git",
            "./.supergoal",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            "kvn-vpn-backup-*.tar",
            "kvn-vpn-release-linux-amd64*.tar.gz",
            "kvn-vpn-deploy*.tar.gz",
            "./backup",
        ]:
            self.assertIn(excluded, source)
        self.assertIn(
            'mktemp "$BACKUP_DIR/.kvn-vpn-backup.XXXXXXXXXX.tar"',
            source,
        )
        self.assertIn('mv -f -- "$tmp_archive" "$published_archive"', source)
        self.assertNotRegex(source, r"cat\s+.*users\.json")
        self.assertNotRegex(source, r"tar\s+-[^\n]*f\s+[\"']?\$published_archive")

    def test_restore_script_validates_archive_and_target_before_extracting(self):
        source = (ROOT / "tools/restore-backup.sh").read_text(encoding="utf-8")
        for marker in [
            "umask 077",
            "путь к backup archive должен быть абсолютным",
            "target directory должен быть абсолютным",
            "target directory слишком широкий",
            "kvn-vpn-backup-*.tar",
            "target directory не должен быть symlink",
            "target directory существует и не пуст",
            "validate_tar_archive",
            'validate_tar_archive "$archive" outer',
            'validate_tar_archive "$staging/project.tar" project',
            "небезопасный путь",
            "ссылки и специальные файлы запрещены",
            "[ -f \"$staging/project.tar\" ]",
            "docker load -i",
            "sudo ./setup.sh <NEW_SERVER_IP_OR_DOMAIN>",
        ]:
            self.assertIn(marker, source)
        extract_pos = source.index('tar -xf "$archive"')
        validation_pos = source.index('validate_tar_archive "$archive" outer')
        self.assertLess(validation_pos, extract_pos)

    def test_embedded_tar_validator_accepts_backup_and_rejects_traversal(self):
        source = (ROOT / "tools/restore-backup.sh").read_text(encoding="utf-8")
        marker = 'python3 - "$archive_path" "$archive_role" <<\'PY\'\n'
        validator = source.split(marker, 1)[1].split("\nPY\n}", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            safe_project = base / "safe-project.tar"
            with tarfile.open(safe_project, "w") as archive:
                payload = b"{}\n"
                info = tarfile.TarInfo("./users.json")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            safe = subprocess.run(
                [sys.executable, "-c", validator, str(safe_project), "project"],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(safe.returncode, 0, safe.stdout)

            outer = base / "kvn-vpn-backup-safe.tar"
            manifest = json.dumps({
                "format": "kvn-vpn-backup-v1",
                "contains_runtime_secrets": True,
            }).encode("utf-8")
            with tarfile.open(outer, "w") as archive:
                for name, payload in {
                    "manifest.json": manifest,
                    "project.tar": safe_project.read_bytes(),
                }.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            valid_outer = subprocess.run(
                [sys.executable, "-c", validator, str(outer), "outer"],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(valid_outer.returncode, 0, valid_outer.stdout)

            evil_project = base / "evil-project.tar"
            with tarfile.open(evil_project, "w") as archive:
                payload = b"escape\n"
                info = tarfile.TarInfo("../escape")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            rejected = subprocess.run(
                [sys.executable, "-c", validator, str(evil_project), "project"],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
            self.assertIn("небезопасный путь", rejected.stdout)

    @unittest.skipUnless(
        os.name == "posix"
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and shutil.which("bash")
        and shutil.which("python3"),
        "нужны Linux root, bash и python3",
    )
    def test_restore_rejects_nested_tar_traversal_before_target_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            project = io.BytesIO()
            with tarfile.open(fileobj=project, mode="w") as archive:
                payload = b"escape\n"
                info = tarfile.TarInfo("../escape")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            backup = base / "kvn-vpn-backup-evil.tar"
            manifest = json.dumps({
                "format": "kvn-vpn-backup-v1",
                "contains_runtime_secrets": True,
            }).encode("utf-8")
            with tarfile.open(backup, "w") as archive:
                for name, payload in {
                    "manifest.json": manifest,
                    "project.tar": project.getvalue(),
                }.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
            target = base / "restored"
            result = subprocess.run(
                [
                    "bash",
                    str(ROOT / "tools" / "restore-backup.sh"),
                    str(backup),
                    str(target),
                ],
                env={
                    **os.environ,
                    "KVN_MAINTENANCE_LOCK": str(base / "maintenance.lock"),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("небезопасный путь", result.stdout)
            self.assertFalse(target.exists())
            self.assertFalse((base / "escape").exists())

    def test_cleanup_script_is_dry_run_and_protects_runtime(self):
        source = (ROOT / "tools/cleanup-project.sh").read_text(encoding="utf-8")
        for marker in [
            "APPLY=0",
            "--apply",
            "[DRY-RUN]",
            "rm -rf -- \"$item\"",
            "users.json",
            "clients|clients/*",
            "certs|certs/*",
            "portal-data|portal-data/*",
            "portal-runtime|portal-runtime/*",
            "nginx/nginx.conf",
            "xray/config.json",
            "amneziawg/awg0.conf",
            "wireguard/wg0.conf",
            "/backup|/backup/*",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
        ]:
            self.assertIn(marker, source)
        dry_run_pos = source.index("[DRY-RUN]")
        delete_pos = source.index("rm -rf -- \"$item\"")
        self.assertLess(dry_run_pos, delete_pos)

    def test_deploy_and_update_lists_include_backup_reference_and_cleanup_files(self):
        build = (ROOT / "tools/build-deploy.sh").read_text(encoding="utf-8")
        update = (ROOT / "update.sh").read_text(encoding="utf-8")
        validator = (ROOT / "tools/deploy_archive.py").read_text(encoding="utf-8")
        schema = (ROOT / "tools/canonical-files.txt").read_text(encoding="utf-8")
        for marker in [
            "tools/cleanup-project.sh",
            "tools/project-backup.sh",
            "tools/restore-backup.sh",
            "portal/app/templates/backups.html",
            "portal/app/templates/backup_result.html",
            "portal/app/templates/project_info.html",
        ]:
            self.assertIn(marker, schema)
        self.assertIn("tools/canonical-files.txt", build)
        self.assertIn("tools/canonical-files.txt", update)
        for marker in ['"backup"', "kvn-vpn-backup-*.tar", '"backup/"']:
            self.assertIn(marker, build + "\n" + update + "\n" + validator)


if __name__ == "__main__":
    unittest.main()
