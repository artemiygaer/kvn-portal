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

from tools.deploy_archive import inspect_archive


ROOT = Path(__file__).resolve().parents[1]


def bash_executable() -> str:
    if os.name == "nt":
        candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
        if candidate.exists():
            return str(candidate)
    return shutil.which("bash") or "bash"


def bash_command(*arguments: str) -> list[str]:
    executable = bash_executable()
    if os.name == "nt":
        # Codex/Windows может передать Git Bash урезанный PATH без /usr/bin.
        return [
            executable,
            "-c",
            'export PATH="/usr/bin:$PATH"; exec "$@"',
            "bash",
            *arguments,
        ]
    return [executable, *arguments]


def canonical_files(root: Path) -> list[str]:
    return (root / "tools/canonical-files.txt").read_text(encoding="utf-8").splitlines()


class DeployBuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name) / "project"
        ignored = shutil.ignore_patterns(
            ".git", ".supergoal", "__pycache__", "*.pyc", "clients", "certs",
            "site-certs", "portal-data", "portal-runtime", ".verify-server-release",
            "kvn-vpn-deploy*.tar.gz", "kvn-vpn-release*.tar.gz", "kvn-vpn-images*.tar",
            "test_on_server",
        )
        shutil.copytree(ROOT, self.project, ignore=ignored)
        placeholder = self.project / "deploy/portal-data/.gitkeep"
        placeholder.parent.mkdir(parents=True, exist_ok=True)
        placeholder.write_bytes(b"")
        runtime_placeholder = self.project / "deploy/portal-runtime/.gitkeep"
        runtime_placeholder.parent.mkdir(parents=True, exist_ok=True)
        runtime_placeholder.write_bytes(b"")

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        env = os.environ.copy()
        if os.name == "nt":
            env["PYTHON3"] = sys.executable
        return subprocess.run(
            bash_command("tools/build-deploy.sh", "package.tar.gz"),
            cwd=self.project,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=45,
            check=False,
        )

    def extracted_bootstrap(self) -> Path:
        target = Path(self.tmp.name) / "bootstrap"
        with tarfile.open(self.project / "package.tar.gz", "r:gz") as archive:
            for relative in ["update.sh", "tools/deploy_archive.py", "tools/canonical-files.txt"]:
                member = archive.getmember(f"deploy/{relative}")
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.extractfile(member).read())
        return target

    def test_clean_build_has_equal_canonical_hashes_and_safe_archive(self):
        dockerfile_before = (self.project / "portal/Dockerfile").read_bytes()
        self.assertFalse((self.project / "portal/build_info.py").exists())
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout)
        expected_manifest = canonical_files(self.project)
        self.assertEqual((self.project / "portal/Dockerfile").read_bytes(), dockerfile_before)
        self.assertFalse((self.project / "portal/build_info.py").exists())
        with tarfile.open(self.project / "package.tar.gz", "r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            manifest = archive.extractfile("deploy/.kvn-canonical-files").read().decode("utf-8").splitlines()
            self.assertEqual(manifest, expected_manifest)
            self.assertNotIn("portal/build_info.py", manifest)
            state = json.loads(archive.extractfile("deploy/users.json").read().decode("utf-8"))
            self.assertEqual(state["users"], [])
            self.assertEqual(state["portal"], {"enabled": False})
            for relative in canonical_files(self.project):
                payload = archive.extractfile(f"deploy/{relative}").read()
                if relative == "portal/Dockerfile":
                    self.assertIn(b"KVN_BUILD_ID=", payload)
                else:
                    self.assertEqual((self.project / relative).read_bytes(), payload, relative)
                self.assertEqual((self.project / "deploy" / relative).read_bytes(), payload, relative)
        self.assertIn("deploy/.kvn-canonical-files", names)
        self.assertIn("deploy/portal/build_info.py", names)
        denied = ["portal.db", "metrics.db", "portal-runtime/users.json", "password_hash", "clients/", ".png", "portal-gateway.conf", ".supergoal"]
        self.assertFalse(any(marker in name for name in names for marker in denied), names)
        metadata = inspect_archive(self.project / "package.tar.gz")
        self.assertEqual(metadata["member_count"], sum(member.isfile() for member in members))

        second = self.build()
        self.assertEqual(second.returncode, 0, second.stdout)
        self.assertEqual((self.project / "portal/Dockerfile").read_bytes(), dockerfile_before)

        cli = subprocess.run(
            [sys.executable, "tools/kvnctl.py", "portal", "status"],
            cwd=self.project / "deploy",
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        self.assertEqual(cli.returncode, 0, cli.stdout)
        self.assertIn("enabled: нет", cli.stdout)

    def test_builder_validator_and_updater_use_one_canonical_schema(self):
        builder = (self.project / "tools/build-deploy.sh").read_text(encoding="utf-8")
        updater = (self.project / "update.sh").read_text(encoding="utf-8")
        validator = (self.project / "tools/deploy_archive.py").read_text(encoding="utf-8")
        self.assertIn("tools/canonical-files.txt", builder)
        self.assertIn("tools/canonical-files.txt", updater)
        self.assertIn("canonical-files.txt", validator)
        self.assertNotIn("canonical=(", updater)

    @unittest.skipUnless(
        os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0,
        "нужен Linux root",
    )
    def test_legacy_install_bootstrap_only_reaches_safe_boundary(self):
        built = self.build()
        self.assertEqual(built.returncode, 0, built.stdout)
        bootstrap = self.extracted_bootstrap()
        installed = Path(self.tmp.name) / "legacy-installed"
        installed.mkdir()
        legacy_update = (ROOT / "tests/fixtures/legacy-deploy/update.sh").read_bytes()
        (installed / "update.sh").write_bytes(legacy_update)
        (installed / "users.json").write_text(
            '{"server":"example.invalid","users":[],"portal":{"enabled":false}}', encoding="utf-8",
        )
        env = os.environ.copy()
        env.update({
            "KVN_UPDATE_WORKER": "1",
            "KVN_UPDATE_ROOT": str(installed),
            "KVN_UPDATE_INSPECTOR": str(bootstrap / "tools/deploy_archive.py"),
            "KVN_UPDATE_MODE": "bootstrap-only",
        })
        result = subprocess.run(
            bash_command(str(bootstrap / "update.sh"), str(self.project / "package.tar.gz")),
            cwd=installed, env=env, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("Bootstrap-only обновление завершено", result.stdout)
        self.assertNotIn("Перегенерирую конфиги", result.stdout)
        self.assertNotIn("Docker-сервисы", result.stdout)
        self.assertNotEqual((installed / "update.sh").read_bytes(), legacy_update)
        self.assertTrue((installed / "portal/agent.py").is_file())

    @unittest.skipUnless(
        os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0,
        "нужен Linux root",
    )
    def test_pre_compose_failure_restores_sources_and_runtime(self):
        built = self.build()
        self.assertEqual(built.returncode, 0, built.stdout)
        bootstrap = self.extracted_bootstrap()
        installed = Path(self.tmp.name) / "rollback-installed"
        installed.mkdir()
        old_update = b"#!/bin/sh\n# OLD-UPDATER\n"
        (installed / "update.sh").write_bytes(old_update)
        users = b"not-json\n"
        (installed / "users.json").write_bytes(users)
        runtime_files = {
            "clients/admin/private.conf": b"client-secret",
            "certs/site/key.pem": b"private-key",
            "portal-data/portal.db": b"sqlite-runtime",
        }
        for relative, payload in runtime_files.items():
            path = installed / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        fake_bin = Path(self.tmp.name) / "fake-bin"
        fake_bin.mkdir()
        docker = fake_bin / "docker"
        docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        docker.chmod(0o755)
        env = os.environ.copy()
        env.update({
            "PATH": f"{fake_bin}{os.pathsep}{env.get('PATH', '')}",
            "KVN_UPDATE_WORKER": "1",
            "KVN_UPDATE_ROOT": str(installed),
            "KVN_UPDATE_INSPECTOR": str(bootstrap / "tools/deploy_archive.py"),
            "KVN_UPDATE_MODE": "full",
        })
        result = subprocess.run(
            bash_command(str(bootstrap / "update.sh"), str(self.project / "package.tar.gz")),
            cwd=installed, env=env, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45, check=False,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("восстанавливаю исходные файлы", result.stdout)
        self.assertEqual((installed / "update.sh").read_bytes(), old_update)
        self.assertEqual((installed / "users.json").read_bytes(), users)
        for relative, payload in runtime_files.items():
            self.assertEqual((installed / relative).read_bytes(), payload)
        self.assertFalse((installed / "portal/agent.py").exists())

    def test_build_rejects_missing_canonical_file(self):
        (self.project / "portal/Dockerfile").unlink()
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Не найден исходный файл: portal/Dockerfile", result.stdout)

    def test_build_rejects_injected_portal_runtime(self):
        runtime = self.project / "deploy/portal-data/portal.db"
        runtime.parent.mkdir(parents=True, exist_ok=True)
        runtime.write_bytes(b"SQLite format 3")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("сгенерированный или устаревший файл", result.stdout)

    def test_build_rejects_injected_portal_state_mirror(self):
        runtime = self.project / "deploy/portal-runtime/users.json"
        runtime.parent.mkdir(parents=True, exist_ok=True)
        runtime.write_text('{"portal":{"password_hash":"secret"}}', encoding="utf-8")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("сгенерированный или устаревший файл", result.stdout)

    def test_build_rejects_malformed_portal_template(self):
        template = self.project / "portal/app/templates/base.html"
        template.write_text(template.read_text(encoding="utf-8") + "\n{% if broken %}\n", encoding="utf-8")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ERROR:PORTAL_TEMPLATE", result.stdout)


class DeployDocumentationTests(unittest.TestCase):
    def test_docs_cover_portal_security_operations_and_recovery(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        deploy = (ROOT / "deploy/DEPLOY.md").read_text(encoding="utf-8")
        for marker in [
            "portal reset-credentials", "portal unlock-ip", "portal configure",
            "kvn-portal-agent.service", "portal-data/portal.db", "/var/lib/kvn-portal/metrics.db",
            "metrics/history.json", "amneziawg verify", "wireguard verify", "reconcile", "/var/run/docker.sock",
            "tools/project-backup.sh", "tools/restore-backup.sh", "tools/cleanup-project.sh", "/backup",
            "раздел «Бэкапы»", "раздел «Проект»", "содержит runtime-секреты",
        ]:
            self.assertIn(marker, readme)
        for marker in [
            "не монтировать Docker socket", "nginx/portal-gateway.conf",
            "portal DB/WAL/SHM", "portal.enabled=false", "Debian-only",
            "kvn-vpn-backup-*.tar", "tools/cleanup-project.sh", "/backup",
        ]:
            self.assertIn(marker, agents)
        for marker in [
            "## Fresh install", "## Upgrade", "## Rollback", "## Backup",
            "<PORTAL_PORT>/tcp", "80/tcp", "kvn-portal-agent.service",
            "kvn-amneziawg.service", "kvn-wireguard.service", "sudo reboot", "4443/udp", "51820/udp", "51821/udp",
            "metrics.db", "72", "QR", "reconcile", "update.sh",
            "## Restore", "tools/project-backup.sh", "tools/restore-backup.sh", "tools/cleanup-project.sh", "/backup",
            "Обновление из GitHub Releases", "--bootstrap-only",
            "ZIP для Telegram", "Прямой отправки через Telegram API нет",
            "/etc/kvn-portal/github.token",
        ]:
            self.assertIn(marker, deploy)

    def test_relative_markdown_links_exist(self):
        documents = [ROOT / "README.md", ROOT / "AGENTS.md", ROOT / "deploy/DEPLOY.md"]
        for document in documents:
            text = document.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
                if "://" in target or target.startswith(("#", "mailto:")):
                    continue
                path_value = target.split("#", 1)[0]
                candidate = (document.parent / path_value).resolve()
                self.assertTrue(candidate.exists(), f"{document}: {target}")


if __name__ == "__main__":
    unittest.main()
