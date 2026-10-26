"""Контракты lifecycle Unix RPC между порталом и host-agent."""

from __future__ import annotations

import os
import socket
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from portal.agent import AgentApplication, AgentDispatcher, ThreadingUnixServer
from portal.agent_client import AgentClient, AgentClientError
from portal.app.agent_errors import map_agent_error


SECRET = "b" * 64


class RuntimeBridgeTests(unittest.TestCase):
    def test_capability_contract_is_typed_and_generation_changes(self):
        first = AgentDispatcher(Path("/srv/kvn"))
        second = AgentDispatcher(Path("/srv/kvn"))
        left = first._ping({})
        right = second._ping({})
        self.assertRegex(left["generation"], r"^[0-9a-f]{32}$")
        self.assertNotEqual(left["generation"], right["generation"])
        self.assertEqual(left["status"], "ok")
        self.assertEqual(left["transport"], "unix")
        self.assertTrue({"rpc-v1", "dashboard-snapshot-v1", "runtime-apply-v1"}.issubset(left["capabilities"]))

    @unittest.skipUnless(hasattr(socket, "AF_UNIX") and os.name != "nt", "нужен Unix socket")
    def test_reused_client_recovers_after_agent_restart_within_ten_seconds(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary)
            socket_path = runtime / "control.sock"
            runtime_inode = runtime.stat().st_ino
            client = AgentClient(socket_path, SECRET, timeout=1)

            def start():
                application = AgentApplication(SECRET, AgentDispatcher(Path("/srv/kvn")))
                server = ThreadingUnixServer(socket_path, application)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                return server, thread

            server, thread = start()
            first = client.call("ping", {})
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            socket_path.unlink(missing_ok=True)

            started = time.monotonic()
            server, thread = start()
            try:
                while True:
                    try:
                        second = client.call("ping", {})
                        break
                    except AgentClientError:
                        if time.monotonic() - started >= 10:
                            raise
                        time.sleep(0.1)
                self.assertLess(time.monotonic() - started, 10)
                self.assertNotEqual(first["generation"], second["generation"])
                self.assertEqual(runtime.stat().st_ino, runtime_inode)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_error_code_http_matrix_is_distinct_and_safe(self):
        expected = {
            "awg31_unsupported": 409,
            "validation_error": 400,
            "revision_conflict": 409,
            "transport_unavailable": 503,
        }
        messages = set()
        for code, status in expected.items():
            mapped = map_agent_error(AgentClientError("sensitive detail", code=code))
            self.assertEqual(mapped.code, code)
            self.assertEqual(mapped.status, status)
            self.assertNotIn("sensitive", mapped.message)
            messages.add(mapped.message)
        self.assertEqual(len(messages), len(expected))

    def test_installer_preserves_runtime_inode_and_checks_permissions(self):
        source = (Path(__file__).resolve().parents[1] / "portal/install-host-agent.sh").read_text(encoding="utf-8")
        for marker in (
            "RuntimeDirectoryPreserve=restart",
            "root:kvn-portal:750",
            "root:kvn-portal:660",
            "root:kvn-portal:640",
            'client.call("ping", {})',
            'capability.get("generation")',
        ):
            self.assertIn(marker, source)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "нужен POSIX Bash")
    def test_installer_fingerprint_changes_for_release_code_and_schema_only(self):
        source = (Path(__file__).resolve().parents[1] / "portal/install-host-agent.sh").read_text(encoding="utf-8")
        snippet = source[source.index("agent_sources=("):source.index("installed_fingerprint=")]
        snippet += '\nprintf "%s\\n" "$source_fingerprint"\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = (
                "portal/agent.py", "portal/agent_protocol.py", "portal/agent_handlers/shell.py",
                "portal/control.py", "portal/control/exports.py", "portal/github_updates.py",
                "portal/metrics.py", "portal/system_user_helper.py", "tools/kvnctl.py",
                "tools/kvnlib/runtime/runner.py", "tools/deploy_archive.py",
                "tools/release/full_archive.py", "tools/canonical-files.txt", "VERSION",
            )
            for relative in files:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("fixture\n", encoding="utf-8")

            def fingerprint():
                return subprocess.check_output(["bash", "-euo", "pipefail", "-c", snippet],
                                               env={**os.environ, "ROOT_DIR": str(root)}, text=True).strip()

            previous = fingerprint()
            self.assertEqual(previous, fingerprint())
            for relative in ("tools/deploy_archive.py", "tools/release/full_archive.py",
                             "tools/canonical-files.txt", "VERSION", "portal/root_shell_helper.py"):
                (root / relative).write_text("changed\n", encoding="utf-8")
                current = fingerprint()
                self.assertNotEqual(previous, current, relative)
                self.assertEqual(current, fingerprint())
                previous = current

    def test_portal_compose_mounts_exclude_docker_socket(self):
        compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
        portal = compose.split("  portal:\n", 1)[1].split("\n  portal-gateway:\n", 1)[0]
        self.assertIn("/run/kvn-portal:/run/kvn-portal:ro", portal)
        self.assertNotIn("docker.sock", portal)
