"""Контракты lifecycle Unix RPC между порталом и host-agent."""

from __future__ import annotations

import os
import socket
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

    def test_portal_compose_mounts_exclude_docker_socket(self):
        compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
        portal = compose.split("  portal:\n", 1)[1].split("\n  portal-gateway:\n", 1)[0]
        self.assertIn("/run/kvn-portal:/run/kvn-portal:ro", portal)
        self.assertNotIn("docker.sock", portal)
