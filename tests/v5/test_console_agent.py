"""Закрытая граница root-консоли и живой управляющий PTY в WSL."""

import os
from pathlib import Path
import shutil
import socket
from tempfile import TemporaryDirectory
from threading import Thread
import time
from unittest import TestCase, skipUnless
from unittest.mock import Mock, patch

from v5.core.console import AGENT_UNIT, SOCKET_UNIT
from v5.core.console.agent import ConsoleAgent
from v5.core.console.auth import _crypt, verify_root
from v5.core.console.leases import GRANT_SECONDS, Leases
from v5.core.console.protocol import HEADER, INPUT, MAX_FRAME, OUTPUT, RESIZE, SIZE, frame, read_frame, read_line, send_line
from v5.core.console.pty import Terminal
from v5.core.release import SERVICES, TRIGGERS, UNIT_FILES
from v5.portal.app import create_app

SID = "a" * 32
OTHER = "b" * 32


class ConsoleAuthTests(TestCase):
    def test_shadow_rejects_locked_empty_expired_and_wrong_password(self):
        digest = _crypt(b"fixture-password", b"$6$testsalt$")
        self.assertTrue(digest.startswith(b"$6$"))
        with TemporaryDirectory() as directory:
            shadow = Path(directory) / "shadow"
            clock = lambda: 30000 * 86400
            rows = (
                (b"root:" + digest + b":29999:0:30:7:::", True),
                (b"root:!" + digest + b":29999:0:30:7:::", False),
                (b"root::29999:0:30:7:::", False),
                (b"root:" + digest + b":29999:0:30:7::30000:", False),
                (b"root:" + digest + b":29899:0:30:7:::", False),
                (b"root:" + digest + b":0:0:30:7:::", False),
            )
            for line, allowed in rows:
                shadow.write_bytes(line + b"\n")
                self.assertEqual(verify_root("fixture-password", shadow=shadow, clock=clock), allowed)
                self.assertFalse(verify_root("wrong", shadow=shadow, clock=clock))
            self.assertFalse(verify_root("fixture-password\0", shadow=shadow, clock=clock))

    def test_grant_binding_consumption_expiry_and_revoke(self):
        now = [0]
        leases = Leases(lambda value: value == "root", clock=lambda: now[0])
        grant = leases.issue(SID, "root")
        with self.assertRaisesRegex(ValueError, "grant_invalid"):
            leases.consume(OTHER, grant)
        lease = leases.consume(SID, grant)
        with self.assertRaisesRegex(ValueError, "grant_invalid"):
            leases.consume(SID, grant)
        leases.revoke(OTHER)
        self.assertFalse(lease.cancelled.is_set())
        leases.revoke(SID)
        self.assertTrue(lease.cancelled.is_set())
        leases.release(lease)
        with self.assertRaisesRegex(ValueError, "session_revoked"):
            leases.issue(SID, "root")
        grant = leases.issue("c" * 32, "root")
        now[0] = GRANT_SECONDS
        with self.assertRaisesRegex(ValueError, "grant_invalid"):
            leases.consume("c" * 32, grant)

    def test_bruteforce_limited_before_second_password_check(self):
        auth = Mock(return_value=False)
        leases = Leases(auth)
        for _ in range(5):
            with self.assertRaisesRegex(ValueError, "auth_failed"):
                leases.issue(SID, "неверный")
        with self.assertRaisesRegex(ValueError, "console_busy"):
            leases.issue(OTHER, "неверный")
        self.assertEqual(auth.call_count, 5)

    def test_console_not_enabled_by_installer_and_http_ws_routes_are_closed(self):
        self.assertIn(AGENT_UNIT, UNIT_FILES)
        self.assertIn(SOCKET_UNIT, UNIT_FILES)
        self.assertNotIn(AGENT_UNIT, SERVICES)
        self.assertNotIn(SOCKET_UNIT, TRIGGERS)
        units = Path(__file__).resolve().parents[2] / "v5/install/systemd"
        self.assertIn(f"PartOf={SOCKET_UNIT}", (units / AGENT_UNIT).read_text())
        self.assertIn("KillMode=control-group", (units / AGENT_UNIT).read_text())
        browser = create_app({"session_key": "fixture", "allowed_hosts": ["localhost:8443"]},
                             client=Mock()).test_client()
        origin = "https://localhost:8443"
        for path in ("/maintenance/console", "/maintenance/console/ws"):
            self.assertEqual(browser.get(path, base_url=origin, headers={"Upgrade": "websocket"}).status_code, 404)


class AgentTests(TestCase):
    def connect(self, agent):
        local, remote = socket.socketpair()
        def serve():
            with remote:
                agent.handle(remote)
        worker = Thread(target=serve, daemon=True)
        worker.start()
        self.addCleanup(local.close)
        self.addCleanup(worker.join, 3)
        return local, worker

    def exchange(self, agent, request):
        connection, worker = self.connect(agent)
        with connection:
            send_line(connection, request)
            response = read_line(connection)
        worker.join(4)
        self.assertFalse(worker.is_alive())
        return response

    def test_peer_and_schema_before_password_lookup_and_never_audit_fields(self):
        auth = Mock(return_value=True)
        request = {"op": "authorize", "session": SID, "password": "private fixture"}
        denied = ConsoleAgent(os.geteuid() + 1, leases=Leases(auth))
        connection, worker = self.connect(denied)
        with connection:
            self.assertEqual(read_line(connection)["error"], "forbidden")
        worker.join(4)
        agent = ConsoleAgent(os.geteuid(), leases=Leases(auth))
        with patch("v5.core.console.agent.audit.record") as record:
            self.assertEqual(self.exchange(agent, {**request, "cmd": "fixture"})["error"], "invalid_request")
            auth.assert_not_called()
            self.assertTrue(self.exchange(agent, request)["ok"])
            self.assertEqual(record.call_args.args, ("console.authorize", True))
            self.assertNotIn("private fixture", repr(record.mock_calls))

    def test_frame_limits_precede_payload_and_input_has_only_typed_frames(self):
        left, right = socket.socketpair()
        with left, right:
            for invalid in (HEADER.pack(INPUT, MAX_FRAME + 1), HEADER.pack(RESIZE, 2), HEADER.pack(99, 10)):
                left.sendall(invalid)
                with self.assertRaisesRegex(ValueError, "invalid_frame"):
                    read_frame(right)
            left.sendall(b'{"op":"revoke","op":"authorize"}\n')
            with self.assertRaisesRegex(ValueError, "invalid_request"):
                read_line(right)

    def test_actual_tty_size_interactive_output_and_revoke(self):
        with TemporaryDirectory() as directory:
            agent = ConsoleAgent(os.geteuid(), leases=Leases(lambda _: True),
                                 terminal=lambda rows, columns: Terminal(rows, columns, home=directory))
            grant = self.exchange(agent, {"op": "authorize", "session": SID, "password": "fixture"})["grant"]
            connection, worker = self.connect(agent)
            with connection:
                send_line(connection, {"op": "attach", "session": SID, "grant": grant, "rows": 24, "columns": 80})
                self.assertEqual(read_line(connection), {"ok": True})
                connection.sendall(frame(RESIZE, SIZE.pack(42, 120)))
                connection.sendall(frame(INPUT, b"stty size; echo \"$TERM\"\n"))
                self._until(connection, (b"42 120", b"xterm-256color"))
                self.assertTrue(self.exchange(agent, {"op": "revoke", "session": SID})["ok"])
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        read_frame(connection)
                    except EOFError:
                        break
                else:
                    self.fail("Отозванный PTY не закрылся")
            worker.join(4)
            self.assertFalse(worker.is_alive())

    @skipUnless(shutil.which("mc") and shutil.which("htop"), "Требуются mc и htop в WSL")
    def test_mc_and_htop_render_over_real_pty(self):
        with TemporaryDirectory() as directory:
            agent = ConsoleAgent(os.geteuid(), leases=Leases(lambda _: True),
                                 terminal=lambda rows, columns: Terminal(rows, columns, home=directory))
            grant = self.exchange(agent, {"op": "authorize", "session": SID, "password": "fixture"})["grant"]
            connection, worker = self.connect(agent)
            with connection:
                send_line(connection, {"op": "attach", "session": SID, "grant": grant, "rows": 35, "columns": 110})
                self.assertEqual(read_line(connection), {"ok": True})
                connection.sendall(frame(INPUT, b"mc -u\n"))
                self._until(connection, (b"Left", b"Right", b"\x1b["))
                connection.sendall(frame(INPUT, b"\x1b[21~"))
                self._until(connection, (b"bash-",))
                connection.sendall(frame(INPUT, b"htop -d 2\n"))
                self._until(connection, (b"Tasks", b"\x1b["))
                connection.sendall(frame(INPUT, b"q"))
                self._until(connection, (b"bash-",))
                connection.sendall(frame(INPUT, b"exit\n"))
            worker.join(4)
            self.assertFalse(worker.is_alive())

    def _until(self, connection, markers):
        output = bytearray()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            kind, data = read_frame(connection)
            self.assertEqual(kind, OUTPUT)
            output.extend(data)
            if all(mark in output for mark in markers):
                return
            if len(output) > 256 * 1024:
                break
        self.fail("PTY не прислал ожидаемый экран или ответ")
