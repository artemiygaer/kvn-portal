"""Буфер/replay/sequence и настоящий Linux PTY для потоковой консоли."""

import base64
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from portal.app import create_app
from portal.app.security import token_hash

from portal.agent import AgentDispatcher, ProtocolError, RootShellSession
from portal.agent_handlers.shell import STREAM_BUFFER_BYTES, stop_stale_shell_units


class ShellStreamTests(unittest.TestCase):
    def session(self):
        now = time.monotonic()
        return RootShellSession("b" * 32, "a" * 64, 99999999, -1, now, now, threading.Lock())

    def test_lost_write_ack_does_not_duplicate_or_allow_changed_payload(self):
        session = self.session()
        session.stream_id = "c" * 32
        with mock.patch("os.write", return_value=4) as write:
            for _ in range(10):
                result = session.ordered_write(session.stream_id, 1, b"test")
                self.assertTrue(result["ok"])
            write.assert_called_once_with(-1, b"test")
        with self.assertRaises(ProtocolError):
            session.ordered_write(session.stream_id, 1, b"changed")
        with self.assertRaises(ProtocolError):
            session.ordered_write(session.stream_id, 3, b"skip")

    def test_partial_input_retries_only_unwritten_suffix(self):
        session = self.session()
        session.stream_id = "c" * 32
        with mock.patch.object(session, "write_bytes", side_effect=[1, 2]) as write:
            self.assertFalse(session.ordered_write(session.stream_id, 1, b"abc")["ok"])
            self.assertTrue(session.ordered_write(session.stream_id, 1, b"abc")["ok"])
            self.assertEqual([item.args[0] for item in write.call_args_list], [b"abc", b"bc"])

    def test_cursor_replay_and_lease_replace_preserve_binary_output(self):
        session = self.session()
        session.stream_id = "c" * 32
        payload = "Ж\x1b[2J\x0eqq\x0f".encode()
        session.output.extend(payload)
        for _ in range(10):
            result = session.read_stream(session.stream_id, 0, 0)
            self.assertEqual(base64.b64decode(result["output_b64"]), payload)
        session.stream_id = "d" * 32
        with self.assertRaises(ProtocolError):
            session.read_stream("c" * 32, 0, 0)
        self.assertEqual(session.read_stream(session.stream_id, len(payload), 0)["output_b64"], "")
        with self.assertRaises(ProtocolError):
            session.read_stream(session.stream_id, 0, 0)
        self.assertEqual(len(session.output), 0)

    @unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "нужен Linux/root PTY")
    def test_real_pty_utf8_resize_reconnect_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            dispatcher = AgentDispatcher(Path(directory))
            session = dispatcher._spawn_root_shell("a" * 64, 28, 100)
            try:
                with session.condition:
                    session.start_stream("c" * 32)
                cursor, output = 0, b""
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and b"# " not in output:
                    result = session.read_stream(session.stream_id, cursor, 100)
                    output += base64.b64decode(result["output_b64"])
                    cursor = result["cursor"]
                self.assertIn(b"# ", output, "Login shell должен закончить startup до первого ввода теста")
                with session.lock:
                    sent = session.ordered_write(session.stream_id, 1, "printf 'STREAM_Ж'; stty size\n".encode())
                self.assertTrue(sent["ok"])
                output = b""
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and b"28 100" not in output:
                    result = session.read_stream(session.stream_id, cursor, 100)
                    output += base64.b64decode(result["output_b64"])
                    cursor = result["cursor"]
                self.assertIn("STREAM_Ж".encode(), output)
                self.assertIn(b"28 100", output)
                pid = session.pid
                for i in range(10):
                    with session.condition:
                        session.start_stream(f"{i + 1:032x}")
                    self.assertEqual(session.pid, pid)
                    session.read_stream(session.stream_id, cursor, 0)
                self.assertIsNone(session.process.poll())
            finally:
                session.close()
            self.assertFalse(session.reader.is_alive())
            self.assertIsNotNone(session.process.poll())
            self.assertEqual(session.fd, -1)

    @unittest.skipUnless(os.name == "posix", "нужен PTY fd")
    def test_output_backpressure_is_bounded_and_does_not_block_input(self):
        session = self.session()
        read_fd, write_fd = os.pipe()
        session.fd = read_fd
        session.output.extend(b"x" * STREAM_BUFFER_BYTES)
        try:
            with session.condition:
                session.start_stream("c" * 32)
            time.sleep(0.05)
            self.assertEqual(len(session.output), STREAM_BUFFER_BYTES)
            self.assertTrue(session.lock.acquire(timeout=0.2))
            session.lock.release()
        finally:
            session.close()
            os.close(write_fd)

    def test_threaded_parent_no_longer_uses_forkpty(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "portal/agent_handlers/dispatcher.py").read_text(encoding="utf-8")
        self.assertNotIn("os.forkpty(", source)

    def test_foreign_owner_never_obtains_shell_session(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"))
        session = self.session()
        dispatcher.root_shells[session.session_id] = session
        with self.assertRaises(ProtocolError) as denied:
            dispatcher._shell_by_id({"shell_id": session.session_id, "session_owner": "e" * 64})
        self.assertEqual(denied.exception.code, "not_found")

    @unittest.skipUnless(os.name == "posix", "нужен PTY")
    def test_pam_waits_for_prompt_before_sending_password(self):
        process = mock.Mock()
        process.poll.side_effect = [None, None, 0, 0]
        process.returncode = 0
        with (mock.patch("os.openpty", return_value=(10000, 10001)),
              mock.patch("subprocess.Popen", return_value=process),
              mock.patch("os.close"), mock.patch("os.write") as write,
              mock.patch("portal.agent_handlers.dispatcher.select.select",
                         side_effect=[([], [], []), ([10000], [], []), ([10000], [], [])]),
              mock.patch("os.read", side_effect=[b"Pass", b"word: "])):
            self.assertTrue(AgentDispatcher._password_auth_pty(["/bin/su"], "fixture-password"))
        write.assert_called_once_with(10000, b"fixture-password\n")

    def test_new_stream_open_never_consumes_the_initial_raw_utf8(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"))
        session = self.session()
        with (mock.patch.object(dispatcher, "_verify_root_password", return_value=True),
              mock.patch.object(dispatcher, "_ensure_root_shell_reaper"),
              mock.patch.object(dispatcher, "_spawn_root_shell", return_value=session),
              mock.patch.object(session, "start_stream") as start,
              mock.patch.object(dispatcher, "_read_shell_locked") as legacy):
            result = dispatcher._shell_open({"root_password": "fixture-password", "session_owner": session.owner,
                                             "rows": 24, "cols": 100, "stream": True})
        self.assertEqual(result["output"], "")
        start.assert_called_once()
        legacy.assert_not_called()

    def test_agent_restart_stops_only_own_strictly_named_transient_units(self):
        output = ("kvn-portal-root-shell-123456789abc.service loaded active running\n"
                  "kvn-portal-root-shell-evil.service loaded active running\n"
                  "unrelated.service loaded active running\n")
        with (mock.patch("pathlib.Path.is_dir", return_value=True),
              mock.patch("subprocess.run", side_effect=[mock.Mock(stdout=output), mock.Mock()]) as run):
            stop_stale_shell_units()
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0],
                         ["systemctl", "stop", "kvn-portal-root-shell-123456789abc.service"])


class ShellWebSocketSecurityTests(unittest.TestCase):
    """Настоящий library WebSocket, auth/Origin/CSRF/logout, без исполнения команд."""

    def setUp(self):
        from werkzeug.serving import make_server, WSGIRequestHandler
        self.directory = tempfile.TemporaryDirectory()
        root = Path(self.directory.name)
        self.calls = []

        class Agent:
            def call(inner, method, params, **_kwargs):
                self.calls.append((method, params))
                if method == "shell.read":
                    if not params.get("attach"):
                        time.sleep(0.04)
                    return {"ok": True, "alive": True, "output_b64": "", "cursor": 0, "input_seq": 0}
                return {"ok": True, "alive": False}

        class QuietHandler(WSGIRequestHandler):
            def log(self, *_args, **_kwargs):
                pass

        self.app = create_app({"TESTING": True, "DATABASE": root / "portal.db",
                               "USERS_FILE": root / "users.json", "PORTAL_PATH": "/gaer",
                               "PROXY_SECRET": "fixture-secret", "AGENT_CLIENT": Agent()})
        self.storage = self.app.extensions["kvn_storage"]
        self.token, self.csrf = self.storage.create_session("192.0.2.42", "fixture")
        self.server = make_server("127.0.0.1", 0, self.app, threaded=True, request_handler=QuietHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host = f"127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.directory.cleanup()

    def connect(self, *, origin=None, cookie=True):
        from simple_websocket import Client

        class ClosingClient(Client):
            def handshake(inner):
                try:
                    super().handshake()
                except Exception:
                    # Client 1.1 не закрывает socket при отклонённом handshake.
                    inner.sock.close()
                    raise
        # simple-websocket 1.1 Client исключает port из Host handshake; Origin
        # совпадает с фактически отправленным Host, production browser сохраняет port.
        headers = {"Origin": origin or "https://127.0.0.1",
                   "X-KVN-Proxy-Secret": "fixture-secret", "X-Forwarded-Proto": "https",
                   "X-Real-IP": "192.0.2.42", "User-Agent": "fixture"}
        if cookie:
            headers["Cookie"] = "kvn_portal_session=" + self.token
        return ClosingClient(f"ws://{self.host}/gaer/terminal/shell/stream", headers=headers)

    def hello(self, client, csrf=None):
        client.send(json.dumps({"type": "hello", "shell_id": "b" * 32,
                                "cursor": 0, "csrf": self.csrf if csrf is None else csrf}))

    def test_wrong_origin_and_missing_session_are_denied_before_rpc(self):
        from simple_websocket import ConnectionError
        for kwargs in ({"origin": "https://attacker.invalid"}, {"cookie": False}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ConnectionError):
                self.connect(**kwargs)
        self.assertEqual(self.calls, [])

    def test_bad_csrf_closes_before_rpc(self):
        from simple_websocket import ConnectionClosed
        client = self.connect()
        self.hello(client, csrf="wrong")
        with self.assertRaises(ConnectionClosed):
            client.receive(timeout=2)
        self.assertEqual(self.calls, [])

    def test_fifty_disconnects_do_not_leak_threads_or_file_descriptors(self):
        before_threads = threading.active_count()
        before_fds = len(os.listdir("/proc/self/fd")) if Path("/proc/self/fd").is_dir() else None
        for _ in range(50):
            client = self.connect()
            self.hello(client)
            self.assertEqual(json.loads(client.receive(timeout=2))["type"], "ready")
            client.close()
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and threading.active_count() > before_threads + 1:
            time.sleep(0.05)
        self.assertLessEqual(threading.active_count(), before_threads + 1)
        if before_fds is not None:
            self.assertLessEqual(len(os.listdir("/proc/self/fd")), before_fds + 1)

    def test_worker_recycling_closes_only_transport(self):
        from simple_websocket import ConnectionClosed
        from portal.app.routes import shell_stream
        worker = types.SimpleNamespace(alive=True)
        with mock.patch.object(shell_stream, "_worker", worker):
            client = self.connect()
            self.hello(client)
            self.assertEqual(json.loads(client.receive(timeout=2))["type"], "ready")
            worker.alive = False
            with self.assertRaises(ConnectionClosed):
                client.receive(timeout=3)
        self.assertFalse(any(method == "shell.close" for method, _params in self.calls))

    def test_logout_and_password_reset_revoke_live_stream_and_no_content_is_audited(self):
        from simple_websocket import ConnectionClosed
        for all_sessions in (False, True):
            if all_sessions:
                self.token, self.csrf = self.storage.create_session("192.0.2.42", "fixture")
            client = self.connect()
            self.hello(client)
            self.assertEqual(json.loads(client.receive(timeout=2))["type"], "ready")
            reads = [params for method, params in self.calls if method == "shell.read"]
            self.assertEqual(reads[-1]["session_owner"], token_hash(self.token))
            if all_sessions:
                self.storage.invalidate_all_sessions()
            else:
                self.storage.invalidate_session(self.token)
            message = json.loads(client.receive(timeout=3))
            self.assertEqual(message, {"type": "error", "code": "session_expired"})
            with self.assertRaises(ConnectionClosed):
                client.receive(timeout=2)
            self.assertTrue(any(method == "shell.close" for method, _params in self.calls))
        self.assertEqual(self.storage.list_audit()["total"], 0)


if __name__ == "__main__":
    unittest.main()
