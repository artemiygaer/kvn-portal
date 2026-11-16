"""Проверки схемы, прав и реального Unix-сокета агента v5."""

import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from v5.core.agent import AgentApplication, AgentServer, MAX_REQUEST
from v5.core.host_status import HostStatus
from v5.core.site.document import DEFAULT_SITE, MAX_HTML_BYTES, SiteStore
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.queue import TLSQueue
from v5.portal.rpc import HostClient


class AgentContractTests(unittest.TestCase):
    def test_tls_import_is_bounded_registered_and_secret_free_in_response(self):
        identity = TLSIdentity("portal.example", False)
        chain, key = b"synthetic-chain", b"synthetic-secret-key"
        with tempfile.TemporaryDirectory() as directory:
            queue = TLSQueue(Path(directory))
            app = AgentApplication(123, tls=queue, tls_registry=lambda: ((identity,), False))
            request = {"version": 1, "method": "tls.import", "params": {
                "name": identity.name, "chain_size": len(chain), "key_size": len(key)}}
            self.assertEqual(app.dispatch(124, request, body=chain + key)["error"], "forbidden")
            self.assertEqual(app.dispatch(123, {**request, "params": {**request["params"], "name": "evil.example"}},
                                          body=chain + key)["error"], "invalid_request")
            self.assertEqual(app.dispatch(123, request, body=chain + key + b"x")["error"], "invalid_request")
            self.assertEqual(app.dispatch(123, {**request, "params": {**request["params"], "key_size": 16385}},
                                          body=chain + key)["error"], "invalid_request")
            result = app.dispatch(123, request, body=chain + key)
            self.assertEqual(result, {"ok": True, "result": {"queued": True}})
            self.assertNotIn(key.decode(), json.dumps(result))
            self.assertEqual(queue.pending.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(key.decode(), json.dumps(app.dispatch(123, {"version": 1, "method": "tls.status", "params": {}})))
            with queue.exclusive():
                job = queue.take((identity,))
            self.assertEqual((job.identity, job.chain, job.key), (identity, chain, key))
            self.assertNotIn(key.decode(), repr(job))
            self.assertFalse(queue.pending.exists())

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Требуется Linux SO_PEERCRED")
    def test_tls_import_over_real_socket_never_returns_key(self):
        identity = TLSIdentity("portal.example", False)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            queue = TLSQueue(root)
            app = AgentApplication(os.getuid(), tls=queue, tls_registry=lambda: ((identity,), False))
            with AgentServer(root / "agent.sock", app) as server:
                thread = threading.Thread(target=server.handle_request, daemon=True)
                thread.start()
                result = HostClient(root / "agent.sock").tls_import(identity.name, b"chain", b"private-fixture")
                thread.join(3)
                self.assertFalse(thread.is_alive())
            self.assertEqual(result, {"queued": True})
            self.assertNotIn("private-fixture", json.dumps(result))
            with queue.exclusive():
                job = queue.take((identity,))
            self.assertEqual(job.key, b"private-fixture")

    def test_dispatch_is_closed_and_strict(self):
        app = AgentApplication(123)
        request = {"version": 1, "method": "health", "params": {}}
        self.assertEqual(app.dispatch(124, request)["error"], "forbidden")
        self.assertTrue(app.dispatch(123, request)["ok"])
        for changed in ({"params": {"command": "id"}}, {"version": True}, {"extra": 0}):
            self.assertEqual(app.dispatch(123, {**request, **changed})["error"], "invalid_request")
        self.assertEqual(app.dispatch(123, {**request, "method": "shell"})["error"], "unknown_method")

    def test_tls_dispatch_enqueues_only_registered_jobs_and_does_not_return_email(self):
        identity = TLSIdentity("portal.example", False)
        with tempfile.TemporaryDirectory() as directory:
            queue = TLSQueue(Path(directory))
            app = AgentApplication(123, tls=queue, tls_registry=lambda: ((identity,), False))
            issue = {"version": 1, "method": "tls.issue",
                     "params": {"name": identity.name, "mode": "staging", "email": "ops@example.net"}}
            status = {"version": 1, "method": "tls.status", "params": {}}
            self.assertEqual(app.dispatch(124, issue)["error"], "forbidden")
            self.assertEqual(app.dispatch(123, {**issue, "params": {**issue["params"], "name": "evil.example"}})["error"],
                             "invalid_request")
            self.assertEqual(app.dispatch(123, {**issue, "params": {**issue["params"], "argv": "arbitrary"}})["error"],
                             "invalid_request")
            self.assertFalse(queue.pending.exists())
            self.assertTrue(app.dispatch(123, issue)["ok"])
            self.assertEqual(queue.pending.stat().st_mode & 0o777, 0o600)
            self.assertEqual(app.dispatch(123, issue)["error"], "tls_busy")
            snapshot = app.dispatch(123, status)["result"]
            self.assertTrue(snapshot["busy"])
            self.assertNotIn("ops@example.net", json.dumps(snapshot))
            with queue.exclusive():
                self.assertEqual(queue.take((identity,)).identity, identity)
            self.assertFalse(app.dispatch(123, status)["result"]["busy"])

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Требуется Linux SO_PEERCRED")
    def test_site_rpc_has_bounded_body_and_preserves_previous_page_on_invalid_frame(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "agent.sock"
            store = SiteStore(root)
            store.reset()
            with AgentServer(path, AgentApplication(os.getuid(), site=store)) as server:
                client = HostClient(path)

                def call(function):
                    thread = threading.Thread(target=server.handle_request, daemon=True)
                    thread.start()
                    try:
                        return function()
                    finally:
                        thread.join(3)
                        self.assertFalse(thread.is_alive())

                html = b"<p>" + b"x" * (60 * 1024) + b"</p>"
                self.assertTrue(call(lambda: client.site_publish(html))["published"])
                self.assertTrue(call(client.site_status)["customized"])
                stored = (root / "index.html").read_bytes()
                self.assertIn(html, stored)

                def invalid(declared, body):
                    message = {"version": 1, "method": "site.publish", "params": {"size": declared}}
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(3)
                        connection.connect(str(path))
                        connection.sendall(json.dumps(message).encode() + b"\n" + body)
                        connection.shutdown(socket.SHUT_WR)
                        with connection.makefile("rb") as stream:
                            return json.loads(stream.readline())["error"]

                for declared, body in ((len(html) - 1, html), (len(html) + 1, html), (True, b""),
                                       (MAX_HTML_BYTES + 1, b"")):
                    self.assertEqual(call(lambda: invalid(declared, body)), "invalid_request")
                    self.assertEqual((root / "index.html").read_bytes(), stored)
                self.assertTrue(call(client.site_reset)["reset"])
                self.assertEqual((root / "index.html").read_bytes(), DEFAULT_SITE)

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Требуется Linux SO_PEERCRED")
    def test_real_socket_permissions_and_peer_uid(self):
        for uid, expected in ((os.getuid(), True), (os.getuid() + 1, False)):
            with self.subTest(uid=uid), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "agent.sock"
                with AgentServer(path, AgentApplication(uid)) as server:
                    thread = threading.Thread(target=server.handle_request, daemon=True)
                    thread.start()
                    self.assertEqual(path.stat().st_mode & 0o777, 0o660)
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                        connection.settimeout(3)
                        connection.connect(str(path))
                        if expected:
                            connection.sendall(b'{"version":1,"method":"health","params":{}}\n')
                        with connection.makefile("rb") as stream:
                            self.assertEqual(json.loads(stream.readline())["ok"], expected)
                    thread.join(3)
                    self.assertFalse(thread.is_alive())

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "Требуется Linux SO_PEERCRED")
    def test_oversized_request_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agent.sock"
            with AgentServer(path, AgentApplication(os.getuid())) as server:
                thread = threading.Thread(target=server.handle_request, daemon=True)
                thread.start()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(3)
                    connection.connect(str(path))
                    connection.sendall(b" " * (MAX_REQUEST + 1) + b"\n")
                    with connection.makefile("rb") as stream:
                        self.assertEqual(json.loads(stream.readline())["error"], "invalid_request")
                thread.join(3)

    def test_snapshot_uses_cpu_deltas_and_never_writes_history(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            (proc / "net").mkdir()
            (proc / "stat").write_text("cpu 1 0 0 9 0 0 0 0\n", encoding="ascii")
            (proc / "meminfo").write_text("MemTotal: 1024 kB\nMemAvailable: 512 kB\n", encoding="ascii")
            (proc / "net/dev").write_text("header\nheader\neth0: 10 0 0 0 0 0 0 0 20\nlo: 99\n", encoding="ascii")
            (proc / "uptime").write_text("123.4 5\n", encoding="ascii")
            status = HostStatus(proc, proc)
            self.assertIsNone(status.snapshot()["cpu_percent"])
            (proc / "stat").write_text("cpu 3 0 0 17 0 0 0 0\n", encoding="ascii")
            result = status.snapshot()
            self.assertEqual(result["cpu_percent"], 20)
            self.assertEqual(result["memory"]["available_bytes"], 512 * 1024)
            self.assertEqual(result["network"], {"received_bytes": 10, "sent_bytes": 20})
            self.assertEqual(result["uptime_seconds"], 123.4)
            self.assertIsNone(result["history_enabled"])
