"""Проверка HTTP-границы и WebSocket до настоящего PTY через два Unix-сокета."""

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import socket
from socketserver import BaseRequestHandler, ThreadingUnixStreamServer
from tempfile import TemporaryDirectory
from threading import Thread
from unittest import IsolatedAsyncioTestCase, TestCase, skipUnless
from unittest.mock import Mock

from tests.v5.test_console_agent import OTHER, SID
from v5.core.console.agent import ConsoleAgent
from v5.core.console.leases import Leases
from v5.core.console.pty import Terminal
from v5.portal.app import create_app
from v5.portal.console_ws import BrowserGate, Bridge, COOKIE, WS_PATH, serve

HOST = "localhost:8443"
ORIGIN = "https://" + HOST
CONFIG = {"session_key": "fixture-only", "allowed_hosts": [HOST]}


class Headers(dict):
    def get_all(self, name):
        return self.get(name, [])


class ConsoleWebTests(TestCase):
    def test_ws_origin_cookie_and_path_match_without_tickets_in_url(self):
        gate = BrowserGate(CONFIG)
        cookie = COOKIE + "=" + gate.serializer.dumps({"admin": True, "console_sid": SID})
        valid = Headers(Host=[HOST], Origin=[ORIGIN], Cookie=[cookie])
        self.assertEqual(gate.binding(WS_PATH, valid)[0], SID)
        for headers in (
            Headers(valid, Origin=["https://localhost"]), Headers(valid, Origin=[ORIGIN, ORIGIN]),
            Headers(valid, Host=["example.invalid:8443"]), Headers(valid, Cookie=[cookie + "x"]),
            Headers(valid, Cookie=[COOKIE + "=" + gate.serializer.dumps({"admin": True})]),
        ):
            self.assertIsNone(gate.binding(WS_PATH, headers))
        self.assertIsNone(gate.binding(WS_PATH + "?grant=fixture", valid))

    def test_http_requires_enabled_admin_origin_csrf_and_never_returns_password(self):
        gateway = Mock()
        gateway.available.return_value = True
        gateway.authorize.return_value = {"ok": True, "grant": "c" * 32}
        app = create_app(CONFIG, client=Mock(), console_client=gateway)
        browser = app.test_client()
        self.assertEqual(browser.get("/maintenance/console", base_url=ORIGIN).status_code, 404)
        with browser.session_transaction(base_url=ORIGIN) as session:
            session.update(admin=True, console_sid=SID, csrf="fixture-csrf")
        page = browser.get("/maintenance/console", base_url=ORIGIN)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"xterm.js", page.data)
        self.assertIn("connect-src 'self'", page.headers["Content-Security-Policy"])
        self.assertIn("style-src 'self' 'unsafe-inline';", page.headers["Content-Security-Policy"])
        self.assertIn("script-src 'self';", page.headers["Content-Security-Policy"])
        maintenance = browser.get("/maintenance", base_url=ORIGIN)
        self.assertNotIn(b"xterm.js", maintenance.data)
        self.assertNotIn("'unsafe-inline'", maintenance.headers["Content-Security-Policy"])
        endpoint = "/maintenance/console/authorize"
        password = "fixture-local-password"
        form = {"csrf": "fixture-csrf", "root_password": password}
        self.assertEqual(browser.post(endpoint, base_url=ORIGIN, data=form).status_code, 403)
        self.assertEqual(browser.post(endpoint, base_url=ORIGIN, data={**form, "csrf": "wrong"},
                                      headers={"Origin": ORIGIN}).status_code, 403)
        gateway.authorize.assert_not_called()
        reply = browser.post(endpoint, base_url=ORIGIN, data=form, headers={"Origin": ORIGIN})
        self.assertEqual(reply.json, {"grant": "c" * 32})
        self.assertNotIn(password.encode(), reply.data)
        gateway.authorize.assert_called_once_with(SID, password)
        self.assertEqual(browser.post("/logout", base_url=ORIGIN, data={"csrf": "fixture-csrf"},
                                      headers={"Origin": ORIGIN}).status_code, 303)
        gateway.revoke.assert_called_once_with(SID)


@skipUnless(importlib.util.find_spec("websockets"), "Нужен необязательный пакет python3-websockets")
class ConsoleWebSocketTests(IsolatedAsyncioTestCase):
    async def test_unix_websocket_to_pty_cross_origin_and_session_revoke(self):
        from websockets.exceptions import ConnectionClosed, InvalidStatusCode
        from websockets.legacy.client import unix_connect

        with TemporaryDirectory() as directory:
            root = Path(directory)
            leases = Leases(lambda _: True)
            agent = ConsoleAgent(os.geteuid(), leases=leases,
                                 terminal=lambda rows, columns: Terminal(rows, columns, home=directory))

            class Handler(BaseRequestHandler):
                def handle(self):
                    agent.handle(self.request)

            with ThreadingUnixStreamServer(str(root / "agent.sock"), Handler) as backend:
                backend.daemon_threads = True
                worker = Thread(target=backend.serve_forever, daemon=True)
                worker.start()
                try:
                    gate = BrowserGate(CONFIG)
                    bridge = Bridge(gate, root / "agent.sock")
                    socket_path = str(root / "ws.sock")

                    def open_ws(sid, origin=ORIGIN):
                        signed = gate.serializer.dumps({"admin": True, "console_sid": sid})
                        return unix_connect(socket_path, uri="ws://" + HOST + WS_PATH, origin=origin,
                                            extra_headers={"Cookie": COOKIE + "=" + signed}, close_timeout=1)

                    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    listener.bind(socket_path)
                    listener.listen(4)
                    service = asyncio.create_task(serve(listener, bridge))
                    try:
                        with self.assertRaises(InvalidStatusCode) as failure:
                            async with open_ws(SID, "https://localhost"):
                                self.fail("Чужой Origin был принят")
                        self.assertEqual(failure.exception.status_code, 404)
                        grant = leases.issue(SID, "fixture")
                        hello = json.dumps({"grant": grant, "rows": 34, "columns": 110})
                        async with open_ws(OTHER) as foreign:
                            await foreign.send(hello)
                            with self.assertRaises(ConnectionClosed):
                                await asyncio.wait_for(foreign.recv(), 4)
                        async with open_ws(SID) as browser:
                            await browser.send(hello)
                            self.assertEqual(await asyncio.wait_for(browser.recv(), 5), '{"ready":true}')
                            await browser.send(b"\x01stty size\n")
                            data = b""
                            async with asyncio.timeout(5):
                                while b"34 110" not in data:
                                    data += await browser.recv()
                            leases.revoke(SID)
                            await asyncio.wait_for(browser.wait_closed(), 5)
                    finally:
                        service.cancel()
                        await asyncio.gather(service, return_exceptions=True)
                        listener.close()
                finally:
                    await asyncio.to_thread(backend.shutdown)
                    worker.join(2)
