"""WebSocket непривилегированного транспорта с проверкой Host, Origin и cookie."""

import asyncio
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
import json
import logging
import os
from pathlib import Path
import socket

from flask import Flask
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import BadData

from v5.core.console import AGENT_SOCKET, WEB_SOCKET
from v5.core.console.protocol import HEADER, INPUT, MAX_FRAME, OUTPUT, RESIZE, SIZE, frame, terminal_size, token

from .console_routes import PATH, SID

COOKIE = "__Host-kvn-v5"
AGE = 1800
WS_PATH = PATH + "/ws"


def _header(headers, key):
    values = headers.get_all(key) or ()
    return values[0] if len(values) == 1 else None


class BrowserGate:
    def __init__(self, config):
        app = Flask(__name__)
        app.secret_key = config["session_key"]
        self.serializer = SecureCookieSessionInterface().get_signing_serializer(app)
        self.hosts = frozenset(config["allowed_hosts"])

    def binding(self, path, headers):
        host, origin, raw = (_header(headers, name) for name in ("Host", "Origin", "Cookie"))
        if (path != WS_PATH or host not in self.hosts or origin != "https://" + host
                or not raw or len(raw) > 4096):
            return None
        try:
            cookie = SimpleCookie(raw)
            if COOKIE not in cookie:
                return None
            session, issued = self.serializer.loads(cookie[COOKIE].value, max_age=AGE, return_timestamp=True)
            if not isinstance(session, dict) or session.get("admin") is not True or not token(session.get(SID)):
                return None
            ttl = AGE - (datetime.now(timezone.utc) - issued).total_seconds()
            return (session[SID], ttl) if ttl > 0 else None
        except (BadData, ValueError, CookieError, RecursionError):
            return None


class Bridge:
    def __init__(self, gate, agent=AGENT_SOCKET):
        self.gate, self.agent = gate, agent
        self.active = 0

    async def handshake(self, path, headers):
        if self.gate.binding(path, headers) is None:
            return HTTPStatus.NOT_FOUND, [("Cache-Control", "no-store")], b"Not found\n"
        return None

    async def handle(self, ws):
        binding = self.gate.binding(ws.path, ws.request_headers)
        if binding is None or self.active >= 2:
            await ws.close(1008)
            return
        sid, ttl = binding
        self.active += 1
        writer = None
        try:
            async with asyncio.timeout(ttl):
                first = await asyncio.wait_for(ws.recv(), 5)
                if not isinstance(first, str) or len(first) > 256:
                    raise ValueError
                start = json.loads(first)
                if (not isinstance(start, dict) or set(start) != {"grant", "rows", "columns"}
                        or not token(start["grant"]) or not terminal_size(start["rows"], start["columns"])):
                    raise ValueError
                reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(self.agent), limit=4096), 2)
                writer.write(json.dumps({"op": "attach", "session": sid, **start}, separators=(",", ":")).encode() + b"\n")
                await asyncio.wait_for(writer.drain(), 2)
                response = json.loads(await asyncio.wait_for(reader.readline(), 3))
                if response != {"ok": True}:
                    raise ValueError
                await ws.send('{"ready":true}')
                await self.relay(ws, reader, writer)
        except Exception:
            # Не передавать исключения транспорта, кадры и cookies в журнал.
            await ws.close(1008)
        finally:
            self.active -= 1
            if writer is not None:
                writer.close()

    @staticmethod
    async def relay(ws, reader, writer):
        async def from_browser():
            async for payload in ws:
                if not isinstance(payload, bytes) or not 2 <= len(payload) <= MAX_FRAME + 1:
                    raise ValueError
                kind, data = payload[0], payload[1:]
                if kind not in (INPUT, RESIZE) or (
                    kind == RESIZE and (len(data) != SIZE.size or not terminal_size(*SIZE.unpack(data)))
                ):
                    raise ValueError
                writer.write(frame(kind, data))
                await asyncio.wait_for(writer.drain(), 2)

        async def from_agent():
            while True:
                kind, size = HEADER.unpack(await reader.readexactly(HEADER.size))
                if kind != OUTPUT or not 0 < size <= MAX_FRAME:
                    raise ValueError
                body = await asyncio.wait_for(reader.readexactly(size), 2)
                await asyncio.wait_for(ws.send(body), 2)

        tasks = [asyncio.create_task(method()) for method in (from_browser, from_agent)]
        try:
            _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for item in tasks:
                if item not in pending:
                    item.result()
        except asyncio.IncompleteReadError:
            # Агент закрыл PTY: exit, отзыв или остановка сокета.
            pass
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


async def serve(listener, bridge):
    from websockets.legacy.server import unix_serve

    quiet = logging.Logger("kvn-console")
    quiet.disabled = True
    async with unix_serve(bridge.handle, sock=listener, process_request=bridge.handshake, logger=quiet,
                          server_header=None, compression=None, ping_interval=15, ping_timeout=10,
                          max_size=MAX_FRAME + 1, max_queue=4, read_limit=32768, write_limit=32768, close_timeout=1):
        await asyncio.Future()


def main():
    if os.geteuid() == 0 or os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        return 1
    with socket.socket(fileno=3) as listener:
        if (listener.family != socket.AF_UNIX or listener.getsockname() != str(WEB_SOCKET)
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            return 1
        try:
            config = json.loads(Path("/etc/kvn-v5/web/config.json").read_bytes())
            asyncio.run(serve(listener, Bridge(BrowserGate(config))))
        except (OSError, ValueError, KeyError, ImportError):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
