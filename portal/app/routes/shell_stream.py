"""Session-bound WebSocket↔Unix RPC; PTY и root-пароль остаются у host-agent."""

from __future__ import annotations

import hmac
import json
import threading
import time
import uuid

from flask import g, jsonify, request
from flask_sock import Sock
from simple_websocket import ConnectionClosed

from ..security import token_hash

_worker = None


def post_worker_init(worker) -> None:
    """Gunicorn hook: завершаем только transport при остановке gthread worker."""
    global _worker
    _worker = worker


def _worker_available() -> bool:
    return _worker is None or bool(_worker.alive)


def register_shell_stream(app, boundary, storage, agent_facade) -> None:
    app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": 25, "max_message_size": 32768}
    sock = Sock(app)

    @app.before_request
    def protect_shell_stream():
        if request.endpoint != "terminal_shell_stream":
            return None
        # Origin проверяется ДО upgrade; CSRF — первым ограниченным сообщением.
        if g.session is None or request.headers.get("Origin", "") != f"https://{request.host}":
            return jsonify(ok=False, code="forbidden"), 403
        return None

    @sock.route(app.config["PORTAL_PATH"] + "/terminal/shell/stream", endpoint="terminal_shell_stream")
    def shell_stream(ws):
        stop = threading.Event()
        send_lock = threading.Lock()
        condition = threading.Condition()
        state = {"cursor": 0, "sent": 0}
        token, ip = g.session_token, g.client_ip
        user_agent = request.headers.get("User-Agent", "")
        csrf = g.session["csrf_token"]
        base = {}
        reader = None

        def send(payload):
            with send_lock:
                ws.send(json.dumps(payload, separators=(",", ":")))

        def rpc(method, params):
            context = {key: value for key, value in base.items()
                       if key != "stream_id" or method in {"shell.read", "shell.write"}}
            return agent_facade.client().call(method, {**context, **params}, timeout=3)

        def output_loop():
            try:
                while not stop.is_set():
                    with condition:
                        # Только один неподтверждённый кадр: xterm ACK после write callback.
                        condition.wait_for(lambda: stop.is_set() or state["cursor"] == state["sent"], 1)
                        if stop.is_set():
                            break
                        if state["cursor"] != state["sent"]:
                            continue
                        cursor = state["cursor"]
                    result = rpc("shell.read", {"cursor": cursor, "wait_ms": 1000})
                    if result.get("output_b64"):
                        with condition:
                            state["sent"] = result["cursor"]
                        send({"type": "output", "data": result["output_b64"], "cursor": result["cursor"]})
                    elif not result.get("alive"):
                        send({"type": "exit", "exit_code": result.get("exit_code")})
                        stop.set()
            except Exception:
                # Не отдаём raw exception: там может оказаться содержимое RPC.
                try:
                    send({"type": "error", "code": "agent_unavailable"})
                except Exception:
                    pass
                stop.set()

        try:
            hello = ws.receive(timeout=5)
            if not isinstance(hello, str) or len(hello) > 2048:
                return
            hello = json.loads(hello)
            if (not isinstance(hello, dict) or hello.get("type") != "hello"
                    or not isinstance(hello.get("csrf"), str)
                    or not hmac.compare_digest(hello["csrf"], csrf)
                    or type(hello.get("cursor")) is not int or hello["cursor"] < 0):
                return
            base = {"shell_id": hello.get("shell_id", ""), "session_owner": token_hash(token),
                    "stream_id": uuid.uuid4().hex}
            state["cursor"] = state["sent"] = hello["cursor"]
            attached = rpc("shell.read", {"attach": True, "cursor": hello["cursor"], "wait_ms": 0})
            send({"type": "ready", "input_seq": attached["input_seq"]})
            reader = threading.Thread(target=output_loop, name="kvn-shell-stream", daemon=True)
            reader.start()
            checked_at = 0.0
            window_at, messages = time.monotonic(), 0
            while not stop.is_set() and _worker_available():
                if time.monotonic() - checked_at >= 1:
                    checked_at = time.monotonic()
                    if storage.get_session(token, boundary.now(), ip=ip, user_agent=user_agent) is None:
                        rpc("shell.close", {})
                        send({"type": "error", "code": "session_expired"})
                        break
                raw = ws.receive(timeout=0.2)
                if raw is None:
                    continue
                if not isinstance(raw, str) or len(raw) > 32768:
                    break
                timestamp = time.monotonic()
                if timestamp - window_at >= 1:
                    window_at, messages = timestamp, 0
                messages += 1
                if messages > 200:
                    break
                message = json.loads(raw)
                if not isinstance(message, dict):
                    break
                kind = message.get("type")
                if kind == "ack":
                    with condition:
                        cursor = message.get("cursor")
                        if type(cursor) is not int or not state["cursor"] <= cursor <= state["sent"]:
                            break
                        state["cursor"] = cursor
                        condition.notify_all()
                elif kind == "input":
                    result = rpc("shell.write", {"data": message.get("data"), "seq": message.get("seq")})
                    send({"type": "input_ack", "seq": result["seq"], "complete": result["ok"],
                          "alive": result["alive"]})
                elif kind == "resize":
                    rpc("shell.resize", {"rows": message.get("rows"), "cols": message.get("cols")})
                elif kind == "close":
                    rpc("shell.close", {})
                    break
                else:
                    break
        except ConnectionClosed:
            pass  # Краткий обрыв закрывает transport, не shell.
        except Exception:
            try:
                send({"type": "error", "code": "stream_failed"})
            except Exception:
                pass
        finally:
            stop.set()
            with condition:
                condition.notify_all()
            if reader is not None:
                reader.join(timeout=1.5)
            ws.close()
