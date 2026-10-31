#!/usr/bin/env python3
"""Длительная WS→Unix RPC→PTY проверка только на изолированных fixtures WSL."""
import argparse
import base64
import json
import os
from pathlib import Path
import resource
import secrets
import tempfile
import threading
import time

from simple_websocket import Client
from werkzeug.serving import make_server, WSGIRequestHandler

from portal.agent import AgentApplication, AgentDispatcher, ThreadingUnixServer
from portal.agent_client import AgentClient
from portal.app import create_app
from portal.app.security import token_hash


class QuietHandler(WSGIRequestHandler):
    def log(self, *_args, **_kwargs):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=1800)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 10 <= args.seconds <= 3600:
        raise SystemExit("Нужен WSL/root и длительность 10–3600 секунд.")
    report = {"surface": "WS→Unix RPC→реальный PTY, synthetic session; не проверка PAM/production",
              "samples": [], "reconnects": 0, "echoes": 0}
    with tempfile.TemporaryDirectory(prefix="kvn-console-soak-") as temporary:
        root = Path(temporary)
        dispatcher = AgentDispatcher(root)
        secret = secrets.token_hex(32)
        socket = root / "control.sock"
        rpc = ThreadingUnixServer(socket, AgentApplication(secret, dispatcher))
        threading.Thread(target=rpc.serve_forever, daemon=True).start()
        app = create_app({"TESTING": True, "DATABASE": root / "portal.db",
                          "USERS_FILE": root / "users.json", "PORTAL_PATH": "/fixture",
                          "PROXY_SECRET": secret, "AGENT_CLIENT": AgentClient(socket, secret)})
        token, csrf = app.extensions["kvn_storage"].create_session("192.0.2.42", "soak")
        shell = dispatcher._spawn_root_shell(token_hash(token), 30, 100)
        dispatcher.root_shells[shell.session_id] = shell
        server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        host = f"127.0.0.1:{server.server_port}"
        headers = {"Origin": "https://127.0.0.1", "X-KVN-Proxy-Secret": secret,
                   "X-Forwarded-Proto": "https", "X-Real-IP": "192.0.2.42",
                   "User-Agent": "soak", "Cookie": "kvn_portal_session=" + token}
        ws = None
        cursor, seq, output = 0, 0, b""
        def connect():
            connection = Client(f"ws://{host}/fixture/terminal/shell/stream", headers=headers)
            connection.send(json.dumps({"type": "hello", "shell_id": shell.session_id,
                                        "csrf": csrf, "cursor": cursor}))
            ready = json.loads(connection.receive(timeout=5))
            assert ready["type"] == "ready"
            return connection, ready["input_seq"]
        started = time.monotonic()
        cpu = time.process_time()
        last_echo, last_sample, last_connect = -10, -60, 0
        waiting = None
        ready_for_input = False
        try:
            ws, seq = connect()
            while time.monotonic() - started < args.seconds:
                elapsed = time.monotonic() - started
                if ready_for_input and elapsed < args.seconds / 2 and elapsed - last_echo >= 5 and waiting is None:
                    seq += 1
                    waiting = f"KVN_SOAK_{seq}_Ж".encode()
                    # Разделённые аргументы исключают ложное совпадение с terminal echo.
                    command = f"printf 'KVN_%s_%s_Ж\\n' SOAK {seq}\n"
                    ws.send(json.dumps({"type": "input", "seq": seq,
                                        "data": command}))
                    last_echo = elapsed
                raw = ws.receive(timeout=0.5)
                if raw is not None:
                    message = json.loads(raw)
                    assert message["type"] in {"output", "input_ack"}, message["type"]
                    if message["type"] == "output":
                        output = (output + base64.b64decode(message["data"]))[-8192:]
                        ready_for_input = ready_for_input or b"# " in output
                        cursor = message["cursor"]
                        ws.send(json.dumps({"type": "ack", "cursor": cursor}))
                        if waiting is not None and waiting in output:
                            waiting = None
                            report["echoes"] += 1
                if waiting is not None and elapsed - last_echo > 10:
                    raise AssertionError("Потерян ответ реального PTY")
                if elapsed - last_connect >= 60 and waiting is None:
                    ws.close()
                    ws, seq = connect()
                    report["reconnects"] += 1
                    last_connect = elapsed
                if elapsed - last_sample >= 60:
                    report["samples"].append({"seconds": round(elapsed),
                        "cpu_seconds": round(time.process_time() - cpu, 3),
                        "rss_peak_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                        "threads": threading.active_count(), "fds": len(os.listdir("/proc/self/fd")),
                        "buffer_bytes": len(shell.output)})
                    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
                    last_sample = elapsed
                assert shell.process.poll() is None
            report["seconds"] = round(time.monotonic() - started, 3)
            report["ok"] = waiting is None and report["echoes"] > 0
            assert report["ok"]
            first, last = report["samples"][0], report["samples"][-1]
            assert last["threads"] <= first["threads"] + 2, "Рост числа потоков"
            assert last["fds"] <= first["fds"] + 2, "Рост числа дескрипторов"
            assert last["rss_peak_kib"] < 192 * 1024, "Превышен бюджет тестового процесса"
        except BaseException:
            report["ok"] = False
            raise
        finally:
            if ws is not None:
                ws.close()
            shell.close()
            server.shutdown()
            server.server_close()
            rpc.shutdown()
            rpc.server_close()
            report["pty_closed"] = not shell.reader.is_alive() and shell.process.poll() is not None
            args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "samples"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
