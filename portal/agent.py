#!/usr/bin/env python3
"""Transport, аутентификация и блокировки привилегированного host-agent."""

from __future__ import annotations

import argparse
import os
import socketserver
import sys
import threading
from pathlib import Path

PROJECT_SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_SOURCE_ROOT))

from portal import agent_handlers as _handlers
from portal.agent_handlers import (
    CommandResult,
    CommandRunner,
    DashboardSnapshotCache,
    MaintenanceCommand,
    RootShellSession,
)
from portal.agent_handlers import dispatcher as _dispatcher
from portal.agent_protocol import (
    MAX_REQUEST_BYTES,
    MUTATION_METHODS,
    ProtocolError,
    decode_request_line,
    error_response,
    sanitize_text,
    success_response,
)
from portal.metrics import HostMetricsCollector, MetricsSampler, MetricsStore


# Эти имена сохранены как тестовый/операционный seam старого agent.py.
pwd = _dispatcher.pwd
grp = _dispatcher.grp
USER_ACTIVITY_TOTAL_TIMEOUT = _dispatcher.USER_ACTIVITY_TOTAL_TIMEOUT


class AgentDispatcher(_handlers.AgentDispatcher):
    """Совместимый composition adapter над модульными RPC handlers."""

    def dispatch(self, request):
        # Старые тесты и диагностические инструменты меняют эти безопасные seams.
        _dispatcher.pwd = pwd
        _dispatcher.grp = grp
        _dispatcher.USER_ACTIVITY_TOTAL_TIMEOUT = USER_ACTIVITY_TOTAL_TIMEOUT
        return super().dispatch(request)


def mutation_lock_scope(method: str) -> str:
    """Возвращает явную область блокировки mutation RPC."""
    if method not in MUTATION_METHODS:
        return "read-only"
    if method == "service.action":
        return "service"
    if method.startswith("shell."):
        return "shell-session"
    return "global"


class AgentApplication:
    def __init__(self, secret: str, dispatcher: AgentDispatcher):
        self.secret = secret
        self.dispatcher = dispatcher
        self.mutation_lock = threading.Lock()
        self.service_locks: dict[str, threading.Lock] = {}
        self.service_locks_guard = threading.Lock()

    def _service_lock(self, service: str) -> threading.Lock:
        with self.service_locks_guard:
            return self.service_locks.setdefault(service, threading.Lock())

    def handle_line(self, line: bytes) -> bytes:
        request_id = ""
        try:
            request = decode_request_line(line, self.secret)
            request_id = request.request_id
            scope = mutation_lock_scope(request.method)
            if scope == "service":
                service = request.params.get("service", "")
                with self._service_lock(service if isinstance(service, str) else ""):
                    data = self.dispatcher.dispatch(request)
            elif scope == "global":
                with self.mutation_lock:
                    data = self.dispatcher.dispatch(request)
            else:
                # Shell имеет собственную session-bound блокировку внутри handler.
                data = self.dispatcher.dispatch(request)
            return success_response(request.request_id, data)
        except ProtocolError as exc:
            if not exc.request_id:
                exc.request_id = request_id
            return error_response(exc)
        except Exception as exc:  # fail-closed boundary; детали остаются в journald
            return error_response(ProtocolError("internal_error", sanitize_text(str(exc), 512), request_id))


class AgentRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline(MAX_REQUEST_BYTES + 2)
        if len(line) > MAX_REQUEST_BYTES:
            response = error_response(ProtocolError("request_too_large", "Запрос превышает допустимый размер."))
        else:
            response = self.server.application.handle_line(line)  # type: ignore[attr-defined]
        try:
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            return


if hasattr(socketserver, "UnixStreamServer"):
    class ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, socket_path: Path, application: AgentApplication):
            self.application = application
            super().__init__(str(socket_path), AgentRequestHandler)
else:
    class ThreadingUnixServer:  # pragma: no cover - production использует Unix
        def __init__(self, _socket_path: Path, _application: AgentApplication):
            raise RuntimeError("Unix-сокеты недоступны в этой системе.")


def serve(
    socket_path: Path,
    secret_file: Path,
    project_root: Path,
    socket_group: str,
    metrics_db: Path,
) -> None:
    import grp as system_group

    if os.geteuid() != 0:
        raise SystemExit("Host-agent должен запускаться от root через systemd.")
    secret = secret_file.read_text(encoding="utf-8").strip()
    if len(secret) < 32:
        raise SystemExit("Секрет host-agent отсутствует или слишком короткий.")
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.unlink(missing_ok=True)
    metrics = MetricsStore(metrics_db)
    dispatcher = AgentDispatcher(project_root, metrics=metrics)
    sampler = MetricsSampler(
        metrics,
        HostMetricsCollector(project_root),
        enabled_provider=dispatcher.monitoring_enabled,
    )
    application = AgentApplication(secret, dispatcher)
    application.dispatcher.reconcile_services()
    sampler.start()
    try:
        with ThreadingUnixServer(socket_path, application) as server:
            group_id = system_group.getgrnam(socket_group).gr_gid
            os.chown(socket_path, 0, group_id)
            os.chmod(socket_path, 0o660)
            server.serve_forever(poll_interval=0.5)
    finally:
        sampler.stop()


def main() -> int:
    parser = argparse.ArgumentParser(description="KVN VPN host-agent")
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--socket", type=Path, default=Path("/run/kvn-portal/control.sock"))
    parser.add_argument("--secret-file", type=Path, default=Path("/etc/kvn-portal/agent.secret"))
    parser.add_argument("--socket-group", default="kvn-portal")
    parser.add_argument("--metrics-db", type=Path, default=Path("/var/lib/kvn-portal/metrics.db"))
    args = parser.parse_args()
    serve(args.socket, args.secret_file, args.project_root, args.socket_group, args.metrics_db)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
