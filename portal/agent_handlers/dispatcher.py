#!/usr/bin/env python3
"""Привилегированный локальный агент управления KVN VPN."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import re
import signal
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_SOURCE_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_SOURCE_ROOT))
from tools.release.artifact import artifact_kind, inspect_update_artifact
from tools.release.deploy_archive import ArchiveValidationError
from tools.kvnlib.services import DOCKER_SERVICE_ORDER, HOST_SERVICE_ORDER, OPERATOR_SERVICE_ORDER
from tools.release.full_archive import ReleaseValidationError
from portal.github_updates import GitHubReleaseSource, GitHubUpdateError

try:
    import errno
    import fcntl
    import grp
    import pwd
    import select
    import struct
    import termios
except ImportError:  # pragma: no cover - root shell доступен только на Linux
    errno = fcntl = grp = pwd = select = struct = termios = None  # type: ignore[assignment]

if __package__:
    from ..agent_protocol import (
        MAX_REQUEST_BYTES,
        MUTATION_METHODS,
        ProtocolError,
        RpcRequest,
        decode_request_line,
        error_response,
        sanitize_text,
        success_response,
    )
    from ..metrics import MetricsQueryError, MetricsStore
else:
    from agent_protocol import (  # type: ignore
        MAX_REQUEST_BYTES,
        MUTATION_METHODS,
        ProtocolError,
        RpcRequest,
        decode_request_line,
        error_response,
        sanitize_text,
        success_response,
    )
    from metrics import HostMetricsCollector, MetricsQueryError, MetricsSampler, MetricsStore  # type: ignore

SERVICES = set(OPERATOR_SERVICE_ORDER)
SELF_LOCKOUT_SERVICES = {"nginx", "portal", "agent"}
DOCKER_SERVICES = set(DOCKER_SERVICE_ORDER)
HOST_VPN_SERVICES = set(HOST_SERVICE_ORDER)
BASE_SERVICE_ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable"}
SERVICE_ACTIONS = BASE_SERVICE_ACTIONS | {"apply"}
SERVICE_ALLOWED_ACTIONS = {
    "nginx": {"start", "restart", "reload", "enable"},
    "portal": {"start", "restart", "reload", "enable"},
    "agent": {"restart", "reload"},
    "telemt": BASE_SERVICE_ACTIONS,
    "ocserv": BASE_SERVICE_ACTIONS,
    "xray": BASE_SERVICE_ACTIONS - {"reload"},
    "hysteria": BASE_SERVICE_ACTIONS - {"reload"},
    "mtg": BASE_SERVICE_ACTIONS - {"reload"},
    "amneziawg": (BASE_SERVICE_ACTIONS - {"reload"}) | {"apply"},
    "wireguard": (BASE_SERVICE_ACTIONS - {"reload"}) | {"apply"},
}
RELOAD_COMMANDS = {
    "nginx": ["exec", "-T", "nginx", "nginx", "-s", "reload"],
    "ocserv": ["kill", "-s", "HUP", "ocserv"],
    "telemt": ["kill", "-s", "HUP", "telemt"],
}
CONTAINER_NAMES = {
    "nginx": "nginx-front",
    "xray": "xray",
    "hysteria": "hysteria",
    "telemt": "telemt-proxy",
    "mtg": "mtg-proxy",
    "ocserv": "ocserv",
    "portal": "kvn-portal",
}
ROOT_SHELL_MAX_SESSIONS = 2
ROOT_SHELL_IDLE_SECONDS = 15 * 60
ROOT_SHELL_ABSOLUTE_SECONDS = 60 * 60
ROOT_SHELL_MAX_WRITE_BYTES = 4096
ROOT_SHELL_MAX_READ_BYTES = 96 * 1024
ROOT_SHELL_AUTH_FAILURES = 5
ROOT_SHELL_AUTH_BLOCK_SECONDS = 15 * 60
ROOT_SHELL_OWNER_RE = re.compile(r"^[0-9a-f]{64}$")
USER_ACTIVITY_COMMAND_TIMEOUT = 3
USER_ACTIVITY_TOTAL_TIMEOUT = 5
USER_ACTIVITY_MAX_OUTPUT = 32 * 1024
USER_ACTIVITY_MAX_ROWS = 16
USER_ACTIVITY_RECENT_SECONDS = 180


def _trim_shell_text(value: str, max_chars: int = ROOT_SHELL_MAX_READ_BYTES) -> str:
    value = "".join(ch for ch in value if ch in "\n\r\t\x1b" or ord(ch) >= 32)
    if len(value) > max_chars:
        return value[:max_chars] + "\n<вывод shell обрезан>"
    return value


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
        }


@dataclass(frozen=True)
class MaintenanceCommand:
    command_id: str
    title: str
    group: str
    description: str
    argv: tuple[str, ...]
    timeout: int = 30
    max_output: int = 128 * 1024
    requires_confirmation: bool = False

    def public_dict(self) -> dict[str, Any]:
        return {
            "id": self.command_id,
            "title": self.title,
            "group": self.group,
            "description": self.description,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass
class RootShellSession:
    session_id: str
    owner: str
    pid: int
    fd: int
    created_at: float
    last_seen: float
    lock: threading.Lock
    unit: str = ""
    closed: bool = False
    exit_code: int | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "shell_id": self.session_id,
            "alive": not self.closed,
            "created_at": int(self.created_at),
            "last_seen": int(self.last_seen),
            "exit_code": self.exit_code,
        }

    def mark_seen(self) -> None:
        self.last_seen = time.monotonic()

    def expired(self, now_value: float) -> bool:
        return (
            self.closed
            or now_value - self.last_seen > ROOT_SHELL_IDLE_SECONDS
            or now_value - self.created_at > ROOT_SHELL_ABSOLUTE_SECONDS
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.unit and Path("/usr/bin/systemctl").is_file():
            for argv in (
                ["systemctl", "kill", "--signal=SIGHUP", self.unit],
                ["systemctl", "stop", self.unit],
            ):
                try:
                    subprocess.run(argv, check=False, capture_output=True, timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        try:
            os.kill(self.pid, getattr(signal, "SIGHUP", signal.SIGTERM))
        except OSError:
            pass
        try:
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
            if waited_pid == self.pid:
                self.exit_code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass


class CommandRunner:
    def run(
        self,
        argv: list[str],
        *,
        timeout: int = 30,
        max_output: int = 128 * 1024,
        input_text: str | None = None,
    ) -> CommandResult:
        started = time.monotonic()
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                input=input_text,
                env={**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"},
            )
        except subprocess.TimeoutExpired as exc:
            raise ProtocolError("command_timeout", "Команда превысила допустимое время выполнения.") from exc
        duration_ms = int((time.monotonic() - started) * 1000)
        return CommandResult(
            tuple(argv),
            result.returncode,
            sanitize_text(result.stdout or "", max_output),
            sanitize_text(result.stderr or "", max_output),
            duration_ms,
        )


DASHBOARD_SOURCE_TTLS = {
    "host": 45,
    "metrics": 30,
    "containers": 60,
    "protocols": 60,
    "certificates": 900,
    "health_summary": 60,
    "ssh_sessions": 30,
}


class DashboardSnapshotCache:
    """Фоновый single-flight cache тяжёлой сводки host-agent."""

    def __init__(self, loader, now_provider=time.time):
        self.loader = loader
        self.now_provider = now_provider
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._refreshing = False
        self._refreshing_sources: set[str] = set()
        self._refresh_done = threading.Event()
        self._refresh_done.set()

    def get(self) -> dict[str, Any]:
        now_value = int(self.now_provider())
        with self._lock:
            expired = [
                name for name in DASHBOARD_SOURCE_TTLS
                if name not in self._items or now_value >= self._items[name]["next_refresh"]
            ]
            if expired and not self._refreshing:
                self._refreshing = True
                self._refreshing_sources = set(expired)
                self._refresh_done.clear()
                threading.Thread(
                    target=self._refresh,
                    args=(tuple(expired),),
                    name="kvn-dashboard-refresh",
                    daemon=True,
                ).start()
            return self._snapshot_locked(now_value)

    def wait(self, timeout: float = 5.0) -> bool:
        """Используется smoke/unit-проверками, RPC его не вызывает."""
        return self._refresh_done.wait(timeout)

    def _refresh(self, names: tuple[str, ...]) -> None:
        with self._lock:
            context = {
                name: item["data"] for name, item in self._items.items()
                if item.get("data") is not None
            }
        try:
            for name in names:
                collected_at = int(self.now_provider())
                try:
                    data = self.loader(name, context)
                except Exception:
                    with self._lock:
                        previous = self._items.get(name, {})
                        self._items[name] = {
                            "data": previous.get("data"),
                            "collected_at": previous.get("collected_at", 0),
                            "error": "Источник временно недоступен.",
                            "next_refresh": collected_at + 15,
                        }
                    continue
                context[name] = data
                with self._lock:
                    self._items[name] = {
                        "data": data,
                        "collected_at": collected_at,
                        "error": "",
                        "next_refresh": collected_at + DASHBOARD_SOURCE_TTLS[name],
                    }
        finally:
            with self._lock:
                self._refreshing = False
                self._refreshing_sources.clear()
                self._refresh_done.set()

    def _snapshot_locked(self, now_value: int) -> dict[str, Any]:
        sources = {}
        for name, ttl in DASHBOARD_SOURCE_TTLS.items():
            item = self._items.get(name, {})
            collected_at = int(item.get("collected_at", 0) or 0)
            error = str(item.get("error", ""))
            expired = bool(collected_at and now_value - collected_at >= ttl)
            refreshing_source = name in self._refreshing_sources
            sources[name] = {
                "data": item.get("data"),
                "collected_at": collected_at,
                "age_seconds": max(0, now_value - collected_at) if collected_at else None,
                # Последний успешный snapshot остаётся актуальным, пока его обновляют в фоне.
                "stale": bool(error) or not collected_at or (expired and not refreshing_source),
                "error": error,
            }
        has_data = any(item["data"] is not None for item in sources.values())
        stale = any(item["stale"] for item in sources.values())
        return {
            "sources": sources,
            "generated_at": now_value,
            "refreshing": self._refreshing,
            "stale": stale,
            "status": "loading" if not has_data else "stale" if stale else "ok",
        }


class AgentDispatcher:
    def __init__(
        self,
        project_root: Path,
        runner: CommandRunner | None = None,
        control=None,
        metrics: MetricsStore | None = None,
        github_source: GitHubReleaseSource | None = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.runner = runner or CommandRunner()
        self.compose = [
            "docker", "compose",
            "--project-directory", str(self.project_root),
            "-f", str(self.project_root / "docker-compose.yml"),
        ]
        self.control = control
        self.metrics = metrics
        self.github_source = github_source or GitHubReleaseSource(
            self.project_root / "portal-data" / "updates"
        )
        self.generation = uuid.uuid4().hex
        self.started_at = int(time.time())
        self.root_shells: dict[str, RootShellSession] = {}
        self.root_shell_lock = threading.Lock()
        self.root_shell_auth_failures: dict[str, tuple[int, float]] = {}
        self.root_shell_reaper_started = False
        self.dashboard_cache = DashboardSnapshotCache(self._dashboard_collect)
        self._handler_registry = None

    def _maintenance_commands(self) -> dict[str, MaintenanceCommand]:
        python = "python3"
        return {
            "system_failed": MaintenanceCommand(
                "system_failed", "Проблемные systemd units", "Система",
                "Показывает units в failed-состоянии.",
                ("systemctl", "--failed", "--no-pager"), timeout=20,
            ),
            "system_status": MaintenanceCommand(
                "system_status", "Статус host-служб KVN", "Система",
                "Проверяет AmneziaWG, WireGuard и host-agent.",
                ("systemctl", "status", "kvn-amneziawg.service", "kvn-wireguard.service", "kvn-portal-agent.service", "--no-pager"),
                timeout=20, max_output=192 * 1024,
            ),
            "network_summary": MaintenanceCommand(
                "network_summary", "Адреса и маршруты", "Сеть",
                "Краткая сводка IP-адресов и маршрутов.",
                ("ip", "-br", "addr", "show"), timeout=15,
            ),
            "listening_ports": MaintenanceCommand(
                "listening_ports", "Слушающие порты", "Сеть",
                "Показывает TCP/UDP listeners для проверки firewall и bind.",
                ("ss", "-tulpen"), timeout=20, max_output=192 * 1024,
            ),
            "disk_usage": MaintenanceCommand(
                "disk_usage", "Диски и mountpoints", "Ресурсы",
                "Показывает занятое место и типы файловых систем.",
                ("df", "-hT"), timeout=15,
            ),
            "memory_usage": MaintenanceCommand(
                "memory_usage", "Память", "Ресурсы",
                "Показывает RAM/swap в человекочитаемом виде.",
                ("free", "-h"), timeout=15,
            ),
            "compose_ps": MaintenanceCommand(
                "compose_ps", "Docker Compose ps", "Docker",
                "Состояние контейнеров проекта.",
                (*self.compose, "ps"), timeout=30, max_output=192 * 1024,
            ),
            "compose_config": MaintenanceCommand(
                "compose_config", "Проверка Compose config", "Docker",
                "Валидирует docker-compose.yml без запуска контейнеров.",
                (*self.compose, "config", "--quiet"), timeout=30,
            ),
            "docker_images": MaintenanceCommand(
                "docker_images", "Docker images", "Docker",
                "Показывает локальные images, полезно перед backup/restore.",
                ("docker", "images", "--format", "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"),
                timeout=30, max_output=192 * 1024,
            ),
            "kvn_reconcile": MaintenanceCommand(
                "kvn_reconcile", "Согласование состояния", "KVN",
                "Повторно применяет целевое состояние, включая host VPN sync.",
                (python, str(self.project_root / "tools" / "kvnctl.py"), "reconcile"),
                timeout=180, max_output=256 * 1024, requires_confirmation=True,
            ),
            "kvn_render": MaintenanceCommand(
                "kvn_render", "Render конфигураций", "KVN",
                "Перегенерирует runtime-конфиги из users.json.",
                (python, str(self.project_root / "tools" / "kvnctl.py"), "render"),
                timeout=180, max_output=256 * 1024, requires_confirmation=True,
            ),
            "kvn_awg_verify": MaintenanceCommand(
                "kvn_awg_verify", "Проверка AmneziaWG", "KVN",
                "Сверяет desired/generated/host/runtime AmneziaWG.",
                (python, str(self.project_root / "tools" / "kvnctl.py"), "amneziawg", "verify"),
                timeout=60, max_output=192 * 1024,
            ),
            "kvn_wg_verify": MaintenanceCommand(
                "kvn_wg_verify", "Проверка WireGuard", "KVN",
                "Сверяет desired/generated/host/runtime WireGuard.",
                (python, str(self.project_root / "tools" / "kvnctl.py"), "wireguard", "verify"),
                timeout=60, max_output=192 * 1024,
            ),
            "cleanup_dry_run": MaintenanceCommand(
                "cleanup_dry_run", "Проверка очистки", "KVN",
                "Показывает, что удалит cleanup-project.sh без применения.",
                ("/bin/bash", str(self.project_root / "tools" / "cleanup-project.sh"), "--dry-run"),
                timeout=60, max_output=192 * 1024,
            ),
        }

    def _control(self):
        if self.control is None:
            if str(self.project_root) not in os.sys.path:
                os.sys.path.insert(0, str(self.project_root))
            from portal.control import KvnControl

            self.control = KvnControl(self.project_root)
        return self.control

    @staticmethod
    def _service(params: dict) -> str:
        service = params.get("service")
        if not isinstance(service, str) or service not in SERVICES:
            raise ProtocolError("policy_denied", "Сервис не разрешён.")
        return service

    def dispatch(self, request: RpcRequest) -> dict[str, Any]:
        from .registry import build_handler_registry, invoke

        if self._handler_registry is None:
            self._handler_registry = build_handler_registry(self)
        return invoke(self._handler_registry, request.method, request.params)

    @staticmethod
    def _system_uid_min() -> int:
        try:
            for line in Path("/etc/login.defs").read_text(encoding="utf-8").splitlines():
                fields = line.split("#", 1)[0].split()
                if len(fields) == 2 and fields[0] == "UID_MIN":
                    value = int(fields[1])
                    if 1 <= value < 65534:
                        return value
        except (OSError, ValueError):
            pass
        return 1000

    def _system_users(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Список системных пользователей не принимает параметры.")
        if pwd is None or grp is None:
            raise ProtocolError("capability_unavailable", "Системные пользователи доступны только на Linux.")
        uid_min = self._system_uid_min()
        privileged = {"sudo", "adm", "wheel"}
        rows = []
        for account in pwd.getpwall():
            if not (uid_min <= account.pw_uid < 65534):
                continue
            if account.pw_shell.endswith(("/nologin", "/false")):
                continue
            groups = {
                item.gr_name for item in grp.getgrall()
                if account.pw_name in item.gr_mem or item.gr_gid == account.pw_gid
            }
            rows.append({
                "user": account.pw_name,
                "uid": account.pw_uid,
                "home": account.pw_dir,
                "shell": account.pw_shell,
                "privileged": bool(groups & privileged),
            })
        rows.sort(key=lambda item: (item["uid"], item["user"]))
        return {"users": rows, "count": len(rows)}

    def _system_user_create(self, params: dict) -> dict[str, Any]:
        if set(params) != {"username", "password"}:
            raise ProtocolError("invalid_params", "Создание пользователя принимает только username и password.")
        username = params.get("username")
        password = params.get("password")
        if not isinstance(username, str) or re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username) is None:
            raise ProtocolError("invalid_params", "Имя: 1–32 строчные латинские буквы, цифры, _ или -.")
        if username in {"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "gnats", "nobody", "systemd-network", "systemd-timesync", "messagebus", "sshd"}:
            raise ProtocolError("invalid_params", "Это системное имя запрещено.")
        if (
            not isinstance(password, str)
            or not 12 <= len(password) <= 128
            or any(char in password for char in ("\n", "\r", "\x00", ":"))
        ):
            raise ProtocolError("invalid_params", "Пароль должен содержать 12–128 символов без двоеточия и переводов строки.")
        if pwd is None:
            raise ProtocolError("capability_unavailable", "Создание системных пользователей доступно только на Linux.")
        try:
            pwd.getpwnam(username)
        except KeyError:
            pass
        else:
            raise ProtocolError("account_exists", "Пользователь с таким именем уже существует.")

        helper = (self.project_root / "portal" / "system_user_helper.py").resolve()
        if helper.parent != (self.project_root / "portal").resolve() or not helper.is_file():
            raise ProtocolError("capability_unavailable", "Системный helper не установлен.")
        unit = f"kvn-system-user-{uuid.uuid4().hex[:12]}"
        argv = [
            "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
            "--service-type=exec", f"--unit={unit}",
            "--property=NoNewPrivileges=true", "--property=PrivateTmp=true",
            "--property=ProtectKernelTunables=true", "--property=ProtectKernelModules=true",
            "--property=ProtectControlGroups=true", "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=UMask=0077",
            "/usr/bin/python3", str(helper), "create", username,
        ]
        result = self.runner.run(argv, timeout=30, max_output=4096, input_text=password + "\n")
        if result.returncode != 0:
            raise ProtocolError("account_create_failed", "Не удалось создать пользователя. Проверьте журнал host-agent.")
        try:
            payload = json.loads(result.stdout)
        except (json.JSONDecodeError, TypeError):
            raise ProtocolError("account_create_failed", "Системный helper вернул некорректный ответ.")
        if not isinstance(payload, dict) or payload.get("user") != username or payload.get("ok") is not True:
            raise ProtocolError("account_create_failed", "Создание пользователя не подтверждено.")
        return {
            "ok": True,
            "user": username,
            "home": f"/home/{username}",
            "shell": "/bin/bash",
            "privileged": False,
        }

    def _user_export(self, params: dict) -> dict[str, Any]:
        if set(params) != {"name", "address_mode"}:
            raise ProtocolError(
                "invalid_params",
                "Экспорт принимает только name и address_mode.",
            )
        name = params.get("name")
        address_mode = params.get("address_mode")
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{2,32}", name) is None
        ):
            raise ProtocolError("invalid_params", "Имя пользователя недопустимо.")
        if address_mode not in {"server", "public-ip"}:
            raise ProtocolError("invalid_params", "Режим адреса экспорта не разрешён.")
        try:
            from portal.control import ControlError
        except ModuleNotFoundError:
            from control import ControlError  # type: ignore
        try:
            return self._control().user_export(name, address_mode)
        except ControlError as exc:
            raise ProtocolError(exc.code, str(exc)) from exc

    def _client_export_settings(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError(
                "invalid_params",
                "Настройки экспорта не принимают параметры.",
            )
        try:
            return self._control().client_export_settings()
        except Exception as exc:
            code = getattr(exc, "code", "read_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _client_export_update(self, params: dict) -> dict[str, Any]:
        expected = {
            "revision", "address_mode", "public_ip", "include_alternate",
        }
        if set(params) != expected:
            raise ProtocolError(
                "invalid_params",
                "Некорректная схема настроек клиентского экспорта.",
            )
        if (
            not isinstance(params.get("revision"), str)
            or len(params["revision"]) != 64
            or params.get("address_mode") not in {"server", "public-ip"}
            or not isinstance(params.get("public_ip"), str)
            or not isinstance(params.get("include_alternate"), bool)
        ):
            raise ProtocolError(
                "invalid_params",
                "Типы настроек клиентского экспорта недопустимы.",
            )
        try:
            return self._control().update_client_export(params)
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _network_topology(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Снимок топологии не принимает параметры.")
        return self._control().network_topology()

    def _domain_advice(self, params: dict) -> dict[str, Any]:
        if set(params) != {"zone"}:
            raise ProtocolError("invalid_params", "Советник доменов принимает только zone.")
        try:
            from portal.control import ControlError
        except ModuleNotFoundError:
            from control import ControlError  # type: ignore
        try:
            return self._control().domain_advice(params)
        except ControlError as exc:
            raise ProtocolError(exc.code, str(exc)) from exc

    def _maintenance_command_list(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Список команд обслуживания не принимает параметры.")
        commands = [command.public_dict() for command in self._maintenance_commands().values()]
        return {"commands": commands}

    def _maintenance_run(self, params: dict) -> dict[str, Any]:
        if set(params) - {"command", "request_id"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры команды обслуживания.")
        command_id = params.get("command")
        if not isinstance(command_id, str):
            raise ProtocolError("invalid_params", "Идентификатор команды обязателен.")
        commands = self._maintenance_commands()
        command = commands.get(command_id)
        if command is None:
            raise ProtocolError("policy_denied", "Команда обслуживания не разрешена.")
        correlation_id = uuid.uuid4().hex
        result = self.runner.run(list(command.argv), timeout=command.timeout, max_output=command.max_output)
        return {
            "ok": result.returncode == 0,
            "id": command.command_id,
            "title": command.title,
            "group": command.group,
            "description": command.description,
            "requires_confirmation": command.requires_confirmation,
            "correlation_id": correlation_id,
            "command": result.to_dict(),
        }

    def _cleanup_root_shells(self) -> None:
        current = time.monotonic()
        with self.root_shell_lock:
            expired = [
                shell_id for shell_id, session in self.root_shells.items()
                if session.expired(current)
            ]
            for shell_id in expired:
                self.root_shells.pop(shell_id).close()

    def _ensure_root_shell_reaper(self) -> None:
        with self.root_shell_lock:
            if self.root_shell_reaper_started:
                return
            self.root_shell_reaper_started = True
        thread = threading.Thread(target=self._root_shell_reaper, name="kvn-root-shell-reaper", daemon=True)
        thread.start()

    def _root_shell_reaper(self) -> None:
        while True:
            time.sleep(30)
            self._cleanup_root_shells()

    def _shell_owner(self, params: dict) -> str:
        owner = params.get("session_owner")
        if not isinstance(owner, str) or not ROOT_SHELL_OWNER_RE.fullmatch(owner):
            raise ProtocolError("invalid_params", "Некорректный владелец shell-сессии.")
        return owner

    @staticmethod
    def _shell_dimension(params: dict, key: str, default: int, minimum: int, maximum: int) -> int:
        value = params.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ProtocolError("invalid_params", f"{key} должен быть целым числом.")
        return max(minimum, min(maximum, value))

    def _shell_by_id(self, params: dict) -> RootShellSession:
        self._cleanup_root_shells()
        shell_id = params.get("shell_id")
        if not isinstance(shell_id, str) or not re.fullmatch(r"[0-9a-f]{32}", shell_id):
            raise ProtocolError("invalid_params", "Некорректный идентификатор shell-сессии.")
        owner = self._shell_owner(params)
        with self.root_shell_lock:
            session = self.root_shells.get(shell_id)
        if session is None or session.owner != owner:
            raise ProtocolError("not_found", "Shell-сессия не найдена.")
        return session

    def _shell_auth_allowed(self, owner: str) -> None:
        failures, blocked_until = self.root_shell_auth_failures.get(owner, (0, 0.0))
        if blocked_until > time.monotonic():
            raise ProtocolError("root_password_blocked", "Слишком много ошибок пароля root. Повторите позже.")
        if failures >= ROOT_SHELL_AUTH_FAILURES:
            self.root_shell_auth_failures[owner] = (0, 0.0)

    def _record_shell_auth_failure(self, owner: str) -> None:
        failures, blocked_until = self.root_shell_auth_failures.get(owner, (0, 0.0))
        if blocked_until <= time.monotonic():
            failures += 1
            blocked_until = time.monotonic() + ROOT_SHELL_AUTH_BLOCK_SECONDS if failures >= ROOT_SHELL_AUTH_FAILURES else 0.0
        self.root_shell_auth_failures[owner] = (failures, blocked_until)

    def _clear_shell_auth_failures(self, owner: str) -> None:
        self.root_shell_auth_failures.pop(owner, None)

    @staticmethod
    def _root_shadow_hash() -> str:
        try:
            for line in Path("/etc/shadow").read_text(encoding="utf-8").splitlines():
                name, password_hash, *_rest = line.split(":")
                if name == "root":
                    return password_hash
        except OSError as exc:
            raise ProtocolError("root_password_unavailable", "Не удалось прочитать /etc/shadow.") from exc
        raise ProtocolError("root_password_unavailable", "Root в /etc/shadow не найден.")

    @staticmethod
    def _password_auth_pty(argv: list[str], password: str, *, timeout: float = 10.0) -> bool:
        if not hasattr(os, "forkpty") or select is None:
            raise ProtocolError("root_password_unavailable", "PTY для проверки пароля недоступен.")
        pid, fd = os.forkpty()
        if pid == 0:  # pragma: no cover - дочерний процесс
            try:
                os.environ.clear()
                os.environ.update({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
                os.execvpe(argv[0], argv, os.environ)
            except Exception:
                os._exit(127)
        try:
            deadline = time.monotonic() + timeout
            sent = False
            while time.monotonic() < deadline:
                try:
                    ready, _write, _error = select.select([fd], [], [], 0.2)
                except OSError:
                    ready = []
                if ready:
                    try:
                        os.read(fd, 4096)
                    except OSError:
                        pass
                if not sent:
                    try:
                        os.write(fd, (password + "\n").encode("utf-8"))
                    except OSError:
                        pass
                    sent = True
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    return os.waitstatus_to_exitcode(status) == 0
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
            return False
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def _verify_root_password_with_systemd_su(self, password: str) -> bool | None:
        systemd_run = "/usr/bin/systemd-run" if Path("/usr/bin/systemd-run").is_file() else ""
        su = "/usr/bin/su" if Path("/usr/bin/su").is_file() else "/bin/su" if Path("/bin/su").is_file() else ""
        if not systemd_run or not su:
            return None
        argv = [
            systemd_run,
            "--quiet",
            "--collect",
            "--wait",
            "--pty",
            "--uid=nobody",
            su,
            "root",
            "-c",
            "/bin/true",
        ]
        return self._password_auth_pty(argv, password, timeout=12.0)

    def _verify_root_password_with_su(self, password: str) -> bool | None:
        if not hasattr(os, "forkpty") or pwd is None or select is None:
            return None
        try:
            nobody = pwd.getpwnam("nobody")
        except KeyError:
            return None
        pid, fd = os.forkpty()
        if pid == 0:  # pragma: no cover - дочерний процесс
            try:
                os.setgid(nobody.pw_gid)
                os.setuid(nobody.pw_uid)
                os.environ.clear()
                os.environ.update({"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
                os.execl("/bin/su", "su", "-", "root", "-c", "/bin/true")
            except Exception:
                os._exit(127)
        try:
            deadline = time.monotonic() + 6
            sent = False
            while time.monotonic() < deadline:
                ready, _write, _error = select.select([fd], [], [], 0.2)
                if ready:
                    try:
                        os.read(fd, 4096)
                    except OSError:
                        pass
                if not sent:
                    try:
                        os.write(fd, (password + "\n").encode("utf-8"))
                    except OSError:
                        pass
                    sent = True
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    return os.waitstatus_to_exitcode(status) == 0
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            return False
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def _verify_root_password(self, password: str) -> bool:
        if not isinstance(password, str) or not password or len(password) > 256 or "\x00" in password or "\n" in password:
            raise ProtocolError("invalid_params", "Некорректный пароль root.")
        stored_hash = self._root_shadow_hash()
        if stored_hash.startswith(("!", "*")) or stored_hash in {"", "x"}:
            raise ProtocolError("root_password_unavailable", "Root-пароль не задан или заблокирован.")
        try:
            import crypt  # type: ignore
        except ImportError:
            crypt = None  # type: ignore[assignment]
        if crypt is not None:
            computed = crypt.crypt(password, stored_hash)
            if computed and hmac.compare_digest(computed, stored_hash):
                return True
        systemd_su = self._verify_root_password_with_systemd_su(password)
        if systemd_su is True:
            return True
        fallback = self._verify_root_password_with_su(password)
        if fallback is not None:
            return fallback
        if systemd_su is not None:
            return systemd_su
        return False

    @staticmethod
    def _set_shell_size(fd: int, rows: int, cols: int) -> None:
        if fcntl is None or termios is None or struct is None:
            return
        try:
            packed = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)
        except OSError:
            pass

    def _spawn_root_shell(self, owner: str, rows: int, cols: int) -> RootShellSession:
        if not hasattr(os, "forkpty") or fcntl is None:
            raise ProtocolError("capability_unavailable", "Root shell доступен только на Linux с PTY.")
        shell_path = "/bin/bash" if Path("/bin/bash").is_file() else "/bin/sh"
        shell_id = uuid.uuid4().hex
        unit = f"kvn-portal-root-shell-{shell_id[:12]}" if Path("/usr/bin/systemd-run").is_file() else ""
        pid, fd = os.forkpty()
        if pid == 0:  # pragma: no cover - дочерний процесс
            try:
                os.chdir(self.project_root)
                env = {
                    "TERM": "xterm-256color",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "HOME": "/root",
                    "USER": "root",
                    "LOGNAME": "root",
                    "SHELL": shell_path,
                    "KVN_PORTAL_SHELL": "1",
                }
                shell_argv = [shell_path, "-l"] if shell_path.endswith("bash") else [shell_path]
                if unit:
                    runner_argv = [
                        "/usr/bin/systemd-run",
                        "--quiet",
                        "--collect",
                        "--wait",
                        "--pty",
                        f"--unit={unit}",
                        f"--property=WorkingDirectory={self.project_root}",
                        "--setenv=TERM=xterm-256color",
                        "--setenv=LANG=C.UTF-8",
                        "--setenv=LC_ALL=C.UTF-8",
                        "--setenv=KVN_PORTAL_SHELL=1",
                        *shell_argv,
                    ]
                    os.execvpe(runner_argv[0], runner_argv, env)
                os.execvpe(shell_path, shell_argv, env)
            except Exception:
                os._exit(127)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self._set_shell_size(fd, rows, cols)
        current = time.monotonic()
        return RootShellSession(shell_id, owner, pid, fd, current, current, threading.Lock(), unit=unit)

    def _read_shell_locked(self, session: RootShellSession) -> tuple[str, bool, int | None]:
        if session.closed:
            return "", False, session.exit_code
        chunks: list[bytes] = []
        total = 0
        while total < ROOT_SHELL_MAX_READ_BYTES:
            if select is None:
                break
            try:
                ready, _write, _error = select.select([session.fd], [], [], 0)
            except OSError:
                break
            if not ready:
                break
            try:
                chunk = os.read(session.fd, min(8192, ROOT_SHELL_MAX_READ_BYTES - total))
            except OSError as exc:
                if exc.errno in {errno.EIO if errno is not None else 5, errno.EBADF if errno is not None else 9}:
                    session.closed = True
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        try:
            waited, status = os.waitpid(session.pid, os.WNOHANG)
            if waited == session.pid:
                session.closed = True
                session.exit_code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            session.closed = True
        except OSError:
            pass
        if session.closed:
            with self.root_shell_lock:
                self.root_shells.pop(session.session_id, None)
            try:
                os.close(session.fd)
            except OSError:
                pass
        session.mark_seen()
        text = b"".join(chunks).decode("utf-8", errors="replace")
        return _trim_shell_text(text), not session.closed, session.exit_code

    def _shell_open(self, params: dict) -> dict[str, Any]:
        if set(params) - {"root_password", "session_owner", "rows", "cols"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры shell.")
        owner = self._shell_owner(params)
        rows = self._shell_dimension(params, "rows", 24, 10, 80)
        cols = self._shell_dimension(params, "cols", 100, 40, 240)
        self._ensure_root_shell_reaper()
        self._cleanup_root_shells()
        self._shell_auth_allowed(owner)
        if not self._verify_root_password(params.get("root_password", "")):
            self._record_shell_auth_failure(owner)
            raise ProtocolError("root_password_denied", "Пароль root указан неверно.")
        self._clear_shell_auth_failures(owner)
        with self.root_shell_lock:
            for shell_id, session in list(self.root_shells.items()):
                if session.owner == owner:
                    self.root_shells.pop(shell_id).close()
            if len(self.root_shells) >= ROOT_SHELL_MAX_SESSIONS:
                raise ProtocolError("too_many_sessions", "Достигнут лимит активных root shell-сессий.")
            session = self._spawn_root_shell(owner, rows, cols)
            self.root_shells[session.session_id] = session
        with session.lock:
            output, alive, exit_code = self._read_shell_locked(session)
        return {
            "ok": True,
            **session.to_public(),
            "alive": alive,
            "exit_code": exit_code,
            "output": output,
            "limits": {
                "idle_seconds": ROOT_SHELL_IDLE_SECONDS,
                "absolute_seconds": ROOT_SHELL_ABSOLUTE_SECONDS,
                "max_write_bytes": ROOT_SHELL_MAX_WRITE_BYTES,
            },
        }

    def _shell_read(self, params: dict) -> dict[str, Any]:
        if set(params) - {"shell_id", "session_owner"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры чтения shell.")
        session = self._shell_by_id(params)
        with session.lock:
            output, alive, exit_code = self._read_shell_locked(session)
        return {"ok": True, "shell_id": session.session_id, "output": output, "alive": alive, "exit_code": exit_code}

    def _shell_write(self, params: dict) -> dict[str, Any]:
        if set(params) - {"shell_id", "session_owner", "data"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры записи shell.")
        data = params.get("data")
        if not isinstance(data, str):
            raise ProtocolError("invalid_params", "Данные shell должны быть строкой.")
        encoded = data.encode("utf-8")
        if len(encoded) > ROOT_SHELL_MAX_WRITE_BYTES:
            raise ProtocolError("request_too_large", "Слишком большой ввод shell.")
        session = self._shell_by_id(params)
        with session.lock:
            if session.closed:
                return {"ok": False, "shell_id": session.session_id, "alive": False, "written": 0}
            try:
                written = os.write(session.fd, encoded)
            except OSError as exc:
                if exc.errno in {errno.EIO if errno is not None else 5, errno.EBADF if errno is not None else 9}:
                    session.closed = True
                written = 0
            session.mark_seen()
        return {"ok": written == len(encoded), "shell_id": session.session_id, "alive": not session.closed, "written": written}

    def _shell_resize(self, params: dict) -> dict[str, Any]:
        if set(params) - {"shell_id", "session_owner", "rows", "cols"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры resize shell.")
        rows = self._shell_dimension(params, "rows", 24, 10, 80)
        cols = self._shell_dimension(params, "cols", 100, 40, 240)
        session = self._shell_by_id(params)
        with session.lock:
            self._set_shell_size(session.fd, rows, cols)
            session.mark_seen()
        return {"ok": True, "shell_id": session.session_id, "alive": not session.closed, "rows": rows, "cols": cols}

    def _shell_close(self, params: dict) -> dict[str, Any]:
        if set(params) - {"shell_id", "session_owner"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры закрытия shell.")
        session = self._shell_by_id(params)
        with session.lock:
            session.close()
        with self.root_shell_lock:
            self.root_shells.pop(session.session_id, None)
        return {"ok": True, "shell_id": session.session_id, "alive": False, "exit_code": session.exit_code}

    @staticmethod
    def _backup_dir() -> Path:
        return Path(os.environ.get("KVN_BACKUP_DIR", "/backup")).resolve()

    def _backup_list(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Список backup не принимает параметры.")
        backup_dir = self._backup_dir()
        backups: list[dict[str, Any]] = []
        if backup_dir.is_dir():
            rows: list[tuple[float, dict[str, Any]]] = []
            for path in backup_dir.glob("kvn-vpn-backup-*.tar"):
                if path.is_symlink() or not path.is_file():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                rows.append((stat.st_mtime, {
                    "name": path.name,
                    "size": stat.st_size,
                    "mtime": int(stat.st_mtime),
                    "readable": os.access(path, os.R_OK),
                }))
            backups = [item for _mtime, item in sorted(rows, key=lambda row: row[0], reverse=True)]
        return {
            "available": backup_dir.is_dir(),
            "directory": str(backup_dir),
            "backups": backups,
        }

    def _project_backup(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Backup проекта не принимает параметры.")
        script = (self.project_root / "tools" / "project-backup.sh").resolve()
        if not script.is_file() or not script.is_relative_to(self.project_root):
            raise ProtocolError("not_found", "Скрипт backup проекта не найден.")
        correlation_id = uuid.uuid4().hex
        unit = f"kvn-project-backup-{correlation_id[:12]}"
        result = self.runner.run(
            [
                "systemd-run",
                "--collect",
                f"--unit={unit}",
                f"--property=WorkingDirectory={self.project_root}",
                "/bin/bash",
                str(script),
            ],
            timeout=30,
            max_output=32 * 1024,
        )
        return {
            "ok": result.returncode == 0,
            "action": "backup",
            "unit": unit,
            "journal_command": f"journalctl -u {unit} -n 200 --no-pager",
            "command": result.to_dict(),
            "correlation_id": correlation_id,
            "backup_dir": str(self._backup_dir()),
        }

    def _metrics_current(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Текущие метрики не принимают параметры.")
        if not self.monitoring_enabled():
            return {
                "available": False, "disabled": True,
                "reason": "monitoring_disabled", "sample": None,
            }
        if self.metrics is None:
            return {"available": False, "sample": None}
        return self.metrics.current()

    def _metrics_history(self, params: dict) -> dict[str, Any]:
        if set(params) - {"range_hours", "step"}:
            raise ProtocolError("invalid_params", "Неизвестные параметры истории метрик.")
        range_hours = params.get("range_hours", 24)
        step = params.get("step", "auto")
        if not isinstance(range_hours, int) or isinstance(range_hours, bool):
            raise ProtocolError("invalid_params", "range_hours должен быть целым числом.")
        if not (step == "auto" or isinstance(step, int) and not isinstance(step, bool)):
            raise ProtocolError("invalid_params", "step должен быть auto или целым числом минут.")
        if not self.monitoring_enabled():
            return {
                "available": False, "disabled": True,
                "reason": "monitoring_disabled", "range_hours": range_hours,
                "step_minutes": 0, "generated_at": int(time.time()), "points": [],
            }
        if self.metrics is None:
            return {
                "available": False,
                "range_hours": range_hours,
                "step_minutes": 0,
                "generated_at": int(time.time()),
                "points": [],
            }
        try:
            return self.metrics.history(range_hours, step)
        except MetricsQueryError as exc:
            raise ProtocolError("invalid_params", str(exc)) from exc

    def monitoring_enabled(self) -> bool:
        """Fail-open для старых state и временно недоступного control."""
        try:
            control = self._control()
            if not hasattr(control, "portal_performance"):
                return True
            performance = control.portal_performance()
            return performance.get("features", {}).get("monitoring") is not False
        except Exception:
            return True

    def _portal_performance(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Настройки нагрузки не принимают параметры.")
        try:
            return self._control().portal_performance()
        except Exception as exc:
            code = getattr(exc, "code", "read_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _portal_performance_update(self, params: dict) -> dict[str, Any]:
        try:
            return self._control().update_portal_performance(params)
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _sni_apply(self, params: dict) -> dict[str, Any]:
        allowed = {"action", "revision", "system", "sni"}
        if set(params) - allowed:
            raise ProtocolError("invalid_params", "Неизвестные параметры SNI.")
        try:
            from portal.control import ControlError
        except ModuleNotFoundError:
            from control import ControlError  # type: ignore
        try:
            return self._control().apply_sni_route(params)
        except ControlError as exc:
            raise ProtocolError(exc.code, str(exc)) from exc

    def _mtproto_diagnose(self, params: dict) -> dict[str, Any]:
        if set(params) != {"system"}:
            raise ProtocolError("invalid_params", "Диагностика MTProto принимает только system.")
        try:
            return self._control().mtproto_diagnose(params)
        except Exception as exc:
            code = getattr(exc, "code", "diagnose_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _mtproto_status(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Статус MTProto не принимает параметры.")
        return self._control().mtproto_status()

    def _mtproto_apply(self, params: dict) -> dict[str, Any]:
        if set(params) != {"system", "origin", "revision"}:
            raise ProtocolError("invalid_params", "Некорректная схема настройки MTProto.")
        try:
            return self._control().apply_mtproto(params)
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _protocol_apply(self, params: dict) -> dict[str, Any]:
        allowed = {"action", "system", "mode", "revision"}
        if set(params) != allowed:
            raise ProtocolError("invalid_params", "Некорректная схема редактора протокола.")
        try:
            from portal.control import ControlError
        except ModuleNotFoundError:
            from control import ControlError  # type: ignore
        try:
            return self._control().apply_protocol(params)
        except ControlError as exc:
            raise ProtocolError(exc.code, str(exc)) from exc

    def _amneziawg_settings(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Настройки AmneziaWG не принимают параметры.")
        return self._control().amneziawg_settings()

    def _amneziawg_apply(self, params: dict) -> dict[str, Any]:
        required = {
            "revision", "protocol_version", "content_padding_addition",
            "rekey_after_time", "rekey_timeout", "reject_after_time",
            "keepalive_timeout", "max_handshake_attempts",
            "regenerate_header_key",
        }
        keys = set(params)
        if not required.issubset(keys) or keys - required - {"random_trailers"}:
            raise ProtocolError("invalid_params", "Некорректная схема настроек AmneziaWG.")
        if "random_trailers" in params and not isinstance(params["random_trailers"], bool):
            raise ProtocolError("invalid_params", "Устаревший флаг AmneziaWG должен быть boolean.")
        if params.get("protocol_version") == "3.1":
            capability = self.runner.run(
                ["awg", "set", "--help"], timeout=5, max_output=32 * 1024
            )
            usage = f"{capability.stdout}\n{capability.stderr}".lower()
            required = (
                "header-protection-key",
                "content-padding-addition",
                "rekey-after-time",
            )
            if any(token not in usage for token in required):
                raise ProtocolError(
                    "awg31_unsupported",
                    "Установленные awg-tools не поддерживают AWG 3.1. Сначала обновите пакет AmneziaWG и перезагрузите сервер.",
                )
        try:
            return self._control().apply_amneziawg(params)
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _ping(self, _params: dict) -> dict[str, Any]:
        return {
            "status": "ok",
            "protocol": 1,
            "transport": "unix",
            "generation": self.generation,
            "started_at": self.started_at,
            "capabilities": [
                "rpc-v1",
                "dashboard-snapshot-v1",
                "runtime-apply-v1",
                "session-bound-shell-v1",
            ],
        }

    def _service_status(self, params: dict) -> dict[str, Any]:
        service = self._service(params)
        return self._service_status_snapshot(service)

    def _service_status_snapshot(self, service: str) -> dict[str, Any]:
        if service in {"amneziawg", "wireguard", "agent"}:
            unit = {
                "amneziawg": "kvn-amneziawg.service",
                "wireguard": "kvn-wireguard.service",
                "agent": "kvn-portal-agent.service",
            }[service]
            result = self.runner.run(["systemctl", "is-active", unit], timeout=10)
        else:
            result = self.runner.run([*self.compose, "ps", "--format", "json", service], timeout=15)
        active = result.returncode == 0
        if service in DOCKER_SERVICES:
            active = active and ("running" in result.stdout.lower() or '"state":"running"' in result.stdout.lower())
        try:
            control = self._control()
            preferences = (
                control.effective_service_preferences()
                if hasattr(control, "effective_service_preferences")
                else control.service_preferences() if hasattr(control, "service_preferences") else {}
            )
        except Exception:
            preferences = {}
        enabled = preferences.get(service, True)
        return {"service": service, "active": active, "enabled": enabled, "command": result.to_dict()}

    def _service_action(self, params: dict) -> dict[str, Any]:
        started = time.monotonic()
        correlation_id = uuid.uuid4().hex
        service = self._service(params)
        action = params.get("action")
        if not isinstance(action, str) or action not in SERVICE_ACTIONS:
            raise ProtocolError("invalid_params", "Действие сервиса не разрешено.")
        if action not in SERVICE_ALLOWED_ACTIONS[service]:
            raise ProtocolError("policy_denied", "Действие для этого сервиса запрещено политикой.")
        if service in SELF_LOCKOUT_SERVICES and action in {"stop", "disable"}:
            raise ProtocolError("policy_denied", "Отключение этого сервиса через портал запрещено.")
        before = self._service_status_snapshot(service)
        warning = ""
        fallback = None
        precommand = None
        if service in SELF_LOCKOUT_SERVICES and action in {"reload", "restart"}:
            warning = "Соединение с порталом может временно прерваться."

        if action == "apply":
            if service not in HOST_VPN_SERVICES:
                raise ProtocolError("policy_denied", "Применение конфигурации доступно только для host VPN-сервисов.")
            try:
                apply_result = self._control().apply_host_service(service)
            except Exception as exc:
                code = getattr(exc, "code", "apply_failed")
                raise ProtocolError(code, str(exc)) from exc
            after = self._service_status_snapshot(service)
            apply_report = apply_result.get("apply", {}) if isinstance(apply_result.get("apply"), dict) else {}
            operation_ok = apply_report.get("outcome") in {"applied", "fallback", "no-op"}
            health_ok = after["active"] is True
            return {
                "service": service,
                "action": action,
                "ok": operation_ok and health_ok,
                "before": {"active": before["active"]},
                "after": {"active": after["active"]},
                "health": {"ok": health_ok, "expected_active": True},
                "duration_ms": int((time.monotonic() - started) * 1000),
                "correlation_id": correlation_id,
                "warning": warning,
                "command": None,
                "precommand": None,
                "fallback": None,
                "plan": apply_result.get("plan", {}),
                "apply": apply_report,
            }

        if service == "agent":
            if action not in {"restart", "reload"}:
                raise ProtocolError("policy_denied", "Для host-agent разрешён только отложенный restart.")
            argv = [
                "systemd-run", "--on-active=2s", "--collect",
                f"--unit=kvn-portal-agent-restart-{correlation_id[:12]}",
                "systemctl", "restart", "kvn-portal-agent.service",
            ]
        elif service == "amneziawg":
            systemd_action = {"enable": "enable", "disable": "disable"}.get(action, action)
            argv = ["systemctl", systemd_action]
            if action in {"enable", "disable"}:
                argv.append("--now")
            argv.append("kvn-amneziawg.service")
        elif service == "wireguard":
            systemd_action = {"enable": "enable", "disable": "disable"}.get(action, action)
            argv = ["systemctl", systemd_action]
            if action in {"enable", "disable"}:
                argv.append("--now")
            argv.append("kvn-wireguard.service")
        elif service == "portal" and action == "reload":
            argv = [*self.compose, "restart", service]
        elif action == "reload":
            reload_argv = RELOAD_COMMANDS.get(service)
            if reload_argv is None:
                raise ProtocolError("capability_unavailable", "Сервис не поддерживает безопасный reload.")
            argv = [*self.compose, *reload_argv]
        elif action == "enable":
            container = CONTAINER_NAMES[service]
            precommand = self.runner.run(["docker", "update", "--restart=unless-stopped", container], timeout=20)
            argv = [*self.compose, "up", "-d", service]
        elif action == "disable":
            container = CONTAINER_NAMES[service]
            precommand = self.runner.run(["docker", "update", "--restart=no", container], timeout=20)
            argv = [*self.compose, "stop", service]
        else:
            argv = [*self.compose, action, service]
        if precommand is not None and precommand.returncode != 0:
            result = precommand
        else:
            result = self.runner.run(argv, timeout=120)
        if action == "reload" and service in RELOAD_COMMANDS and result.returncode != 0:
            fallback = self.runner.run([*self.compose, "restart", service], timeout=120)
        operation_ok = result.returncode == 0 or bool(fallback and fallback.returncode == 0)
        if operation_ok and action in {"enable", "disable"}:
            try:
                self._control().set_service_enabled(service, action == "enable")
            except Exception:
                operation_ok = False
                warning = "Сервис изменён, но persistent-состояние сохранить не удалось."
        after = self._service_status_snapshot(service)
        expected_active = action not in {"stop", "disable"}
        health_ok = after["active"] is expected_active
        if service == "agent" and operation_ok:
            health_ok = True
        return {
            "service": service,
            "action": action,
            "ok": operation_ok and health_ok,
            "before": {"active": before["active"]},
            "after": {"active": after["active"]},
            "health": {"ok": health_ok, "expected_active": expected_active},
            "duration_ms": int((time.monotonic() - started) * 1000),
            "correlation_id": correlation_id,
            "warning": warning,
            "command": result.to_dict(),
            "precommand": precommand.to_dict() if precommand else None,
            "fallback": fallback.to_dict() if fallback else None,
        }

    def reconcile_services(self) -> list[dict[str, Any]]:
        results = []
        control = self._control()
        preferences = (
            control.effective_service_preferences()
            if hasattr(control, "effective_service_preferences")
            else control.service_preferences()
        )
        for service, enabled in sorted(preferences.items()):
            if service not in SERVICES or service in SELF_LOCKOUT_SERVICES:
                continue
            action = "enable" if enabled else "disable"
            try:
                results.append(self._service_action({"service": service, "action": action}))
            except ProtocolError as exc:
                results.append({"service": service, "ok": False, "error": exc.code})
        return results

    def _logs_tail(self, params: dict) -> dict[str, Any]:
        service = self._service(params)
        tail = params.get("tail", 200)
        since_minutes = params.get("since_minutes", 60)
        if not isinstance(tail, int) or not 50 <= tail <= 2000:
            raise ProtocolError("invalid_params", "tail должен быть в диапазоне 50..2000.")
        if not isinstance(since_minutes, int) or not 1 <= since_minutes <= 10080:
            raise ProtocolError("invalid_params", "since_minutes должен быть в диапазоне 1..10080.")
        if service in {"amneziawg", "wireguard", "agent"}:
            unit = {
                "amneziawg": "kvn-amneziawg.service",
                "wireguard": "kvn-wireguard.service",
                "agent": "kvn-portal-agent.service",
            }[service]
            argv = ["journalctl", "-u", unit, "--no-pager", "-n", str(tail), "--since", f"-{since_minutes} minutes"]
        else:
            argv = [*self.compose, "logs", "--no-color", "--tail", str(tail), "--since", f"{since_minutes}m", service]
        result = self.runner.run(argv, timeout=30, max_output=256 * 1024)
        return {
            "service": service,
            "tail": tail,
            "since_minutes": since_minutes,
            "cursor": int(time.time() * 1000),
            "command": result.to_dict(),
        }

    def _container_stats(self, _params: dict) -> dict[str, Any]:
        service_names = [(service, CONTAINER_NAMES[service]) for service in sorted(CONTAINER_NAMES)]
        states = {}
        existing_names = []
        inspect = self.runner.run(
            [
                "docker", "inspect", "--format",
                "{{.Name}}\t{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}\t{{.RestartCount}}",
                *[name for _service, name in service_names],
            ],
            timeout=15,
            max_output=32 * 1024,
        )
        parsed_states = {}
        for line in inspect.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) != 4:
                continue
            name = parts[0].removeprefix("/")
            parsed_states[name] = {
                "state": parts[1],
                "health": parts[2],
                "restarts": int(parts[3]) if parts[3].isdigit() else 0,
            }
            existing_names.append(name)
        for service, name in service_names:
            state = parsed_states.get(name, {"state": "missing", "health": "unknown", "restarts": 0})
            states[name] = {**state, "service": service}

        if existing_names:
            result = self.runner.run(
                ["docker", "stats", "--no-stream", "--format", "{{json .}}", *existing_names],
                timeout=30,
            )
        else:
            result = CommandResult(tuple(["docker", "stats", "--no-stream"]), 0, "", "", 0)

        stats_by_name = {}
        for line in result.stdout.splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            name = str(row.get("Name", ""))
            if name:
                stats_by_name[name] = row

        rows = []
        for _service, name in service_names:
            row = dict(stats_by_name.get(name, {"Name": name}))
            row.update(states[name])
            rows.append(row)
        return {
            "available": result.returncode == 0,
            "containers": rows,
            "state_available": any(item["state"] != "missing" for item in states.values()),
            "command": result.to_dict(),
            "inspect": inspect.to_dict(),
        }

    def _dashboard_collect(self, name: str, context: dict[str, Any]) -> dict[str, Any]:
        if name == "host":
            return self._host_health({})
        if name == "metrics":
            return self._metrics_current({})
        if name == "containers":
            return self._container_stats({})
        if name == "protocols":
            return self._protocol_stats({})
        if name == "certificates":
            return self._control().certificate_status()
        if name == "health_summary":
            return self._health_summary(
                {},
                containers=context.get("containers"),
                certificates=context.get("certificates"),
            )
        if name == "ssh_sessions":
            return self._ssh_sessions()
        raise ProtocolError("internal_error", "Неизвестный источник dashboard.")

    def _ssh_sessions(self) -> dict[str, Any]:
        """Возвращает только безопасные поля активных удалённых login-сессий."""
        rows = self._ssh_sessions_loginctl()
        if rows is None:
            rows = self._ssh_sessions_who()
        if rows is None:
            return {
                "available": False,
                "sessions": [],
                "count": 0,
                "users": 0,
                "reason": "session_sources_unavailable",
            }
        rows = self._deduplicate_ssh_sessions(rows)
        return {
            "available": True,
            "sessions": rows,
            "count": len(rows),
            "users": len({item["user"] for item in rows}),
        }

    @staticmethod
    def _deduplicate_ssh_sessions(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        unique: dict[tuple[str, str, str, str], dict[str, str]] = {}
        for item in rows:
            key = (item["user"], item["tty"], item["login_at"], item["remote_ip"])
            unique[key] = item
        return sorted(
            unique.values(),
            key=lambda item: (item["user"].lower(), item["tty"], item["login_at"]),
        )

    @staticmethod
    def _safe_ssh_row(
        user: str,
        tty: str,
        login_at: str,
        remote: str,
    ) -> dict[str, str] | None:
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", user):
            return None
        if not re.fullmatch(r"[A-Za-z0-9_./:-]{1,64}", tty):
            return None
        try:
            remote_ip = str(ipaddress.ip_address(remote.strip().strip("()")))
        except ValueError:
            return None
        timestamp = re.search(
            r"(?P<date>\d{4}-\d{2}-\d{2})[ T]+(?P<time>\d{2}:\d{2})",
            login_at,
        )
        if timestamp is None:
            return None
        return {
            "user": user,
            "tty": tty,
            "login_at": f"{timestamp.group('date')} {timestamp.group('time')}",
            "remote_ip": remote_ip,
        }

    def _ssh_sessions_loginctl(self) -> list[dict[str, str]] | None:
        result = self.runner.run(
            ["loginctl", "list-sessions", "--no-legend", "--no-pager"],
            timeout=5,
            max_output=64 * 1024,
        )
        if result.returncode != 0:
            return None
        rows: list[dict[str, str]] = []
        session_ids: list[str] = []
        for line in result.stdout.splitlines()[:128]:
            parts = line.split()
            if parts and re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", parts[0]):
                session_ids.append(parts[0])
        for session_id in session_ids:
            details = self.runner.run(
                [
                    "loginctl",
                    "show-session",
                    session_id,
                    "--no-pager",
                    "--property=Name",
                    "--property=Remote",
                    "--property=RemoteHost",
                    "--property=TTY",
                    "--property=Timestamp",
                ],
                timeout=5,
                max_output=16 * 1024,
            )
            if details.returncode != 0:
                continue
            fields: dict[str, str] = {}
            for line in details.stdout.splitlines():
                key, separator, value = line.partition("=")
                if separator and key in {"Name", "Remote", "RemoteHost", "TTY", "Timestamp"}:
                    fields[key] = value.strip()
            if fields.get("Remote") != "yes":
                continue
            row = self._safe_ssh_row(
                fields.get("Name", ""),
                fields.get("TTY", ""),
                fields.get("Timestamp", ""),
                fields.get("RemoteHost", ""),
            )
            if row is not None:
                rows.append(row)
        return rows or None

    def _ssh_sessions_who(self) -> list[dict[str, str]] | None:
        result = self.runner.run(["who", "--ips"], timeout=5, max_output=64 * 1024)
        if result.returncode != 0:
            result = self.runner.run(["who"], timeout=5, max_output=64 * 1024)
        if result.returncode != 0:
            return None
        rows: list[dict[str, str]] = []
        pattern = re.compile(
            r"^\s*(?P<user>\S+)\s+(?P<tty>\S+)\s+"
            r"(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2})"
            r"(?:\s+(?P<remote>.+?))?\s*$"
        )
        for line in result.stdout.splitlines():
            match = pattern.match(line)
            if not match:
                continue
            row = self._safe_ssh_row(
                match.group("user"),
                match.group("tty"),
                f"{match.group('date')} {match.group('time')}",
                match.group("remote") or "",
            )
            if row is not None:
                rows.append(row)
        return rows

    def _dashboard_snapshot(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Dashboard snapshot не принимает параметры.")
        return self.dashboard_cache.get()

    def _host_health(self, _params: dict) -> dict[str, Any]:
        commands = {
            "uptime": ["uptime", "-p"],
            "memory": ["free", "-b"],
            "disk": ["df", "-B1", "--output=size,used,avail,pcent", str(self.project_root)],
        }
        data = {}
        for name, argv in commands.items():
            data[name] = self.runner.run(argv, timeout=10, max_output=32 * 1024).to_dict()
        return data

    def _awg_status(self, _params: dict) -> dict[str, Any]:
        result = self.runner.run(["awg", "show", "awg0", "dump"], timeout=15)
        return {"available": result.returncode == 0, "command": result.to_dict()}

    @staticmethod
    def _numbers(value: str) -> list[int]:
        return [int(item) for item in re.findall(r"(?<![A-Za-z])\d+", value)]

    def _command_metric(self, argv: list[str], parser) -> dict[str, Any]:
        try:
            result = self.runner.run(argv, timeout=5, max_output=64 * 1024)
        except ProtocolError as exc:
            return {"available": False, "error": exc.code, "values": {}}
        if result.returncode != 0:
            return {"available": False, "error": "api_unavailable", "values": {}}
        try:
            values = parser(result.stdout)
        except (ValueError, json.JSONDecodeError, TypeError, AttributeError):
            return {"available": False, "error": "invalid_response", "values": {}}
        return {"available": True, "error": "", "values": values}

    def _hysteria_metrics(self) -> dict[str, Any]:
        secret = self._control().observability_config().get("hysteria_secret", "")
        if not secret:
            return {"available": False, "error": "not_configured", "values": {}}
        values = {"users": 0, "online": 0, "tx": 0, "rx": 0}
        for endpoint in ["traffic", "online"]:
            try:
                result = self.runner.run(
                    [
                        "docker", "exec", "hysteria", "wget", "-qO-",
                        "--header", f"Authorization: {secret}", f"http://127.0.0.1:9090/{endpoint}",
                    ],
                    timeout=5,
                    max_output=64 * 1024,
                )
            except ProtocolError as exc:
                return {"available": False, "error": exc.code, "values": {}}
            if result.returncode != 0:
                return {"available": False, "error": "api_unavailable", "values": {}}
            try:
                payload = json.loads(result.stdout)
                if endpoint == "traffic":
                    values["users"] = len(payload)
                    values["tx"] = sum(int(item.get("tx", 0)) for item in payload.values())
                    values["rx"] = sum(int(item.get("rx", 0)) for item in payload.values())
                else:
                    values["online"] = sum(int(item) for item in payload.values())
            except (json.JSONDecodeError, ValueError, TypeError, AttributeError):
                return {"available": False, "error": "invalid_response", "values": {}}
        return {"available": True, "error": "", "values": values}

    def _protocol_stats(self, _params: dict) -> dict[str, Any]:
        compose = self.compose
        collectors = {
            "xray": self._command_metric(
                ["docker", "exec", "xray", "xray", "api", "statsquery", "--server=127.0.0.1:10085", "-pattern", "", "-reset=false"],
                lambda text: {"counters": len(re.findall(r'"value"\s*:', text)), "total": sum(int(value) for value in re.findall(r'"value"\s*:\s*"?(\d+)', text))},
            ),
            "hysteria": self._hysteria_metrics(),
            "telemt": self._command_metric(
                ["curl", "--fail", "--silent", "--show-error", "--max-time", "3", "http://127.0.0.1:9091/metrics"],
                lambda text: {"samples": len(self._numbers(text)), "total": sum(self._numbers(text))},
            ),
            "ocserv": self._command_metric(
                [*compose, "exec", "-T", "ocserv", "occtl", "-j", "show", "status"],
                lambda text: {"numeric_values": len(self._numbers(text)), "total": sum(self._numbers(text))},
            ),
            "amneziawg": self._command_metric(
                ["awg", "show", "awg0", "dump"],
                self._parse_awg_metrics,
            ),
            "wireguard": self._command_metric(
                ["wg", "show", "wg0", "dump"],
                self._parse_awg_metrics,
            ),
            "nginx": self._command_metric(
                [*compose, "exec", "-T", "nginx", "wget", "-qO-", "http://127.0.0.1:8080/nginx_status"],
                lambda text: {"active": int(re.search(r"Active connections:\s*(\d+)", text).group(1))},
            ),
            "mtg": {"available": False, "error": "container_metrics_only", "values": {}},
        }
        return {"collectors": collectors}

    @staticmethod
    def _activity_row(
        system: str,
        status: str,
        source: str,
        reason: str = "",
        **fields: Any,
    ) -> dict[str, Any]:
        row: dict[str, Any] = {
            "system": system,
            "status": status,
            "source": source,
            "reason": reason,
        }
        for key in (
            "last_activity", "uplink_bytes", "downlink_bytes", "rx_bytes", "tx_bytes",
            "online", "connections",
        ):
            value = fields.get(key)
            if value is None:
                continue
            if key in {"online"}:
                row[key] = bool(value)
            elif isinstance(value, (int, float)) and value >= 0:
                row[key] = int(value)
        return row

    @staticmethod
    def _json_stats(value: Any) -> list[tuple[str, int]]:
        rows: list[tuple[str, int]] = []

        def walk(item: Any) -> None:
            if isinstance(item, dict):
                name = item.get("name")
                raw_value = item.get("value")
                if isinstance(name, str) and isinstance(raw_value, (int, str)):
                    try:
                        rows.append((name, max(0, int(raw_value))))
                    except ValueError:
                        pass
                for nested in item.values():
                    walk(nested)
            elif isinstance(item, list):
                for nested in item[:USER_ACTIVITY_MAX_ROWS * 8]:
                    walk(nested)

        walk(value)
        return rows[:USER_ACTIVITY_MAX_ROWS * 8]

    def _xray_user_activity(self, subject: dict) -> dict[str, dict[str, Any]]:
        systems = [item for item in subject["systems"] if item in {"tls", "reality-xhttp", "reality-tcp"}]
        pattern = f"user>>>{subject['name']}-"
        result = self.runner.run(
            [
                "docker", "exec", "xray", "xray", "api", "statsquery",
                "--server=127.0.0.1:10085", "-pattern", pattern, "-reset=false",
            ],
            timeout=USER_ACTIVITY_COMMAND_TIMEOUT,
            max_output=USER_ACTIVITY_MAX_OUTPUT,
        )
        if result.returncode != 0:
            return {
                system: self._activity_row(system, "unavailable", "xray-stats", "api_unavailable")
                for system in systems
            }
        try:
            stats = self._json_stats(json.loads(result.stdout or "{}"))
        except json.JSONDecodeError:
            stats = []
        output: dict[str, dict[str, Any]] = {}
        for system in systems:
            email = f"{subject['name']}-{system}"
            prefix = f"user>>>{email}>>>traffic>>>"
            uplink = sum(value for name, value in stats if name == prefix + "uplink")
            downlink = sum(value for name, value in stats if name == prefix + "downlink")
            output[system] = self._activity_row(
                system,
                "observed" if uplink or downlink else "idle",
                "xray-stats",
                uplink_bytes=uplink,
                downlink_bytes=downlink,
            )
        return output

    def _hysteria_user_activity(self, subject: dict) -> dict[str, dict[str, Any]]:
        secret = self._control().observability_config().get("hysteria_secret", "")
        if not secret:
            return {"hysteria": self._activity_row("hysteria", "unavailable", "hysteria-api", "not_configured")}
        payloads: dict[str, dict] = {}
        for endpoint in ("traffic", "online"):
            result = self.runner.run(
                [
                    "docker", "exec", "hysteria", "wget", "-qO-",
                    "--header", f"Authorization: {secret}", f"http://127.0.0.1:9090/{endpoint}",
                ],
                timeout=USER_ACTIVITY_COMMAND_TIMEOUT,
                max_output=USER_ACTIVITY_MAX_OUTPUT,
            )
            if result.returncode != 0:
                return {"hysteria": self._activity_row("hysteria", "unavailable", "hysteria-api", "api_unavailable")}
            try:
                payload = json.loads(result.stdout or "{}")
            except json.JSONDecodeError:
                payload = None
            if not isinstance(payload, dict):
                return {"hysteria": self._activity_row("hysteria", "unavailable", "hysteria-api", "invalid_response")}
            payloads[endpoint] = payload
        traffic = payloads["traffic"].get(subject["name"], {})
        if not isinstance(traffic, dict):
            traffic = {}
        online_raw = payloads["online"].get(subject["name"], 0)
        try:
            online_count = max(0, int(online_raw))
            rx = max(0, int(traffic.get("rx", 0)))
            tx = max(0, int(traffic.get("tx", 0)))
        except (TypeError, ValueError):
            return {"hysteria": self._activity_row("hysteria", "unavailable", "hysteria-api", "invalid_response")}
        return {"hysteria": self._activity_row(
            "hysteria", "active" if online_count else "observed" if rx or tx else "idle", "hysteria-api",
            rx_bytes=rx, tx_bytes=tx, online=bool(online_count), connections=online_count,
        )}

    @staticmethod
    def _parse_prometheus_user(text: str, username: str) -> dict[str, int]:
        values: dict[str, int] = {}
        for line in text.splitlines()[:USER_ACTIVITY_MAX_ROWS * 64]:
            match = re.fullmatch(
                r"([A-Za-z_:][A-Za-z0-9_:]*)\{([^}]*)\}\s+([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)",
                line.strip(),
            )
            if not match:
                continue
            labels = {
                key: bytes(value, "utf-8").decode("unicode_escape")
                for key, value in re.findall(r'(\w+)="((?:\\.|[^"\\])*)"', match.group(2))
            }
            if not any(labels.get(key) == username for key in ("user", "username", "access_user")):
                continue
            try:
                values[match.group(1).lower()] = max(0, int(float(match.group(3))))
            except (ValueError, OverflowError):
                continue
            if len(values) >= USER_ACTIVITY_MAX_ROWS:
                break
        return values

    def _telemt_user_activity(self, subject: dict) -> dict[str, dict[str, Any]]:
        result = self.runner.run(
            ["curl", "--fail", "--silent", "--show-error", "--max-time", "3", "http://127.0.0.1:9091/metrics"],
            timeout=USER_ACTIVITY_COMMAND_TIMEOUT,
            max_output=USER_ACTIVITY_MAX_OUTPUT,
        )
        if result.returncode != 0:
            return {"telemt": self._activity_row("telemt", "unavailable", "telemt-metrics", "api_unavailable")}
        metrics = self._parse_prometheus_user(result.stdout, subject["name"])
        if not metrics:
            return {"telemt": self._activity_row("telemt", "unsupported", "telemt-metrics", "per_user_metrics_not_exposed")}
        rx = sum(value for name, value in metrics.items() if "byte" in name and any(part in name for part in ("rx", "receive", "inbound", "from_client")))
        tx = sum(value for name, value in metrics.items() if "byte" in name and any(part in name for part in ("tx", "sent", "outbound", "to_client")))
        connections = sum(
            value for name, value in metrics.items()
            if "connection" in name and any(part in name for part in ("active", "current"))
        )
        if not any((rx, tx, connections)) and not any("byte" in name or "connection" in name for name in metrics):
            return {"telemt": self._activity_row("telemt", "unsupported", "telemt-metrics", "per_user_fields_not_exposed")}
        return {"telemt": self._activity_row(
            "telemt", "active" if connections else "observed" if rx or tx else "idle", "telemt-metrics",
            rx_bytes=rx, tx_bytes=tx, online=bool(connections), connections=connections,
        )}

    def _wireguard_user_activity(self, subject: dict, system: str) -> dict[str, dict[str, Any]]:
        command = "awg" if system == "amneziawg" else "wg"
        interface = "awg0" if system == "amneziawg" else "wg0"
        public_key = subject.get(f"{system}_public_key", "")
        if not public_key:
            return {system: self._activity_row(system, "unavailable", f"{command}-dump", "public_key_missing")}
        result = self.runner.run(
            [command, "show", interface, "dump"],
            timeout=USER_ACTIVITY_COMMAND_TIMEOUT,
            max_output=USER_ACTIVITY_MAX_OUTPUT,
        )
        if result.returncode != 0:
            return {system: self._activity_row(system, "unavailable", f"{command}-dump", "interface_unavailable")}
        peer = next(
            (parts for parts in (line.split("\t") for line in result.stdout.splitlines()) if parts and parts[0] == public_key),
            None,
        )
        if peer is None or len(peer) < 7:
            return {system: self._activity_row(system, "unavailable", f"{command}-dump", "peer_not_applied")}
        try:
            handshake, rx, tx = max(0, int(peer[4])), max(0, int(peer[5])), max(0, int(peer[6]))
        except ValueError:
            return {system: self._activity_row(system, "unavailable", f"{command}-dump", "invalid_response")}
        age = max(0, int(time.time()) - handshake) if handshake else None
        status = "active" if age is not None and age <= USER_ACTIVITY_RECENT_SECONDS else "stale" if handshake else "idle"
        return {system: self._activity_row(
            system, status, f"{command}-dump", last_activity=handshake or None, rx_bytes=rx, tx_bytes=tx,
        )}

    @staticmethod
    def _find_ocserv_user(value: Any, username: str) -> dict | None:
        if isinstance(value, dict):
            lowered = {str(key).lower().replace(" ", "_"): item for key, item in value.items()}
            if any(lowered.get(key) == username for key in ("username", "user", "name")):
                return lowered
            for nested in value.values():
                found = AgentDispatcher._find_ocserv_user(nested, username)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for nested in value[:USER_ACTIVITY_MAX_ROWS * 4]:
                found = AgentDispatcher._find_ocserv_user(nested, username)
                if found is not None:
                    return found
        return None

    def _ocserv_user_activity(self, subject: dict) -> dict[str, dict[str, Any]]:
        result = self.runner.run(
            [*self.compose, "exec", "-T", "ocserv", "occtl", "-j", "show", "users"],
            timeout=USER_ACTIVITY_COMMAND_TIMEOUT,
            max_output=USER_ACTIVITY_MAX_OUTPUT,
        )
        if result.returncode != 0:
            return {"ocserv": self._activity_row("ocserv", "unavailable", "occtl", "api_unavailable")}
        try:
            user = self._find_ocserv_user(json.loads(result.stdout or "{}"), subject["name"])
        except json.JSONDecodeError:
            return {"ocserv": self._activity_row("ocserv", "unavailable", "occtl", "invalid_response")}
        if user is None:
            return {"ocserv": self._activity_row("ocserv", "idle", "occtl", online=False, connections=0)}

        def number(*keys: str) -> int:
            for key in keys:
                try:
                    return max(0, int(user.get(key, 0)))
                except (TypeError, ValueError):
                    continue
            return 0

        rx = number("rx", "bytes_in", "received_bytes")
        tx = number("tx", "bytes_out", "sent_bytes")
        return {"ocserv": self._activity_row(
            "ocserv", "active", "occtl", rx_bytes=rx, tx_bytes=tx, online=True, connections=1,
        )}

    def _user_activity(self, params: dict) -> dict[str, Any]:
        if set(params) != {"name"} or not isinstance(params.get("name"), str):
            raise ProtocolError("invalid_params", "Активность пользователя принимает только name.")
        try:
            subject = self._control().user_activity_subject(params["name"])
        except Exception as exc:
            code = getattr(exc, "code", "invalid_user")
            if code not in {"invalid_user", "not_found"}:
                code = "invalid_user"
            raise ProtocolError(code, "Пользователь не найден или имя некорректно.") from exc

        service_by_system = {
            "tls": "xray", "reality-xhttp": "xray", "reality-tcp": "xray",
            "hysteria": "hysteria", "telemt": "telemt", "mtg": "mtg",
            "amneziawg": "amneziawg", "wireguard": "wireguard", "ocserv": "ocserv",
        }
        rows: dict[str, dict[str, Any]] = {}
        runnable: set[str] = set()
        for system in subject["systems"][:USER_ACTIVITY_MAX_ROWS]:
            if system == "mtg":
                rows[system] = self._activity_row(system, "unsupported", "mtg-shared-secret", "shared_secret_has_no_attribution")
            elif not subject["enabled"] or not subject["services"].get(service_by_system[system], True):
                rows[system] = self._activity_row(system, "disabled", service_by_system[system], "user_or_service_disabled")
            else:
                runnable.add(system)

        jobs: dict[str, Any] = {}
        executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="kvn-user-activity")
        try:
            if runnable & {"tls", "reality-xhttp", "reality-tcp"}:
                jobs["xray"] = executor.submit(self._xray_user_activity, subject)
            if "hysteria" in runnable:
                jobs["hysteria"] = executor.submit(self._hysteria_user_activity, subject)
            if "telemt" in runnable:
                jobs["telemt"] = executor.submit(self._telemt_user_activity, subject)
            if "amneziawg" in runnable:
                jobs["amneziawg"] = executor.submit(self._wireguard_user_activity, subject, "amneziawg")
            if "wireguard" in runnable:
                jobs["wireguard"] = executor.submit(self._wireguard_user_activity, subject, "wireguard")
            if "ocserv" in runnable:
                jobs["ocserv"] = executor.submit(self._ocserv_user_activity, subject)
            done, _pending = wait(jobs.values(), timeout=USER_ACTIVITY_TOTAL_TIMEOUT)
            for adapter, future in jobs.items():
                adapter_systems = (
                    sorted(runnable & {"tls", "reality-xhttp", "reality-tcp"})
                    if adapter == "xray" else [adapter]
                )
                if future not in done:
                    for system in adapter_systems:
                        rows[system] = self._activity_row(system, "unavailable", adapter, "total_timeout")
                    continue
                try:
                    rows.update(future.result())
                except ProtocolError as exc:
                    for system in adapter_systems:
                        rows[system] = self._activity_row(system, "unavailable", adapter, exc.code)
                except Exception:
                    for system in adapter_systems:
                        rows[system] = self._activity_row(system, "unavailable", adapter, "adapter_failed")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        ordered = [rows[system] for system in subject["systems"] if system in rows][:USER_ACTIVITY_MAX_ROWS]
        return {
            "name": subject["name"],
            "generated_at": int(time.time()),
            "privacy": {"client_endpoints": "hidden", "raw_logs": "excluded"},
            "systems": ordered,
            "limits": {
                "rows": USER_ACTIVITY_MAX_ROWS,
                "output_bytes_per_adapter": USER_ACTIVITY_MAX_OUTPUT,
                "total_timeout_seconds": USER_ACTIVITY_TOTAL_TIMEOUT,
            },
        }

    @staticmethod
    def _parse_awg_metrics(text: str) -> dict[str, int]:
        lines = [line.split("\t") for line in text.splitlines() if line.strip()]
        peers = lines[1:]
        now = int(time.time())
        return {
            "peers": len(peers),
            "recent_handshakes": sum(1 for item in peers if len(item) > 4 and item[4].isdigit() and now - int(item[4]) < 180),
            "rx": sum(int(item[5]) for item in peers if len(item) > 6 and item[5].isdigit()),
            "tx": sum(int(item[6]) for item in peers if len(item) > 6 and item[6].isdigit()),
        }

    def _health_summary(
        self,
        _params: dict,
        *,
        containers: dict[str, Any] | None = None,
        certificates: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        diagnostics = []
        services = {}
        try:
            control = self._control()
            preferences = (
                control.effective_service_preferences()
                if hasattr(control, "effective_service_preferences")
                else control.service_preferences()
            )
        except Exception:
            preferences = {}
        container_states = {
            item.get("service"): item
            for item in (containers or {}).get("containers", [])
            if isinstance(item, dict) and isinstance(item.get("service"), str)
        }
        for service in sorted(SERVICES):
            if service in DOCKER_SERVICES and service in container_states:
                status = {"active": str(container_states[service].get("state", "")).lower() == "running"}
            else:
                try:
                    status = self._service_status_snapshot(service)
                except ProtocolError:
                    status = {"active": False}
            enabled = preferences.get(service, True)
            services[service] = {"active": status["active"], "enabled": enabled}
            if enabled and not status["active"]:
                command = (
                    "systemctl status kvn-amneziawg.service"
                    if service == "amneziawg"
                    else "systemctl status kvn-wireguard.service"
                    if service == "wireguard"
                    else "systemctl status kvn-portal-agent.service"
                    if service == "agent"
                    else f"docker compose ps {service}"
                )
                diagnostics.append({
                    "severity": "error",
                    "reason": f"Сервис {service} не запущен.",
                    "command": command,
                })
        certificate_rows = (
            certificates.get("certificates", [])
            if isinstance(certificates, dict)
            else self._control().certificate_status()["certificates"]
        )
        for certificate in certificate_rows:
            if certificate["san_mismatch"]:
                diagnostics.append({
                    "severity": "error",
                    "reason": f"SAN сертификата {certificate['target']} не соответствует настроенным доменам.",
                    "command": f"python3 tools/kvnctl.py letsencrypt status --target {certificate['target']}",
                })
        return {"services": services, "certificates": certificate_rows, "diagnostics": diagnostics}

    def _certificate_action(self, params: dict) -> dict[str, Any]:
        correlation_id = uuid.uuid4().hex
        action = params.get("action")
        target = params.get("target", "all")
        if action not in {"issue-configured", "renew", "reissue", "deploy"}:
            raise ProtocolError("policy_denied", "Операция сертификата не разрешена.")
        if target not in {"site", "ocserv", "all"}:
            raise ProtocolError("invalid_params", "Некорректный target сертификата.")
        cli_action = "issue-configured" if action == "renew" and target != "all" else action
        argv = ["python3", str(self.project_root / "tools" / "kvnctl.py"), "letsencrypt", cli_action]
        if cli_action != "renew":
            if action == "deploy" and target == "all":
                raise ProtocolError("invalid_params", "deploy требует target site или ocserv.")
            argv.extend(["--target", target])
        result = self.runner.run(argv, timeout=600, max_output=64 * 1024)
        reloads = []
        if result.returncode == 0:
            affected = ["nginx"] if target == "site" else ["ocserv"] if target == "ocserv" else ["nginx", "ocserv"]
            for service in affected:
                reloads.append(self._service_action({"service": service, "action": "reload"}))
            if target in {"site", "all"} and getattr(self._control(), "portal_custom_gateway", lambda: False)():
                checked = self.runner.run(
                    [*self.compose, "exec", "-T", "portal-gateway", "nginx", "-t"], timeout=30
                )
                reloaded = checked
                if checked.returncode == 0:
                    reloaded = self.runner.run(
                        [*self.compose, "exec", "-T", "portal-gateway", "nginx", "-s", "reload"],
                        timeout=30,
                    )
                reloads.append({
                    "service": "portal-gateway",
                    "ok": reloaded.returncode == 0,
                    "command": reloaded.to_dict(),
                })
        return {
            "ok": result.returncode == 0 and all(item["ok"] for item in reloads),
            "action": action,
            "target": target,
            "command": result.to_dict(),
            "reloads": reloads,
            "correlation_id": correlation_id,
        }

    def _inspect_project_update_archive(self, archive_value: Any) -> tuple[Path, dict[str, Any]]:
        """Проверяет путь и содержимое update-архива без запуска привилегированных команд."""
        if not isinstance(archive_value, str) or not archive_value:
            raise ProtocolError("invalid_params", "Архив обновления не задан.")
        archive_relative = Path(archive_value)
        if archive_relative.is_absolute():
            raise ProtocolError("policy_denied", "Абсолютный путь архива запрещён.")
        archive_candidate = self.project_root / archive_relative
        if archive_candidate.is_symlink():
            raise ProtocolError("policy_denied", "Символическая ссылка вместо архива запрещена.")
        archive_path = archive_candidate.resolve()
        allowed_root_archives = {
            (self.project_root / "kvn-vpn-deploy.tar.gz").resolve(),
            (self.project_root / "kvn-vpn-release-linux-amd64.tar.gz").resolve(),
        }
        uploads_root = (self.project_root / "portal-data" / "updates").resolve()
        if archive_path not in allowed_root_archives and not archive_path.is_relative_to(uploads_root):
            raise ProtocolError("policy_denied", "Архив должен лежать в корне проекта или portal-data/updates.")
        archive_name = archive_candidate.name
        try:
            kind = artifact_kind(archive_name)
        except ValueError as exc:
            raise ProtocolError("invalid_params", "Неизвестное имя deploy/release архива.") from exc
        if archive_candidate.suffixes[-2:] != [".tar", ".gz"]:
            raise ProtocolError("invalid_params", "Разрешён только архив .tar.gz.")
        try:
            inspection = inspect_update_artifact(archive_path, kind)
            metadata = inspection["metadata"]
            release_manifest = inspection["manifest"]
            required_free = int(inspection["required_free_bytes"])
            if not inspection["has_required_space"]:
                raise ProtocolError("insufficient_disk", f"Для release требуется {required_free} bytes свободного места.")
        except (ArchiveValidationError, ReleaseValidationError) as exc:
            if "не найден" in str(exc):
                raise ProtocolError("not_found", "Архив обновления не найден.") from exc
            detail = sanitize_text(str(exc), max_chars=2048)
            raise ProtocolError("invalid_archive", f"Архив обновления отклонён: {detail}") from exc
        except OSError as exc:
            raise ProtocolError("not_found", "Архив обновления не найден.") from exc
        return archive_path, {
            "archive": archive_path.relative_to(self.project_root).as_posix(),
            "archive_name": str(metadata["name"]),
            "archive_size": int(metadata["size"]),
            "archive_sha256": str(metadata["sha256"]),
            "archive_members": int(metadata["member_count"]),
            "archive_kind": kind,
            "release_source": release_manifest.get("source", {}) if release_manifest else {},
            "release_images": release_manifest.get("images", {}) if release_manifest else {},
            "required_free_bytes": required_free,
        }

    def _project_update_inspect(self, params: dict) -> dict[str, Any]:
        if set(params) != {"archive"}:
            raise ProtocolError("invalid_params", "Проверка обновления принимает только путь архива.")
        _archive_path, metadata = self._inspect_project_update_archive(params.get("archive"))
        return {"ok": True, **metadata}

    def _github_update_state(self) -> dict[str, Any]:
        return self._control().kvnctl.STATE_STORE.load()

    def _project_release_settings(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Настройки GitHub Release не принимают параметры.")
        try:
            return self.github_source.settings(self._github_update_state())
        except GitHubUpdateError as exc:
            raise ProtocolError(exc.code, sanitize_text(str(exc), max_chars=2048)) from exc

    def _project_release_check(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Проверка GitHub Release не принимает параметры.")
        try:
            return self.github_source.check(self._github_update_state())
        except GitHubUpdateError as exc:
            raise ProtocolError(exc.code, sanitize_text(str(exc), max_chars=2048)) from exc

    def _project_release_prepare(self, params: dict) -> dict[str, Any]:
        if (
            set(params) != {"release_id", "asset_id", "asset_sha256"}
            or not isinstance(params.get("release_id"), int)
            or params["release_id"] <= 0
            or not isinstance(params.get("asset_id"), int)
            or params["asset_id"] <= 0
            or not isinstance(params.get("asset_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", params["asset_sha256"]) is None
        ):
            raise ProtocolError(
                "invalid_params",
                "Подготовка GitHub Release принимает только release_id, asset_id и SHA-256.",
            )
        try:
            prepared = self.github_source.prepare(self._github_update_state(), params)
            archive_path = Path(prepared["path"]).resolve()
            relative = archive_path.relative_to(self.project_root).as_posix()
            inspected_path, metadata = self._inspect_project_update_archive(relative)
            release_asset = prepared["release"]["asset"]
            if (
                inspected_path != archive_path
                or metadata["archive_sha256"] != release_asset["sha256"]
                or metadata["archive_size"] != release_asset["size"]
            ):
                archive_path.unlink(missing_ok=True)
                raise GitHubUpdateError(
                    "archive_changed",
                    "Подготовленный архив не совпадает с проверенным GitHub asset.",
                )
            return {
                "ok": True,
                "ready": True,
                "reused": bool(prepared["reused"]),
                "repository": prepared["release"]["repository"],
                "channel": prepared["release"]["channel"],
                "tag": prepared["release"]["tag"],
                "release_id": prepared["release"]["release_id"],
                "asset_id": release_asset["id"],
                "validation": prepared["validation"],
                "partials_removed": int(prepared["partials_removed"]),
                **metadata,
            }
        except (GitHubUpdateError, ValueError) as exc:
            code = getattr(exc, "code", "policy_denied")
            raise ProtocolError(code, sanitize_text(str(exc), max_chars=2048)) from exc

    def _project_update(self, params: dict) -> dict[str, Any]:
        required = {"archive", "root_password", "session_owner"}
        if not required.issubset(params) or set(params) - required - {"mode", "expected_sha256"}:
            raise ProtocolError("invalid_params", "Для обновления нужны архив, режим и подтверждение root-паролем.")
        mode = params.get("mode", "full")
        if mode not in {"full", "bootstrap-only"}:
            raise ProtocolError("invalid_params", "Неизвестный режим обновления.")
        correlation_id = uuid.uuid4().hex
        owner = self._shell_owner(params)
        self._shell_auth_allowed(owner)
        if not self._verify_root_password(params.get("root_password", "")):
            self._record_shell_auth_failure(owner)
            raise ProtocolError("root_password_denied", "Пароль root указан неверно.")
        self._clear_shell_auth_failures(owner)

        archive_path, metadata = self._inspect_project_update_archive(params.get("archive"))
        expected_sha256 = params.get("expected_sha256")
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
                raise ProtocolError("invalid_params", "Ожидаемый SHA-256 архива задан неверно.")
            if not hmac.compare_digest(metadata["archive_sha256"], expected_sha256.lower()):
                raise ProtocolError("archive_changed", "Архив изменился после предварительной проверки.")
        is_release = metadata["archive_kind"] == "release"
        unit = f"kvn-project-update-{correlation_id[:12]}"
        update_script = r"""
project_root="$1"
archive="$2"
kind="$3"
mode="$4"
work="$(mktemp -d /tmp/kvn-project-update.XXXXXXXXXX)"
marker="${archive}.running"
cleanup() {
    rm -f "$marker"
    rm -rf "$work"
}
trap cleanup EXIT
umask 077
: > "$marker"
if [ "$kind" = "release" ]; then
    if [ "$mode" = "bootstrap-only" ]; then
        exec /bin/bash "$project_root/update.sh" --bootstrap-only "$archive"
    fi
    exec /bin/bash "$project_root/update.sh" "$archive"
fi
tar --extract --gzip --file "$archive" --directory "$work" --no-same-owner --no-same-permissions \
    deploy/update.sh deploy/tools/deploy_archive.py deploy/tools/canonical-files.txt
chmod 700 "$work/deploy/update.sh" "$work/deploy/tools/deploy_archive.py"
KVN_UPDATE_WORKER=1 KVN_UPDATE_ROOT="$project_root" KVN_UPDATE_WORKER_DIR="$work" \
    KVN_UPDATE_INSPECTOR="$work/deploy/tools/deploy_archive.py" KVN_UPDATE_MODE="$mode" \
    exec /bin/bash "$work/deploy/update.sh" "$archive"
"""
        result = self.runner.run(
            [
                "systemd-run",
                "--collect",
                f"--unit={unit}",
                f"--property=WorkingDirectory={self.project_root}",
                "/bin/bash",
                "-ceu",
                update_script,
                "--",
                str(self.project_root),
                str(archive_path),
                "release" if is_release else "deploy",
                mode,
            ],
            timeout=30,
            max_output=32 * 1024,
        )
        return {
            "ok": result.returncode == 0,
            "action": "update",
            "mode": mode,
            **metadata,
            "unit": unit,
            "journal_command": f"journalctl -u {unit} -n 200 --no-pager",
            "recovery_command": (
                f"sudo ./update.sh --bootstrap-only {archive_path.relative_to(self.project_root).as_posix()}"
                if mode == "full"
                else f"sudo ./update.sh {archive_path.relative_to(self.project_root).as_posix()}"
            ),
            "command": result.to_dict(),
            "correlation_id": correlation_id,
        }

    def _not_implemented(self, _params: dict) -> dict[str, Any]:
        raise ProtocolError("capability_unavailable", "Метод будет активирован после подключения транзакционного adapter.")

    def _state_apply(self, params: dict) -> dict[str, Any]:
        try:
            return self._control().apply_user(params)
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _state_reconcile(self, params: dict) -> dict[str, Any]:
        if params:
            raise ProtocolError("invalid_params", "Reconcile не принимает параметры.")
        try:
            return self._control().reconcile_state()
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc

    def _portal_credentials(self, params: dict) -> dict[str, Any]:
        try:
            return self._control().update_portal_credentials(params)
        except Exception as exc:
            code = getattr(exc, "code", "apply_failed")
            raise ProtocolError(code, str(exc)) from exc
