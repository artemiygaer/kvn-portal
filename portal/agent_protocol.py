"""Версионированный RPC-контракт локального host-agent."""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
MAX_REQUEST_ID_LENGTH = 64

READ_ONLY_METHODS = {
    "ping",
    "service.status",
    "logs.tail",
    "stats.containers",
    "dashboard.snapshot",
    "health.host",
    "amneziawg.status",
    "state.users",
    "state.user",
    "user.activity",
    "network.topology",
    "domain.advice",
    "sni.routes",
    "sni.diagnose",
    "mtproto.status",
    "mtproto.diagnose",
    "user.file",
    "user.export",
    "client.export.settings",
    "protocol.stats",
    "certificates.status",
    "health.summary",
    "metrics.current",
    "metrics.history",
    "portal.performance",
    "backup.list",
    "project.update.inspect",
    "project.release.settings",
    "project.release.check",
    "maintenance.commands",
    "shell.read",
}
MUTATION_METHODS = {
    "service.action",
    "state.apply",
    "state.reconcile",
    "sni.apply",
    "mtproto.apply",
    "protocol.apply",
    "certificate.action",
    "portal.credentials",
    "portal.performance.update",
    "client.export.update",
    "project.release.prepare",
    "project.update",
    "project.backup",
    "maintenance.run",
    "shell.open",
    "shell.write",
    "shell.resize",
    "shell.close",
}
ALLOWED_METHODS = READ_ONLY_METHODS | MUTATION_METHODS

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_RE = re.compile(
    r"(?i)\b(password|private[_-]?key|preshared[_-]?key|token|secret|uuid)\b"
    r"(\s*[:=]\s*)([^\s,;]+)"
)


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str, request_id: str = ""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


@dataclass(frozen=True)
class RpcRequest:
    request_id: str
    method: str
    params: dict[str, Any]


def sanitize_text(value: str, max_chars: int = 128 * 1024) -> str:
    value = _ANSI_RE.sub("", value)
    value = _CONTROL_RE.sub("", value)
    value = _SECRET_RE.sub(lambda match: f"{match.group(1)}{match.group(2)}<скрыто>", value)
    if len(value) > max_chars:
        value = value[:max_chars] + "\n<вывод обрезан>"
    return value


def decode_request_line(line: bytes, expected_secret: str) -> RpcRequest:
    if len(line) > MAX_REQUEST_BYTES:
        raise ProtocolError("request_too_large", "Запрос превышает допустимый размер.")
    try:
        payload = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid_json", "Некорректный JSON-запрос.") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("invalid_request", "Запрос должен быть JSON-объектом.")
    request_id = payload.get("id", "")
    if not isinstance(request_id, str) or len(request_id) > MAX_REQUEST_ID_LENGTH:
        raise ProtocolError("invalid_request", "Некорректный идентификатор запроса.")
    if payload.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("invalid_version", "Неподдерживаемая версия протокола.", request_id)
    supplied_secret = payload.get("secret", "")
    if not isinstance(supplied_secret, str) or not hmac.compare_digest(supplied_secret, expected_secret):
        raise ProtocolError("unauthorized", "Доступ запрещён.", request_id)
    method = payload.get("method")
    params = payload.get("params", {})
    if not isinstance(method, str) or method not in ALLOWED_METHODS:
        raise ProtocolError("method_not_found", "Метод не разрешён.", request_id)
    if not isinstance(params, dict):
        raise ProtocolError("invalid_params", "Параметры должны быть JSON-объектом.", request_id)
    return RpcRequest(request_id, method, params)


def success_response(request_id: str, data: dict[str, Any]) -> bytes:
    payload = {"version": PROTOCOL_VERSION, "id": request_id, "ok": True, "data": data}
    return (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def error_response(error: ProtocolError) -> bytes:
    payload = {
        "version": PROTOCOL_VERSION,
        "id": error.request_id,
        "ok": False,
        "error": {"code": error.code, "message": sanitize_text(error.message, 2048)},
    }
    return (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
