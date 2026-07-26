"""Клиент локального RPC host-agent."""

from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path

try:
    from .agent_protocol import MAX_RESPONSE_BYTES, PROTOCOL_VERSION
except ImportError:
    from agent_protocol import MAX_RESPONSE_BYTES, PROTOCOL_VERSION


class AgentClientError(RuntimeError):
    pass


class AgentClient:
    def __init__(self, socket_path: Path, secret: str, timeout: float = 10.0):
        self.socket_path = Path(socket_path)
        self.secret = secret
        self.timeout = timeout

    def call(self, method: str, params: dict | None = None, *, timeout: float | None = None) -> dict:
        request_id = uuid.uuid4().hex
        payload = {
            "version": PROTOCOL_VERSION,
            "id": request_id,
            "secret": self.secret,
            "method": method,
            "params": params or {},
        }
        encoded = (json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            if not hasattr(socket, "AF_UNIX"):
                raise AgentClientError("Host-agent недоступен: Unix-сокеты не поддерживаются в этой среде.")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout if timeout is None else timeout)
                client.connect(str(self.socket_path))
                client.sendall(encoded)
                response = bytearray()
                while not response.endswith(b"\n"):
                    chunk = client.recv(min(65536, MAX_RESPONSE_BYTES + 1 - len(response)))
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > MAX_RESPONSE_BYTES:
                        raise AgentClientError("Ответ host-agent превышает допустимый размер.")
        except AgentClientError:
            raise
        except OSError as exc:
            raise AgentClientError("Host-agent недоступен: ошибка Unix-сокета.") from exc
        try:
            decoded = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AgentClientError("Host-agent вернул некорректный ответ.") from exc
        if decoded.get("id") != request_id:
            raise AgentClientError("Идентификатор ответа host-agent не совпадает с запросом.")
        if not decoded.get("ok"):
            error = decoded.get("error", {})
            raise AgentClientError(f"{error.get('code', 'agent_error')}: {error.get('message', 'ошибка')}")
        return decoded.get("data", {})
