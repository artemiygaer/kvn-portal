"""Единственная граница доступа web-приложения к host-agent."""

from __future__ import annotations

from pathlib import Path

try:
    from portal.agent_client import AgentClient, AgentClientError
except ModuleNotFoundError:
    from agent_client import AgentClient, AgentClientError


class AgentFacade:
    """Лениво создаёт RPC-клиент и не допускает прямых host-операций."""

    def __init__(self, app) -> None:
        self.app = app

    def client(self):
        configured = self.app.config.get("AGENT_CLIENT")
        if configured is not None:
            return configured
        cached = self.app.extensions.get("kvn_agent_client")
        if cached is not None:
            return cached
        try:
            secret = Path(self.app.config["AGENT_SECRET_FILE"]).read_text(
                encoding="utf-8"
            ).strip()
        except OSError as exc:
            raise AgentClientError(
                "Host-agent недоступен: секрет RPC не читается."
            ) from exc
        cached = AgentClient(Path(self.app.config["AGENT_SOCKET"]), secret)
        self.app.extensions["kvn_agent_client"] = cached
        return cached
