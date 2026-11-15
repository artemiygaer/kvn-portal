"""Изолированная root-консоль: по умолчанию нет активной службы."""

from pathlib import Path

AGENT_SOCKET = Path("/run/kvn-v5-console-agent.sock")
WEB_SOCKET = Path("/run/kvn-v5-console-web.sock")
SOCKET_UNIT = "kvn-v5-console-agent.socket"
AGENT_UNIT = "kvn-v5-console-agent.service"
WEB_SOCKET_UNIT = "kvn-v5-console-web.socket"
WEB_UNIT = "kvn-v5-console-web.service"
