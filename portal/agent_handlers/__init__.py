"""Allowlisted обработчики привилегированного host-agent."""

from .contract import HandlerSpec
from .dispatcher import (
    AgentDispatcher,
    CommandResult,
    CommandRunner,
    DashboardSnapshotCache,
    MaintenanceCommand,
    RootShellSession,
)
from .registry import build_handler_registry

__all__ = [
    "AgentDispatcher",
    "CommandResult",
    "CommandRunner",
    "DashboardSnapshotCache",
    "HandlerSpec",
    "MaintenanceCommand",
    "RootShellSession",
    "build_handler_registry",
]
