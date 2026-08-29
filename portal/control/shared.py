"""Явные dependencies и типы application services портала."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

class ControlPort(Protocol):
    """Минимальный порт, внедряемый в bounded services."""
    def list_users(self) -> dict: ...
    def apply_user(self, params: dict) -> dict: ...
    def apply_protocol(self, params: dict) -> dict: ...
    def service_preferences(self) -> dict: ...
    def user_export(self, name: str, address_mode: str) -> dict: ...
    def network_topology(self) -> dict: ...

@dataclass(frozen=True, slots=True)
class ControlDependencies:
    project_root: Path
    control: ControlPort

    @classmethod
    def create(cls, project_root: Path, control: ControlPort) -> "ControlDependencies":
        return cls(Path(project_root).resolve(), control)

@dataclass(frozen=True, slots=True)
class ServiceResult:
    revision: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"revision": self.revision, **self.payload}

__all__ = ["ControlDependencies", "ControlPort", "ServiceResult"]
