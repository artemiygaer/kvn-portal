"""Read-only application service диагностики."""

from dataclasses import dataclass
from .shared import ControlDependencies

@dataclass(slots=True)
class DiagnosticsService:
    dependencies: ControlDependencies
    def topology(self) -> dict:
        return self.dependencies.control.network_topology()
    def domains(self, params: dict) -> dict:
        return self.dependencies.control.domain_advice(params)
    def sni(self, params: dict) -> dict:
        return self.dependencies.control.sni_diagnose(params)

__all__ = ["DiagnosticsService"]
