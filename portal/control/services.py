"""Application service lifecycle и настроек portal runtime."""

from dataclasses import dataclass
from .shared import ControlDependencies

@dataclass(slots=True)
class ServicesService:
    dependencies: ControlDependencies
    def preferences(self) -> dict:
        return self.dependencies.control.service_preferences()
    def set_enabled(self, service: str, enabled: bool) -> dict:
        return self.dependencies.control.set_service_enabled(service, enabled)
    def apply_host(self, service: str) -> dict:
        return self.dependencies.control.apply_host_service(service)
    def reconcile(self) -> dict:
        return self.dependencies.control.reconcile_state()

__all__ = ["ServicesService"]
