"""Application service export policy и пользовательских bundles."""

from dataclasses import dataclass
from .shared import ControlDependencies

@dataclass(slots=True)
class ExportsService:
    dependencies: ControlDependencies
    def settings(self) -> dict:
        return self.dependencies.control.client_export_settings()
    def update(self, params: dict) -> dict:
        return self.dependencies.control.update_client_export(params)
    def user_bundle(self, name: str, address_mode: str) -> dict:
        return self.dependencies.control.user_export(name, address_mode)

__all__ = ["ExportsService"]
