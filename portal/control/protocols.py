"""Application service протоколов и SNI."""

from dataclasses import dataclass
from .shared import ControlDependencies

@dataclass(slots=True)
class ProtocolsService:
    dependencies: ControlDependencies
    def apply(self, params: dict) -> dict:
        return self.dependencies.control.apply_protocol(params)
    def apply_sni(self, params: dict) -> dict:
        return self.dependencies.control.apply_sni_route(params)
    def apply_mtproto(self, params: dict) -> dict:
        return self.dependencies.control.apply_mtproto(params)
    def apply_amneziawg(self, params: dict) -> dict:
        return self.dependencies.control.apply_amneziawg(params)

__all__ = ["ProtocolsService"]
