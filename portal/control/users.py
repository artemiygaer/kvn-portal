"""Application service пользователей."""

from dataclasses import dataclass
from .shared import ControlDependencies

@dataclass(slots=True)
class UsersService:
    dependencies: ControlDependencies
    def list(self) -> dict:
        return self.dependencies.control.list_users()
    def get(self, name: str) -> dict:
        return self.dependencies.control.get_user(name)
    def apply(self, params: dict) -> dict:
        return self.dependencies.control.apply_user(params)

__all__ = ["UsersService"]
