"""Application service update orchestration с явным adapter dependency."""

from collections.abc import Callable
from dataclasses import dataclass

@dataclass(slots=True)
class UpdatesService:
    check: Callable[[], dict]
    stage: Callable[[dict], dict]
    def status(self) -> dict:
        return self.check()
    def prepare(self, request: dict) -> dict:
        return self.stage(request)

__all__ = ["UpdatesService"]
