"""Пути source of truth и его производных без глобального состояния."""

from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class ProjectPaths:
    """Явные пути проекта, пригодные для CLI, портала и тестов."""
    root: Path
    users: Path
    lock: Path
    portal_runtime: Path

    @classmethod
    def from_root(cls, root: Path | str) -> "ProjectPaths":
        resolved = Path(root).resolve()
        return cls(resolved, resolved / "users.json", resolved / ".kvnctl.lock", resolved / "portal-runtime" / "users.json")
