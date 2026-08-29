"""Изолированные command adapters; только runtime слой запускает subprocess."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Protocol, Sequence

@dataclass(frozen=True, slots=True)
class CommandResult:
    code: int
    stdout: str = ""
    stderr: str = ""

class CommandRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...

class SubprocessRunner:
    """Production adapter без shell=True и без вывода аргументов в ошибки."""
    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        completed = subprocess.run(list(argv), capture_output=True, text=True, check=False, timeout=timeout)
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)

__all__ = ["CommandResult", "CommandRunner", "SubprocessRunner"]
