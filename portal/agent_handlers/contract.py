"""Неизменяемый контракт одного привилегированного RPC-обработчика."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


Handler = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class HandlerSpec:
    callback: Handler
    mutates: bool
    allowed_params: frozenset[str]
