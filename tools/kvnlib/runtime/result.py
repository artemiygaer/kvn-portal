"""Единый JSON-контракт результата применения runtime."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RESULT_SCHEMA_VERSION = 1

@dataclass(frozen=True, slots=True)
class ApplyResult:
    outcome: str = "applied"
    hot_updated: tuple[str, ...] = ()
    reloaded: tuple[str, ...] = ()
    restarted: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    fallbacks: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    reconcile_required: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def applied(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.hot_updated + self.reloaded + self.restarted)))

    def to_dict(self) -> dict[str, Any]:
        """Стабильная схема с legacy-полями для CLI/control/agent."""
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "outcome": self.outcome,
            "applied": list(self.applied),
            "hot_updated": list(self.hot_updated),
            "reloaded": list(self.reloaded),
            "restarted": list(self.restarted),
            "skipped": list(self.skipped),
            "skipped_disabled": list(self.skipped),
            "failed": list(self.failed),
            "fallbacks": list(self.fallbacks),
            "warnings": list(self.warnings),
            "reconcile_required": self.reconcile_required,
            "details": self.details,
        }

    @classmethod
    def from_report(cls, report: dict[str, Any]) -> "ApplyResult":
        def names(key: str) -> tuple[str, ...]:
            value = report.get(key, [])
            return tuple(sorted({str(item) for item in value})) if isinstance(value, list) else ()
        return cls(
            outcome=str(report.get("outcome", "failed")),
            hot_updated=names("hot_updated"),
            reloaded=names("reloaded"),
            restarted=names("restarted"),
            skipped=names("skipped_disabled") or names("skipped"),
            failed=names("failed"),
            fallbacks=tuple(str(item) for item in report.get("fallbacks", []) if isinstance(item, str)),
            warnings=tuple(str(item) for item in report.get("warnings", []) if isinstance(item, str)),
            reconcile_required=bool(report.get("reconcile_required")),
            details=dict(report.get("details", {})) if isinstance(report.get("details", {}), dict) else {},
        )

def normalize_apply_report(report: dict[str, Any]) -> dict[str, Any]:
    return ApplyResult.from_report(report).to_dict()

__all__ = ["ApplyResult", "RESULT_SCHEMA_VERSION", "normalize_apply_report"]
