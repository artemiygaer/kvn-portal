"""Планы, result contract и privileged runtime adapters."""

from .plan import ApplyAction, ChangeSet, RenderResult, SERVICE_CAPABILITIES, ServiceChange, build_change_set, merge_service_change
from .result import ApplyResult, RESULT_SCHEMA_VERSION, normalize_apply_report
from .runner import CommandResult, CommandRunner, SubprocessRunner
from .verification import VerificationResult, host_tunnel_action

__all__ = [
    "ApplyAction", "ApplyResult", "ChangeSet", "CommandResult", "CommandRunner", "RESULT_SCHEMA_VERSION",
    "RenderResult", "SERVICE_CAPABILITIES", "ServiceChange", "SubprocessRunner", "VerificationResult",
    "build_change_set", "host_tunnel_action", "merge_service_change", "normalize_apply_report",
]
