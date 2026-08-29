"""Чистые решения apply для host tunnels и типизированная verification."""

from dataclasses import dataclass

from .plan import ApplyAction

HOST_STRUCTURAL_FIELDS = ("interface", "network", "server_address", "port", "mtu", "protocol_version", "obfuscation", "v3")

def host_tunnel_action(before: dict, after: dict) -> ApplyAction:
    """Peer-only delta использует syncconf, structural delta — restart."""
    if before == after:
        return ApplyAction.NOOP
    if any(before.get(key) != after.get(key) for key in HOST_STRUCTURAL_FIELDS):
        return ApplyAction.RESTART
    return ApplyAction.HOT_UPDATE

@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    reason: str
    expected_peers: int = 0
    runtime_peers: int = 0

    def to_dict(self) -> dict:
        return {"ok": self.ok, "reason": self.reason, "expected_peers": self.expected_peers, "runtime_peers": self.runtime_peers}

__all__ = ["HOST_STRUCTURAL_FIELDS", "VerificationResult", "host_tunnel_action"]
