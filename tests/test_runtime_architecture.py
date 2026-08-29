"""Apply/result/runtime contracts модульного монолита."""

import ast
import json
import unittest
from pathlib import Path

from tools.kvnlib.runtime import ApplyAction, ApplyResult, host_tunnel_action, normalize_apply_report

ROOT = Path(__file__).resolve().parents[1]

class RuntimeBoundaryTests(unittest.TestCase):
    def test_only_runtime_package_imports_subprocess(self):
        violations = []
        roots = [ROOT / "tools/kvnlib/core", ROOT / "tools/kvnlib/protocols", ROOT / "tools/kvnlib/exports"]
        for package in roots:
            for path in package.rglob("*.py"):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for node in ast.walk(tree):
                    names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                    if any(name and name.lstrip(".").split(".")[0] == "subprocess" for name in names):
                        violations.append(f"{path}:{node.lineno}")
        self.assertEqual(violations, [])

class HostTunnelDecisionTests(unittest.TestCase):
    def test_peer_only_uses_syncconf_and_structural_delta_restarts(self):
        base = {"interface": "awg0", "port": 51820, "network": "10.66.66.0/24", "peers": {"a": "10.66.66.2/32"}}
        peer = {**base, "peers": {"a": "10.66.66.2/32", "b": "10.66.66.3/32"}}
        structural = {**base, "port": 51822}
        self.assertIs(host_tunnel_action(base, base), ApplyAction.NOOP)
        self.assertIs(host_tunnel_action(base, peer), ApplyAction.HOT_UPDATE)
        self.assertIs(host_tunnel_action(base, structural), ApplyAction.RESTART)

class ApplyResultContractTests(unittest.TestCase):
    def test_partial_failure_lists_applied_skipped_and_failed_services(self):
        report = normalize_apply_report({
            "outcome": "failed", "hot_updated": ["telemt"], "reloaded": ["nginx"],
            "restarted": [], "skipped_disabled": ["mtg"], "failed": ["xray"],
            "fallbacks": [], "warnings": ["runtime failure"], "reconcile_required": True,
            "details": {"xray": {"reason": "probe_failed"}},
        })
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["applied"], ["nginx", "telemt"])
        self.assertEqual(report["skipped"], ["mtg"])
        self.assertEqual(report["failed"], ["xray"])
        self.assertTrue(report["reconcile_required"])
        json.dumps(report, ensure_ascii=False)

    def test_result_schema_is_stable_and_secret_free(self):
        result = ApplyResult(outcome="applied", restarted=("xray",)).to_dict()
        self.assertEqual(
            tuple(result),
            ("schema_version", "outcome", "applied", "hot_updated", "reloaded", "restarted", "skipped", "skipped_disabled", "failed", "fallbacks", "warnings", "reconcile_required", "details"),
        )
        self.assertNotIn("password", json.dumps(result).lower())

if __name__ == "__main__":
    unittest.main()
