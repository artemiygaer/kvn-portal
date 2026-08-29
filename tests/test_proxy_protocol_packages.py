"""Контракты registry и автономных proxy protocol packages."""

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.test_baseline_contracts import fixture_state, fixture_user
from tools import kvnctl
from tools.kvnlib.protocols import hysteria, mtproto, registry, sni, xray

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = ROOT / "tools" / "kvnlib" / "protocols"
CONTRACT = json.loads((ROOT / "tests/fixtures/v3_contracts/contracts.json").read_text(encoding="utf-8"))

class RegistryTests(unittest.TestCase):
    def test_each_supported_system_occurs_exactly_once(self):
        expected = {"tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg", "amneziawg", "wireguard", "ocserv"}
        self.assertEqual(set(registry.SYSTEMS), expected)
        self.assertEqual(len(registry.SYSTEMS), len(set(registry.SYSTEMS)))
        self.assertEqual(kvnctl.ALL_SYSTEMS, list(registry.SYSTEMS))

    def test_capabilities_are_complete(self):
        for item in registry.SYSTEM_CAPABILITIES:
            self.assertTrue(item.label)
            self.assertIn(item.sni_scope, {"per_user", "service", "not_applicable"})
            self.assertTrue(item.runtime)

class ProxyImportBoundaryTests(unittest.TestCase):
    def test_proxy_packages_have_no_runtime_adapter_imports(self):
        forbidden = {"subprocess", "docker", "systemd", "flask", "argparse"}
        violations = []
        for path in sorted(PROTOCOLS.rglob("*.py")):
            if any(part in {"amneziawg", "wireguard", "ocserv"} for part in path.parts):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                for name in names:
                    if name.lstrip(".").split(".")[0] in forbidden:
                        violations.append(f"{path}:{node.lineno}:{name}")
        self.assertEqual(violations, [])

    def test_host_packages_do_not_import_proxy_implementations(self):
        forbidden = {"xray", "hysteria", "mtproto", "sni"}
        for package in ("amneziawg", "wireguard", "ocserv"):
            text = (PROTOCOLS / package / "__init__.py").read_text(encoding="utf-8")
            self.assertFalse(any(f".{name}" in text for name in forbidden))

class ProxyGoldenTests(unittest.TestCase):
    def test_xray_and_mtproto_golden_outputs_are_unchanged(self):
        state = fixture_state()
        state["users"] = [fixture_user()]
        actual = {
            "xray_server": xray.render_config(kvnctl.default_xray_config(state)).rstrip("\n"),
            "telemt_server": kvnctl.telemt_config_text(state),
            "mtg_server": kvnctl.mtg_config_text(state),
        }
        # Xray golden хранит canonical JSON, поэтому сравниваем семантический JSON.
        xray_canonical = json.dumps(json.loads(actual["xray_server"]), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(hashlib.sha256(xray_canonical.encode()).hexdigest(), CONTRACT["golden_outputs"]["xray_server"]["sha256"])
        for name in ("telemt_server", "mtg_server"):
            self.assertEqual(hashlib.sha256(actual[name].encode()).hexdigest(), CONTRACT["golden_outputs"][name]["sha256"])

    def test_new_mtproto_renderers_equal_legacy_functions(self):
        state = fixture_state()
        state["users"] = [fixture_user()]
        self.assertEqual(kvnctl.telemt_config_text(copy.deepcopy(state)), kvnctl._legacy_telemt_config_text(copy.deepcopy(state)))
        self.assertEqual(kvnctl.mtg_config_text(copy.deepcopy(state)), kvnctl._legacy_mtg_config_text(copy.deepcopy(state)))

    def test_hysteria_renderer_matches_runtime_file(self):
        state = fixture_state()
        state["users"] = [fixture_user()]
        users = [(state["users"][0]["name"], state["users"][0]["hysteria_password"])]
        expected = hysteria.render_server(users=users)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.yaml"
            original = kvnctl.HY2_CONFIG
            try:
                kvnctl.HY2_CONFIG = path
                kvnctl.render_hysteria(state)
                self.assertEqual(path.read_text(encoding="utf-8"), expected)
            finally:
                kvnctl.HY2_CONFIG = original

class SniPackageTests(unittest.TestCase):
    def test_collision_and_reality_alias_behavior(self):
        routes = {"a.example": [("tls", "xray:443"), ("mtg", "mtg:3128")], "b.example": [("x", "same"), ("y", "same")]}
        self.assertEqual(set(sni.route_collisions(routes)), {"a.example"})
        self.assertTrue(sni.reality_alias_allowed("github.com", ["www.github.com"], "www.github.com"))
        self.assertFalse(sni.reality_alias_allowed("github.com", [], "blocked.example"))

    def test_existing_sni_validator_still_rejects_collision(self):
        state = fixture_state()
        state["sni_routes"]["telemt"]["dest"] = "telemt:3129"
        state["sni_routes"]["mtg"]["dest"] = "mtg:3128"
        state["sni_routes"]["mtg"]["default"] = state["sni_routes"]["telemt"]["default"]
        state["sni_routes"]["mtg"]["aliases"] = [state["sni_routes"]["telemt"]["default"]]
        with self.assertRaises(SystemExit):
            kvnctl.validate_sni_uniqueness(state)

if __name__ == "__main__":
    unittest.main()
