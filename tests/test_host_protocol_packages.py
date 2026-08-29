"""Контракты автономных пакетов host-протоколов."""

import ast
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

from tests.test_baseline_contracts import fixture_state, fixture_user
from tools import kvnctl
from tools.kvnlib.protocols import amneziawg, ocserv, wireguard


ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = ROOT / "tools" / "kvnlib" / "protocols"
CONTRACT = json.loads((ROOT / "tests/fixtures/v3_contracts/contracts.json").read_text(encoding="utf-8"))


class ProtocolPackageBoundaryTests(unittest.TestCase):
    def test_packages_do_not_import_flask_or_argparse(self):
        violations = []
        for path in sorted(PROTOCOLS.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if name.lstrip(".").split(".")[0] in {"argparse", "flask"}:
                        violations.append(f"{path}:{node.lineno}:{name}")
        self.assertEqual(violations, [])

    def test_public_apis_are_explicit(self):
        self.assertIn("render_client", amneziawg.__all__)
        self.assertIn("safe_profile_summary", amneziawg.__all__)
        self.assertIn("render_client", wireguard.__all__)
        self.assertIn("certificate_domains", ocserv.__all__)


class AmneziawgPackageTests(unittest.TestCase):
    def state(self, profile="legacy"):
        state = fixture_state()
        state["amneziawg"]["obfuscation"] = {
            "Jc": 5, "Jmin": 64, "Jmax": 1024, "S1": 32, "S2": 48,
            "H1": 1000000001, "H2": 1000000002, "H3": 1000000003,
            "H4": 1000000004,
            "I1": "<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>",
        }
        state["amneziawg"]["protocol_version"] = profile
        if profile == "3.1":
            state["amneziawg"]["obfuscation"].update(S3=64, S4=96)
            state["amneziawg"]["v3"] = {
                **kvnctl.AWG31_DEFAULTS,
                "header_protection_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            }
        return state

    def test_legacy_export_keeps_v3_golden_hash(self):
        state, user = self.state(), fixture_user()
        actual = kvnctl.amneziawg_client_conf(state, user)
        golden = CONTRACT["golden_outputs"]["awg_client"]
        self.assertEqual(len(actual.encode()), golden["bytes"])
        self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), golden["sha256"])

    def test_profile_31_is_rendered_but_secret_is_not_in_summary(self):
        state, user = self.state("3.1"), fixture_user()
        rendered = kvnctl.amneziawg_client_conf(state, user)
        secret = state["amneziawg"]["v3"]["header_protection_key"]
        self.assertIn(f"HeaderProtectionKey = {secret}", rendered)
        self.assertNotIn(secret, json.dumps(amneziawg.safe_profile_summary(state["amneziawg"])))

    def test_runtime_dump_parser_is_stable(self):
        dump = "private\tpublic\t51820\toff\npeer-key\tpsk\tendpoint\t10.66.66.2/32\t0\t0\t0\t0\n"
        self.assertEqual(amneziawg.parse_runtime_dump(dump), {"peer-key": "10.66.66.2/32"})


class WireguardPackageTests(unittest.TestCase):
    def test_wireguard_export_keeps_golden_and_separate_endpoint(self):
        state, user = fixture_state(), fixture_user()
        actual = kvnctl.wireguard_client_conf(state, user)
        golden = CONTRACT["golden_outputs"]["wg_client"]
        self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), golden["sha256"])
        self.assertIn(":51821", actual)
        self.assertNotIn(":51820", actual)
        self.assertNotEqual(state["wireguard"]["interface"], state["amneziawg"]["interface"])

    def test_equal_awg_port_or_interface_is_rejected(self):
        awg = {"port": 51820, "interface": "awg0"}
        for config in ({"port": 51820, "interface": "wg0"}, {"port": 51821, "interface": "awg0"}):
            with self.assertRaises(ValueError):
                wireguard.validate_config(config, amneziawg=awg)


class OcservPackageTests(unittest.TestCase):
    def test_server_config_keeps_v3_golden_hash(self):
        state = fixture_state()
        actual = kvnctl.ocserv_conf_text(state)
        golden = CONTRACT["golden_outputs"]["ocserv_server"]
        self.assertEqual(hashlib.sha256(actual.encode()).hexdigest(), golden["sha256"])

    def test_cert_domains_and_user_file_contract(self):
        config = {"sni_enabled": True, "sni": "vpn.example.com", "front_snis": ["alt.example.com", "vpn.example.com"]}
        self.assertEqual(ocserv.certificate_domains(config), ["vpn.example.com", "alt.example.com"])
        self.assertEqual(ocserv.render_users([("alice", "secret")]).splitlines()[-1], "alice:secret")


if __name__ == "__main__":
    unittest.main()
