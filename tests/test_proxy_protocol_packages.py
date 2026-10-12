"""Контракты registry и автономных proxy protocol packages."""

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
    def test_local_reality_target_does_not_loop_or_claim_ip_identity(self):
        self.assertEqual(xray.reality_target("web.example.test", ["web.example.test"]), "web.example.test:443")
        self.assertEqual(xray.reality_target("web.example.test", ["web.example.test"], "self-steal"), "nginx:8443")
        self.assertEqual(xray.reality_target("apple.com", ["web.example.test"]), "apple.com:443")
        for host in ("1.1.1.1", "2001:db8::1"):
            with self.assertRaises(ValueError): xray.reality_target(host, [host], "self-steal")

    def test_self_steal_routes_and_render_preserve_reality_keys(self):
        for system, destination in (("reality-tcp", "xray:2054"), ("reality-xhttp", "xray:2053")):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as temporary:
                state = fixture_state()
                state["users"] = [fixture_user()]
                state["sni_routes"][system] = {"default": state["server"], "aliases": [state["server"]], "dest": destination, "reality_mode":"self-steal"}
                state["ocserv"].update(enabled=True, sni=state["server"])
                kvnctl.validate_state_inputs(state)
                kvnctl.validate_sni_uniqueness(state)
                self.assertEqual(kvnctl.all_sni_aliases(state)[state["server"]], destination)
                config = kvnctl.default_xray_config(state)
                inbound = next(i for i in config["inbounds"] if i["port"] == (2054 if system == "reality-tcp" else 2053))
                settings = inbound["streamSettings"]["realitySettings"]
                settings.update(privateKey="fixture-key-preserved", shortIds=["0011223344556677"], dest="old.example.test:443", xver=2)
                path = Path(temporary)/"config.json"
                path.write_text(json.dumps(config))
                # State — источник ключей; если они ещё не нормализованы, старый config сохраняется.
                with mock.patch.object(kvnctl, "XRAY_CONFIG", path):
                    kvnctl.render_xray(state)
                actual = next(i for i in json.loads(path.read_text())["inbounds"] if i["port"] == inbound["port"])["streamSettings"]["realitySettings"]
                self.assertEqual(actual["target"], "nginx:8443")
                self.assertEqual(actual["xver"], 0)
                self.assertNotIn("dest", actual)
                self.assertEqual(actual["privateKey"], "fixture-key-preserved")
                self.assertEqual(actual["shortIds"], ["0011223344556677"])
                if system == "reality-xhttp": self.assertEqual(actual["serverNames"], [state["server"]])
                self.assertIn("http2 on;", kvnctl.decoy_server_block(state))

    def test_self_steal_does_not_allow_ambiguous_or_foreign_routes(self):
        for other in ("reality-xhttp", "telemt", "custom"):
            state = fixture_state()
            own = state["server"]
            state["sni_routes"]["reality-tcp"] = {"default": own, "aliases": [own], "dest":"xray:2054", "reality_mode":"self-steal"}
            if other == "custom": state["sni_routes"]["custom"] = [{"sni":own,"dest":"mtg:3128"}]
            else: state["sni_routes"][other].update(default=own,aliases=[own],dest="xray:2053" if other == "reality-xhttp" else "telemt:3129")
            with self.subTest(other=other), self.assertRaises(SystemExit): kvnctl.validate_sni_uniqueness(state)

    def test_external_reality_render_preserves_existing_targets_and_credentials(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit), tempfile.TemporaryDirectory() as temporary:
                state=fixture_state()
                state["users"]=[fixture_user()]
                config=kvnctl.default_xray_config(state)
                for system, port in (("reality-tcp",2054),("reality-xhttp",2053)):
                    if explicit: state["sni_routes"][system]["reality_mode"]="external"
                    settings=next(i for i in config["inbounds"] if i["port"]==port)["streamSettings"]["realitySettings"]
                    settings.update(target="custom-cover.example.test:8443", dest="legacy-cover.example.test:443", xver=1,
                                    privateKey="preserved-key", shortIds=["0011223344556677"])
                before=copy.deepcopy(state)
                path=Path(temporary)/"xray.json"; path.write_text(json.dumps(config))
                with mock.patch.object(kvnctl,"XRAY_CONFIG",path): kvnctl.render_xray(state)
                rendered=json.loads(path.read_text())
                for port in (2054,2053):
                    settings=next(i for i in rendered["inbounds"] if i["port"]==port)["streamSettings"]["realitySettings"]
                    self.assertEqual(settings["target"],"custom-cover.example.test:8443")
                    self.assertEqual(settings["dest"],"legacy-cover.example.test:443")
                    self.assertEqual(settings["xver"],1)
                    self.assertEqual(settings["privateKey"],"preserved-key")
                for key in ("sni_routes","users","reality","reality_tcp"):
                    self.assertEqual(state.get(key),before.get(key))

    def test_explicit_external_sni_change_still_updates_cover_without_self_steal(self):
        for system,port in (("reality-tcp",2054),("reality-xhttp",2053)):
            with self.subTest(system=system), tempfile.TemporaryDirectory() as temporary:
                state=fixture_state(); state["users"]=[]; config=kvnctl.default_xray_config(state)
                path=Path(temporary)/"xray.json"; path.write_text(json.dumps(config))
                state["sni_routes"][system]["default"]="external-new.example.test"
                with mock.patch.object(kvnctl,"XRAY_CONFIG",path): kvnctl.render_xray(state)
                settings=next(i for i in json.loads(path.read_text())["inbounds"] if i["port"]==port)["streamSettings"]["realitySettings"]
                self.assertEqual(settings["target"],"external-new.example.test:443")
                self.assertNotIn("reality_mode",state["sni_routes"][system])

    def test_self_steal_is_explicit_and_can_restore_external_route(self):
        own="web.example.test"
        route={"default":"apple.com","aliases":["apple.com"],"dest":"xray:2054"}
        self.assertEqual(xray.reality_mode(route),"external")
        self.assertEqual(sni.reality_route_for_mode(route,"external","apple.com",[own]),route)
        selected=sni.reality_route_for_mode(route,"self-steal",own,[own])
        self.assertEqual(selected["reality_mode"],"self-steal")
        restored=sni.reality_route_for_mode(selected,"external","apple.com",[own])
        self.assertEqual(restored["aliases"],route["aliases"])
        self.assertEqual(route["default"],"apple.com")
        for mode,domain in (("automatic",own),("self-steal","foreign.example.test"),("external",own)):
            with self.subTest(mode=mode),self.assertRaises(ValueError): sni.reality_route_for_mode(route,mode,domain,[own])

    def test_ocserv_shared_front_sni_cannot_override_portal_or_subscription(self):
        state = fixture_state()
        state["portal"] = {"enabled":True,"domain":"web.example.test","port":8443,"path":"/gaer",
                           "login":"admin","password_hash":"scrypt$fixture",
                           "proxy_secret":"p"*64,"hysteria_secret":"h"*64}
        state["subscription"] = {"enabled":True,"public_host":"cfg.example.test","public_port":443,"port":2096}
        state["ocserv"].update(enabled=True,front_snis=["web.example.test","cfg.example.test"])
        kvnctl.validate_state_inputs(state)
        kvnctl.validate_sni_uniqueness(state)
        aliases = kvnctl.all_sni_aliases(state)
        self.assertEqual(aliases["web.example.test"], "127.0.0.1:8443")
        self.assertEqual(aliases["cfg.example.test"], "127.0.0.1:8443")
        self.assertEqual(aliases["oc.example.test"], "ocserv:443")
        self.assertEqual(kvnctl.ocserv_public_tcp_port(state, "web.example.test"), 2448)
        self.assertEqual(kvnctl.ocserv_public_tcp_port(state), 443)
        text = kvnctl.openconnect_client_text(state, fixture_user())
        self.assertIn("https://web.example.test:2448/", text)

    def test_nginx_hash_handles_maximum_dns_name_and_large_route_pool(self):
        maximum_domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
        self.assertEqual(len(maximum_domain), 253)
        self.assertEqual(sni.nginx_map_hash_sizes(["1:" + maximum_domain]), (512, 2048))
        self.assertEqual(sni.nginx_map_hash_sizes(["1:example.com"]), (64, 2048))
        self.assertEqual(sni.nginx_map_hash_sizes(["1:" + "a" * 45]), (128, 2048))
        self.assertEqual(sni.nginx_map_hash_sizes([str(i) for i in range(3000)]), (64, 8192))

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
