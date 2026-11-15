"""Границы конфигураций, сетевого плана и возможностей WG/AWG."""

import base64
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from v5.core.lifecycle.controller import LifecycleError
from v5.core.network.plan import Binding, NetworkConflict, build_plan
from v5.modules import wireguard
from v5.modules.amneziawg import profile as amneziawg
from v5.modules.host_tunnel.config import AWG, WG, Peer, Settings, render_server, settings_from_document
from v5.modules.host_tunnel.firewall import TunnelFirewall
from v5.modules.host_tunnel.platform import _AWG31_OPTIONS, _kernel_accepts_31, _tool_supports_31
from v5.modules.host_tunnel.state import State
from v5.modules.host_tunnel.runtime import TunnelRuntime
from v5.modules.host_tunnel.adapter import TunnelAdapter
from v5.modules.host_tunnel.credentials import allocate, peer, public_key
from v5.modules.host_tunnel.users import restore_profile, restore_seed, server_seed, set_user


def sample_key(value: int) -> str:
    return base64.b64encode(bytes([value]) * 32).decode("ascii")


class TunnelProfileTests(unittest.TestCase):
    def setUp(self):
        self.wg_peer = Peer(sample_key(2), "10.67.67.2", sample_key(3))
        self.awg_peer = Peer(sample_key(4), "10.66.66.2")
        self.wg = Settings(WG.address, sample_key(1), (self.wg_peer,))
        self.awg = Settings(AWG.address, sample_key(5), (self.awg_peer,))

    def test_udp_publications_and_device_names_are_independent(self):
        self.assertEqual((WG.interface, WG.port), ("wg0", 51821))
        self.assertEqual((AWG.interface, AWG.port), ("awg0", 51820))
        disabled = AWG.network(ipv6=True)
        active = replace(WG.network(ipv6=True), enabled=True)
        plan = build_plan((disabled, active))
        self.assertEqual(tuple((row.publication.public.ip, row.publication.public.port) for row in plan.publications),
                         (("0.0.0.0", 51821), ("::", 51821)))
        self.assertEqual(plan.active, ("wireguard",))
        with self.assertRaisesRegex(NetworkConflict, "unmanaged_port_conflict"):
            build_plan((disabled, active), occupied=(Binding("udp", "::", 51821),))

    def test_new_awg_defaults_to_31_without_changing_wireguard(self):
        awg = TunnelRuntime(AWG)
        with patch.object(awg, "_tool", return_value="/usr/bin/awg"), patch(
                "v5.modules.host_tunnel.runtime._run", side_effect=[sample_key(11).encode(), sample_key(12).encode()]):
            state = awg.initial_state()
        self.assertEqual(state.mode, "3.1")
        self.assertIn(b"HeaderProtectionKey = " + sample_key(12).encode(), state.server())
        wg = TunnelRuntime(WG)
        with patch.object(wg, "_tool", return_value="/usr/bin/wg"), patch(
                "v5.modules.host_tunnel.runtime._run", return_value=sample_key(13).encode()):
            state = wg.initial_state()
        self.assertEqual(state.mode, "standard")
        self.assertNotIn(b"HeaderProtectionKey", state.server())
        modern = State(AWG, self.awg, amneziawg.Profile.modern(sample_key(12)))
        with patch("v5.modules.host_tunnel.runtime.capability", return_value=SimpleNamespace(issue=None, profiles=("legacy",))):
            with self.assertRaisesRegex(LifecycleError, "amneziawg_profile_unsupported"):
                awg.preflight(modern)

    def test_initialization_never_replaces_existing_tunnel_keys(self):
        with TemporaryDirectory() as directory:
            packages = SimpleNamespace(runtime_guard=nullcontext, require_network_idle=lambda: None,
                                       installed=lambda: [{'module': 'wireguard', 'enabled': False}])
            adapter = TunnelAdapter(SimpleNamespace(packages=packages), WG, modules_root=Path(directory) / 'modules')
            original = State(WG, self.wg)
            with patch.object(adapter, 'running', return_value=False):
                adapter.configure(original, initial=True)
                config = adapter.root / 'settings.json'
                before = config.read_bytes()
                replacement = State(WG, replace(self.wg, private_key=sample_key(99)))
                with self.assertRaisesRegex(LifecycleError, 'tunnel_already_configured'):
                    adapter.configure(replacement, initial=True)
                self.assertEqual(config.read_bytes(), before)

    def test_tunnel_egress_edit_preserves_keys_peers_and_rejects_stale(self):
        with TemporaryDirectory() as directory:
            for spec, settings, profile in ((WG, self.wg, None),
                                             (AWG, self.awg, amneziawg.Profile.modern(sample_key(12)))):
                packages = SimpleNamespace(runtime_guard=nullcontext, require_network_idle=lambda: None,
                                           installed=lambda: [{'module': spec.module, 'enabled': False}])
                adapter = TunnelAdapter(SimpleNamespace(packages=packages), spec, modules_root=Path(directory) / 'modules')
                original = State(spec, settings, profile)
                with self.subTest(module=spec.module), patch.object(adapter, 'running', return_value=False):
                    self.assertIsNone(adapter.egress_view())
                    adapter.configure(original, initial=True)
                    view = adapter.egress_view()
                    self.assertNotIn(settings.private_key, str(view))
                    adapter.change_egress('eth0', view['revision'])
                    self.assertEqual(adapter.settings(), replace(original, settings=replace(settings, egress='eth0')))
                    before = (adapter.root / 'settings.json').read_bytes()
                    with self.assertRaisesRegex(LifecycleError, 'tunnel_configuration_changed'):
                        adapter.change_egress(None, view['revision'])
                    with self.assertRaisesRegex(LifecycleError, 'tunnel_egress_invalid'):
                        adapter.change_egress('eth0;id', adapter.egress_view()['revision'])
                    with patch.object(adapter, 'running', return_value=True):
                        with self.assertRaisesRegex(LifecycleError, 'module_must_be_disabled'):
                            adapter.change_egress(None, adapter.egress_view()['revision'])
                    self.assertEqual((adapter.root / 'settings.json').read_bytes(), before)

    def test_awg_restores_u16_junk_size_and_tagged_slot_numbers(self):
        profile = amneziawg.Profile(junk_max=1024, tagged=("", "<r 2>"))
        self.assertIn("Jmax = 1024", profile.lines())
        self.assertIn("I2 = <r 2>", profile.lines())
        self.assertFalse(any(line.startswith("I1 =") for line in profile.lines()))
        with self.assertRaises(ValueError):
            replace(profile, junk_max=65536)

    def test_tunnel_material_has_matching_key_pair_and_stable_address(self):
        state = State(WG, replace(self.wg, peers=()))
        first = allocate(state.settings, ())
        second = allocate(state.settings, (first,))
        self.assertEqual((first["address"], second["address"]), ("10.67.67.2", "10.67.67.3"))
        enabled = set_user(state, first, True)
        self.assertEqual(enabled.settings.peers, (peer(first),))
        self.assertEqual(set_user(enabled, first, True), enabled)
        self.assertEqual(set_user(enabled, first, False), state)
        with self.assertRaises(ValueError):
            peer({**first, "public_key": second["public_key"]})

    def test_tunnel_server_and_awg_31_restore_without_generating_new_identity(self):
        private = sample_key(17)
        seed = {"private_key": private, "public_key": public_key(private), "address": "10.99.0.1/24",
                "mode": "3.1", "obfuscation": {"Jmax": 1024, "I3": "<r 2>"},
                "v3": {"header_protection_key": sample_key(18)}}
        state = State(AWG, replace(self.awg, peers=()), amneziawg.Profile.modern(sample_key(19)))
        restored = restore_seed(state, seed)
        self.assertEqual(restored.settings.private_key, private)
        self.assertEqual(restored.profile.v31.header_key, sample_key(18))
        self.assertEqual(restored.settings.address, "10.99.0.1/24")
        self.assertEqual(restored.profile.junk_max, 1024)
        self.assertIn("I3 = <r 2>", restored.profile.lines())
        self.assertFalse(restored.profile.v31.random_trailers)
        self.assertEqual(restore_profile({"mode": "legacy"}).mode, "legacy")
        exported = server_seed(restored)
        self.assertNotIn("egress", exported)
        self.assertNotIn("peers", exported)
        self.assertEqual(restore_seed(state, exported), restored)

    def test_kernel_config_contains_no_quick_hooks_or_cross_protocol_options(self):
        modern = amneziawg.Profile.modern(sample_key(6))
        wg = wireguard.server(self.wg)
        legacy = amneziawg.server(self.awg, amneziawg.Profile())
        awg = amneziawg.server(self.awg, modern)
        self.assertIn(b"ListenPort = 51821", wg)
        self.assertIn(b"ListenPort = 51820", awg)
        self.assertIn(b"AllowedIPs = 10.67.67.2/32", wg)
        self.assertIn(b"S2 = 120", legacy)
        self.assertNotIn(b"S3 =", legacy)
        self.assertNotIn(b"HeaderProtectionKey", legacy)
        self.assertNotIn(b"PresharedKey", awg)
        self.assertNotIn(b"Jc", wg)
        self.assertNotIn(b"HeaderProtectionKey", wg)
        self.assertIn(b"HeaderProtectionKey = " + sample_key(6).encode(), awg)
        self.assertIn(b"ContentPaddingAddition = 16-64", awg)
        self.assertTrue(all(b"PostUp" not in value and b"Address =" not in value for value in (wg, legacy, awg)))
        with self.assertRaises(ValueError):
            render_server(WG, self.wg, obfuscation=modern.lines())

    def test_client_export_matches_server_family_and_checks_permission(self):
        options = dict(private_key=sample_key(7), server_key=sample_key(8), endpoint="2001:db8::42", active=True)
        config = wireguard.client(self.wg, self.wg_peer, **options)
        self.assertIn(b"Endpoint = [2001:db8::42]:51821", config)
        self.assertIn(b"AllowedIPs = 10.67.67.0/24", config)
        self.assertNotIn(b"HeaderProtectionKey", config)
        awg = amneziawg.client(replace(self.awg, egress="ens3"), self.awg_peer,
                                amneziawg.Profile.modern(sample_key(6)), **options)
        self.assertIn(b"Endpoint = [2001:db8::42]:51820", awg)
        self.assertIn(b"AllowedIPs = 0.0.0.0/0", awg)
        self.assertIn(b"HeaderProtectionKey", awg)
        self.assertEqual(wireguard.client(self.wg, self.awg_peer, **options), b"")
        self.assertEqual(wireguard.client(self.wg, self.wg_peer, **(options | {"active": False})), b"")
        with self.assertRaises(ValueError):
            wireguard.client(self.wg, self.wg_peer, **(options | {"endpoint": "portal.example\nPostUp = id"}))

    def test_key_and_address_validation(self):
        for changed in ({"address": "10.66.66.1/24"}, {"peers": (self.wg_peer, self.wg_peer)},
                        {"peers": (replace(self.wg_peer, address="10.67.67.1"),)},
                        {"egress": "awg0"}, {"private_key": sample_key(0)}, {"mtu": True}):
            with self.subTest(field=next(iter(changed))), self.assertRaises(ValueError):
                replace(self.wg, **changed)
        raw = {"address": WG.address, "private_key": sample_key(1), "peers": [], "mtu": 1280, "egress": None}
        self.assertEqual(settings_from_document(raw), replace(self.wg, peers=()))
        with self.assertRaises(ValueError):
            settings_from_document(raw | {"PostUp": "id"})

    def test_rejects_invalid_or_mixed_amnezia_parameters(self):
        modern = amneziawg.Profile.modern(sample_key(6))
        for changed in ({"mode": "legacy"}, {"padding": (11, 120, 32, 48)},
                        {"padding": (12, 68, 32, 48)}, {"headers": ("5-9", "8-10", "11", "12")},
                        {"tagged": ("<r 3>\nListenPort = 22",)}):
            with self.subTest(field=next(iter(changed))), self.assertRaises(ValueError):
                replace(modern, **changed)
        with self.assertRaises(ValueError):
            replace(modern.v31, reject_after="120-140")

    def test_requires_both_modern_kernel_and_tool_options(self):
        options = b" ".join(_AWG31_OPTIONS)
        self.assertFalse(_tool_supports_31(b"header-protection-key"))
        self.assertTrue(_tool_supports_31(options))
        with patch("v5.modules.host_tunnel.platform._try", side_effect=[True, False, True]) as call:
            self.assertFalse(_kernel_accepts_31("/usr/local/bin/awg"))
        created, applied, deleted = call.call_args_list
        self.assertEqual(created.args[1:4], ("link", "add", "name"))
        name = created.args[4]
        self.assertEqual(applied.args, ("/usr/local/bin/awg", "setconf", name, "/dev/stdin"))
        self.assertIn(b"HeaderProtectionKey", applied.kwargs["data"])
        self.assertNotIn(b"ListenPort", applied.kwargs["data"])
        self.assertNotIn(b"Address", applied.kwargs["data"])
        self.assertEqual(deleted.args[1:], ("link", "delete", "dev", name))
        with (patch("v5.modules.host_tunnel.platform._try", side_effect=[True, True, True]),
              patch("v5.modules.host_tunnel.platform._probe", return_value=b"[Interface]\n")):
            self.assertFalse(_kernel_accepts_31("/usr/local/bin/awg"))
        observed = ("HeaderProtectionKey = " + sample_key(8) + "\nContentPaddingAddition = 16-64\n"
                    "RekeyAfterTime = 120-150\nRandomTrailers = on\n").encode("ascii")
        with (patch("v5.modules.host_tunnel.platform._try", side_effect=[True, True, True]),
              patch("v5.modules.host_tunnel.platform._probe", return_value=observed),
              patch("v5.modules.host_tunnel.platform.secrets.token_bytes", side_effect=lambda size: bytes([8]) * size)):
            self.assertTrue(_kernel_accepts_31("/usr/local/bin/awg"))

    def test_private_round_trip_and_peer_only_changes(self):
        wg = State(WG, self.wg)
        awg = State(AWG, self.awg, amneziawg.Profile.modern(sample_key(6)))
        self.assertTrue(wg.peer_only(replace(wg, settings=replace(self.wg, peers=()))))
        self.assertFalse(wg.peer_only(replace(wg, settings=replace(self.wg, mtu=1300))))
        self.assertFalse(wg.peer_only(replace(wg, settings=Settings("10.68.0.1/24", sample_key(1)))))
        self.assertFalse(wg.peer_only(awg))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            awg.save(path)
            self.assertEqual(State.load(AWG, path), awg)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                State.load(WG, path)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                State.load(AWG, path)

    def test_nft_firewalls_are_separate_and_not_implicit_transit(self):
        wg = TunnelFirewall(WG)
        awg = TunnelFirewall(AWG)
        local = wg.compile(self.wg)
        self.assertEqual(local.rule_count, 2)
        self.assertNotIn(b"masquerade", local.batch(None))
        self.assertIn(b'iifname "wg0" drop', local.batch(None))
        full = awg.compile(replace(self.awg, egress="ens3"))
        self.assertIn(b'iifname "awg0" oifname "ens3" ip saddr 10.66.66.0/24 masquerade', full.batch(None))
        self.assertNotIn(b"wireguard", full.batch(None))
        self.assertEqual(awg.compile(None).batch(17), b"delete table inet handle 17\n")
        with self.assertRaisesRegex(NetworkConflict, "invalid_nft_owner"):
            wg.apply_compiled(full)
