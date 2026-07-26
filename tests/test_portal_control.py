import os
import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from portal.control import ControlError, KvnControl
from tests.test_kvnctl_security import base_state
from tools import kvnctl
from tools.kvnlib.state import JsonStateStore, StateRevisionConflict, atomic_write_json, state_revision
from tools.kvnlib.services import configured_service_preferences


class FakeKvnctl:
    def __init__(self, store):
        self.STATE_STORE = store

    @staticmethod
    def validate_name(name):
        if not name or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in name):
            raise SystemExit("invalid name")

    @staticmethod
    def find_user(state, name):
        return next((item for item in state["users"] if item["name"] == name), None)

    configured_service_preferences = staticmethod(configured_service_preferences)


class UserDownloadBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        users = self.root / "users.json"
        atomic_write_json(users, {"users": [{"name": "Alice"}]})
        client_dir = self.root / "clients" / "Alice"
        client_dir.mkdir(parents=True)
        (client_dir / "send.txt").write_text("allowed", encoding="utf-8")
        (client_dir / "private.key").write_text("denied", encoding="utf-8")
        self.control = KvnControl.__new__(KvnControl)
        self.control.root = self.root
        self.control.kvnctl = FakeKvnctl(JsonStateStore(users))

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_safe_generated_files_are_listed_and_read(self):
        files = self.control.user_files("Alice")
        self.assertEqual([item["name"] for item in files], ["send.txt"])
        self.assertEqual(files[0]["kind"], "file")
        self.assertTrue(files[0]["can_preview"])
        result = self.control.read_user_file("Alice", "send.txt")
        self.assertEqual(result["filename"], "send.txt")
        with self.assertRaises(ControlError):
            self.control.read_user_file("Alice", "private.key")

    def test_qr_and_primary_configs_have_typed_metadata(self):
        client_dir = self.root / "clients" / "Alice"
        (client_dir / "amneziawg.png").write_bytes(b"png")
        (client_dir / "wireguard.png").write_bytes(b"png")
        (client_dir / "wireguard.conf").write_text("[Interface]\n", encoding="utf-8")
        (client_dir / "happ-subscription.txt").write_text("https://vpn.example/token", encoding="utf-8")
        (client_dir / "karing-subscription.txt").write_text("https://vpn.example/token", encoding="utf-8")
        (client_dir / "karing-subscription.png").write_bytes(b"png")
        (client_dir / "karing-wireguard.txt").write_text("https://vpn.example/karing-wg/token", encoding="utf-8")
        (client_dir / "karing-wireguard.yaml").write_text("proxies: []\n", encoding="utf-8")
        (client_dir / "karing-wireguard.png").write_bytes(b"png")
        (client_dir / "telemt.png").write_bytes(b"png")
        (client_dir / "telemt.txt").write_text("telemt", encoding="utf-8")
        (client_dir / "mtg.png").write_bytes(b"png")
        (client_dir / "mtg.txt").write_text("mtg", encoding="utf-8")
        (client_dir / "telegram-proxy.txt").write_text("telegram", encoding="utf-8")
        metadata = {item["name"]: item for item in self.control.user_files("Alice")}
        self.assertEqual(metadata["amneziawg.png"]["kind"], "amneziawg-qr")
        self.assertEqual(metadata["amneziawg.png"]["content_type"], "image/png")
        self.assertEqual(metadata["wireguard.png"]["kind"], "wireguard-qr")
        self.assertEqual(metadata["wireguard.conf"]["kind"], "wireguard-config")
        self.assertEqual(metadata["happ-subscription.txt"]["kind"], "happ-url")
        self.assertEqual(metadata["karing-subscription.png"]["kind"], "karing-qr")
        self.assertEqual(metadata["karing-subscription.txt"]["kind"], "karing-url")
        self.assertEqual(metadata["karing-wireguard.png"]["kind"], "karing-wireguard-qr")
        self.assertEqual(metadata["karing-wireguard.txt"]["kind"], "karing-wireguard-url")
        self.assertEqual(metadata["karing-wireguard.yaml"]["kind"], "karing-wireguard-config")
        self.assertEqual(metadata["telemt.png"]["kind"], "telemt-qr")
        self.assertEqual(metadata["telemt.txt"]["kind"], "telemt-config")
        self.assertEqual(metadata["mtg.png"]["kind"], "mtg-qr")
        self.assertEqual(metadata["mtg.txt"]["kind"], "mtg-config")
        self.assertEqual(metadata["telegram-proxy.txt"]["kind"], "telegram-proxy")

    def test_service_enabled_preference_is_persisted(self):
        result = self.control.set_service_enabled("xray", False)
        self.assertTrue(result["changed"])
        self.assertEqual(self.control.service_preferences(), {"xray": False})
        stored = self.control.kvnctl.STATE_STORE.load()
        self.assertFalse(stored["services"]["xray"]["enabled"])

    def test_traversal_unknown_user_and_large_file_are_denied(self):
        for name, filename in [
            ("Alice", "../users.json"),
            ("Missing", "send.txt"),
        ]:
            with self.subTest(name=name, filename=filename), self.assertRaises(ControlError):
                self.control.read_user_file(name, filename)
        large = self.root / "clients" / "Alice" / "large.txt"
        large.write_bytes(b"x" * (KvnControl.MAX_DOWNLOAD_BYTES + 1))
        with self.assertRaises(ControlError):
            self.control.read_user_file("Alice", "large.txt")
        with self.assertRaises(ControlError):
            self.control.read_user_file("Alice", 'bad"name.txt')

    @unittest.skipIf(os.name == "nt", "создание symlink требует прав Windows")
    def test_symlink_escape_is_denied(self):
        outside = self.root / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        (self.root / "clients" / "Alice" / "escape.txt").symlink_to(outside)
        with self.assertRaises(ControlError):
            self.control.read_user_file("Alice", "escape.txt")


class PortalAtomicPrepareTests(unittest.TestCase):
    @staticmethod
    def protocol_control(root: Path, store: JsonStateStore) -> KvnControl:
        control = KvnControl.__new__(KvnControl)
        control.root = root
        control.kvnctl = kvnctl
        control.StateRevisionConflict = StateRevisionConflict
        control.state_revision = state_revision
        return control

    def test_read_only_views_keep_revision_of_sparse_source_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state.pop("sni_routes", None)
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            expected = state_revision(store.load())

            with mock.patch.object(kvnctl, "STATE_STORE", store):
                self.assertEqual(control.list_users()["revision"], expected)
                self.assertEqual(control.network_topology()["revision"], expected)
                self.assertEqual(control.sni_routes()["revision"], expected)
            self.assertEqual(state_revision(store.load()), expected)

    def test_user_activity_subject_contains_only_safe_runtime_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            user = state["users"][0]
            user["systems"].extend(["amneziawg", "wireguard"])
            user["amneziawg"] = {
                "private_key": "awg-private", "preshared_key": "awg-psk", "public_key": "awg-public",
            }
            user["wireguard"] = {
                "private_key": "wg-private", "preshared_key": "wg-psk", "public_key": "wg-public",
            }
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            with mock.patch.object(kvnctl, "STATE_STORE", store):
                subject = control.user_activity_subject("Alice")
            self.assertEqual(subject["amneziawg_public_key"], "awg-public")
            self.assertEqual(subject["wireguard_public_key"], "wg-public")
            self.assertIn("wireguard", subject["systems"])
            serialized = json.dumps(subject)
            for forbidden in ["awg-private", "wg-private", "awg-psk", "wg-psk", "uuid", "secret", "password"]:
                self.assertNotIn(forbidden, serialized)
            with mock.patch.object(kvnctl, "STATE_STORE", store), self.assertRaises(ControlError):
                control.user_activity_subject("Missing")

    def test_legacy_ip_performance_revision_matches_stored_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["portal"] = {
                "enabled": True, "name": "KVN", "domain": "46.29.239.64",
                "port": 8443, "path": "/gaer", "login": "admin",
                "password_hash": "scrypt$legacy", "proxy_secret": "p" * 64,
                "hysteria_secret": "h" * 64, "allow_self_signed_ip": True,
            }
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            expected = state_revision(store.load())

            with mock.patch.object(kvnctl, "STATE_STORE", store):
                result = control.portal_performance()

            self.assertEqual(result["revision"], expected)
            self.assertEqual(result["profile"], "standard")
            self.assertEqual(state_revision(store.load()), expected)

    def test_performance_profile_updates_only_portal_state_without_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["portal"] = {
                "enabled": True, "performance_profile": "standard",
                "features": {"monitoring": True, "background_refresh": True},
            }
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "sync_portal_runtime_state") as sync_runtime,
                mock.patch.object(kvnctl, "render_all") as render,
                mock.patch.object(kvnctl, "restart_services") as restart,
            ):
                result = control.update_portal_performance({
                    "revision": state_revision(state), "profile": "light",
                    "monitoring": True, "background_refresh": True,
                })
            stored = store.load()
            self.assertTrue(result["changed"])
            self.assertEqual(result["changed_features"], ["monitoring", "background_refresh"])
            self.assertEqual(stored["portal"]["performance_profile"], "light")
            self.assertEqual(stored["portal"]["features"], {
                "monitoring": False, "background_refresh": False,
            })
            sync_runtime.assert_called_once()
            render.assert_not_called()
            restart.assert_not_called()

    def test_client_export_settings_report_ip_bundle_and_subscription_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["client_export"] = {
                "address_mode": "server",
                "public_ip": "8.8.4.4",
                "include_alternate": True,
            }
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            expected_revision = state_revision(state)

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "certificate_sans", return_value=[]),
            ):
                result = control.client_export_settings()

            self.assertEqual(result["revision"], expected_revision)
            self.assertEqual(result["public_ip"], "8.8.4.4")
            self.assertTrue(result["ip_bundle_ready"])
            self.assertTrue(result["subscription"]["route_ready"])
            self.assertFalse(result["subscription"]["certificate_ready"])
            self.assertFalse(result["subscription"]["ready"])
            self.assertEqual(state_revision(store.load()), expected_revision)

    def test_client_export_update_is_revision_safe_and_renders_client_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            render_result = kvnctl.RenderResult(("clients/Alice/send.txt",))

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "certificate_sans", return_value=[]),
                mock.patch.object(
                    kvnctl, "render_all", return_value=render_result,
                ) as render,
                mock.patch.object(
                    kvnctl,
                    "restart_services",
                    return_value={
                        "outcome": "applied",
                        "reconcile_required": False,
                        "warnings": [],
                        "fallbacks": [],
                        "failed": [],
                    },
                ) as restart,
            ):
                result = control.update_client_export({
                    "revision": state_revision(state),
                    "address_mode": "public-ip",
                    "public_ip": "8.8.4.4",
                    "include_alternate": True,
                })

            self.assertTrue(result["changed"])
            self.assertEqual(store.load()["client_export"], {
                "address_mode": "public-ip",
                "public_ip": "8.8.4.4",
                "include_alternate": True,
            })
            render.assert_called_once()
            restart.assert_called_once()

    def test_client_export_invalid_or_stale_update_does_not_write_or_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            original = users_file.read_bytes()

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all") as render,
            ):
                for public_ip, revision in [
                    ("10.0.0.1", state_revision(state)),
                    ("8.8.4.4", "0" * 64),
                ]:
                    with self.subTest(
                        public_ip=public_ip, revision=revision,
                    ), self.assertRaises(ControlError):
                        control.update_client_export({
                            "revision": revision,
                            "address_mode": "public-ip",
                            "public_ip": public_ip,
                            "include_alternate": False,
                        })

            self.assertEqual(users_file.read_bytes(), original)
            render.assert_not_called()

    def test_protocol_apply_changes_only_xhttp_mode_and_applies_xray(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["xray"] = {"xhttp_mode": "stream-one"}
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "prepare_state"),
                mock.patch.object(kvnctl, "render_all", return_value=kvnctl.RenderResult(("xray/config.json",))) as render,
                mock.patch.object(kvnctl, "restart_services", return_value={"outcome": "applied", "reconcile_required": False}) as restart,
            ):
                result = control.apply_protocol({
                    "action": "set-xhttp-mode", "system": "reality-xhttp",
                    "mode": "stream-up", "revision": state_revision(state),
                })

            expected = copy.deepcopy(state)
            expected["xray"]["xhttp_mode"] = "stream-up"
            self.assertEqual(store.load(), expected)
            self.assertTrue(result["changed"])
            render.assert_called_once()
            restart.assert_called_once()

    def test_protocol_apply_rejects_invalid_schema_mode_and_stale_revision_before_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["xray"] = {"xhttp_mode": "stream-one"}
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            original = users_file.read_bytes()
            valid = {"action": "set-xhttp-mode", "system": "reality-xhttp", "mode": "stream-up", "revision": state_revision(state)}

            with mock.patch.object(kvnctl, "STATE_STORE", store), mock.patch.object(kvnctl, "render_all") as render:
                for params in ({**valid, "backend": "attacker:443"}, {**valid, "mode": "invalid-mode"}, {**valid, "revision": "0" * 64}):
                    with self.assertRaises(ControlError):
                        control.apply_protocol(params)

            self.assertEqual(users_file.read_bytes(), original)
            render.assert_not_called()

    def test_protocol_apply_noop_skips_render_and_degraded_keeps_desired_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["xray"] = {"xhttp_mode": "stream-one"}
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            params = {"action": "set-xhttp-mode", "system": "reality-xhttp", "mode": "stream-one", "revision": state_revision(state)}

            with mock.patch.object(kvnctl, "STATE_STORE", store), mock.patch.object(kvnctl, "prepare_state"), mock.patch.object(kvnctl, "render_all") as render:
                noop = control.apply_protocol(params)
            self.assertFalse(noop["changed"])
            render.assert_not_called()

            params.update({"mode": "packet-up", "revision": noop["revision"]})
            with mock.patch.object(kvnctl, "STATE_STORE", store), mock.patch.object(kvnctl, "prepare_state"), mock.patch.object(kvnctl, "render_all", side_effect=RuntimeError("fixture failure")):
                degraded = control.apply_protocol(params)
            self.assertEqual(store.load()["xray"]["xhttp_mode"], "packet-up")
            self.assertEqual(degraded["apply"]["outcome"], "failed")
            self.assertTrue(degraded["apply"]["reconcile_required"])

    def test_network_topology_is_complete_and_secret_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["users"][0].update({
                "sub_token": "feedfacefeedfacefeedfacefeedface",
                "ocserv_password": "OpenConnectSecret123",
                "amneziawg": {"private_key": "AWG_PRIVATE_SECRET", "preshared_key": "AWG_PSK_SECRET"},
            })
            state["reality"] = {"privateKey": "REALITY_PRIVATE_SECRET", "shortIds": ["deadbeef"]}
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.state_revision = state_revision

            with mock.patch.object(kvnctl, "STATE_STORE", JsonStateStore(users_file, root / ".lock")):
                data = control.network_topology()

            self.assertEqual(set(data), {"revision", "ingress", "routes", "protocols", "infrastructure"})
            self.assertEqual([item["system"] for item in data["protocols"]], kvnctl.ALL_SYSTEMS)
            self.assertEqual({item["id"] for item in data["infrastructure"]}, {"nginx", "portal", "agent"})
            for item in data["protocols"]:
                self.assertTrue(item["ingress"])
                self.assertIn("transport", item)
                self.assertIn("backend", item)
                self.assertIn("backend_kind", item)
                self.assertIn("apply_kind", item)
                self.assertEqual(item["sni_scope"], item["sni"]["scope"])
                self.assertTrue(item["read_only"])
                self.assertIn("assigned", item["users"])
                self.assertIn(item["sni"]["scope"], {"per_user", "service", "not_applicable"})
            xhttp = next(item for item in data["protocols"] if item["system"] == "reality-xhttp")
            tcp = next(item for item in data["protocols"] if item["system"] == "reality-tcp")
            self.assertEqual(xhttp["backend"], "xray:2053")
            self.assertEqual(tcp["backend"], "xray:2054")
            self.assertEqual(xhttp["sni"]["target"], "github.com:443")
            self.assertIn("github.com", xhttp["sni"]["server_names"])
            by_system = {item["system"]: item for item in data["protocols"]}
            self.assertEqual(by_system["hysteria"]["facts"]["public_transport"], "443/udp")
            self.assertEqual(by_system["telemt"]["facts"]["sni_scope"], "service")
            self.assertEqual(by_system["mtg"]["facts"]["sni_scope"], "service")
            self.assertEqual(by_system["amneziawg"]["facts"]["public_transport"], "51820/udp")
            self.assertEqual(by_system["wireguard"]["facts"]["public_transport"], "51821/udp")
            self.assertNotEqual(by_system["amneziawg"]["facts"]["interface"], by_system["wireguard"]["facts"]["interface"])
            self.assertEqual(by_system["ocserv"]["facts"]["dtls_transport"], "4443/udp")
            serialized = json.dumps(data, ensure_ascii=False)
            for secret in [
                state["users"][0]["uuid"], "StrongPass123", "feedfacefeedfacefeedfacefeedface",
                "OpenConnectSecret123", "AWG_PRIVATE_SECRET", "AWG_PSK_SECRET",
                "REALITY_PRIVATE_SECRET", "deadbeef",
            ]:
                self.assertNotIn(secret, serialized)

    def test_domain_advice_is_safe_read_only_and_warns_about_self_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["server"] = "203.0.113.10"
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            before = users_file.read_bytes()

            def probe(hostname, timeout):
                if hostname.startswith("portal."):
                    return {"dns": "ok", "tls": "unavailable", "reason": "tls_invalid"}
                if hostname.startswith("kvn-wildcard-check."):
                    return {"dns": "unavailable", "tls": "not_checked", "reason": "dns_unavailable"}
                if hostname.startswith("sub."):
                    return {"dns": "timeout", "tls": "not_checked", "reason": "dns_timeout"}
                return {"dns": "ok", "tls": "ok", "reason": "ok"}

            def addresses(hostname, _timeout):
                return {"203.0.113.10"} if hostname == "gaer.loc.cc" else {"198.51.100.20"}

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "probe_sni_target", side_effect=probe),
                mock.patch.object(control, "_resolve_addresses", side_effect=addresses),
            ):
                advice = control.domain_advice({"zone": "gaer.loc.cc"})

            self.assertEqual(users_file.read_bytes(), before)
            self.assertEqual(advice["hostname_count"], 7)
            self.assertEqual(advice["status"], "needs_attention")
            by_role = {item["role"]: item for item in advice["hostnames"]}
            self.assertTrue(by_role["site"]["same_server"])
            self.assertEqual(by_role["portal"]["cert_match"], "mismatch")
            self.assertEqual(by_role["subscription"]["dns"], "timeout")
            self.assertEqual(by_role["wildcard"]["recommendation"], "wildcard-absent")
            reality = {item["system"]: item for item in advice["protocols"]}
            self.assertEqual(reality["reality-xhttp"]["recommendation"], "external-cover-required")
            self.assertEqual(reality["telemt"]["recommendation"], "service-level-camouflage")
            self.assertEqual(reality["wireguard"]["recommendation"], "no-sni")
            serialized = json.dumps(advice, ensure_ascii=False)
            for forbidden in [
                "203.0.113.10",
                "198.51.100.20",
                '"certificate":',
                '"private_key":',
                '"password":',
                '"uuid":',
            ]:
                self.assertNotIn(forbidden, serialized.lower())

    def test_domain_advice_rejects_invalid_zone_and_bounds_total_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            users_file = root / "users.json"
            atomic_write_json(users_file, base_state())
            store = JsonStateStore(users_file, root / ".lock")
            control = self.protocol_control(root, store)
            with mock.patch.object(kvnctl, "STATE_STORE", store):
                for params in ({"zone": "bad zone"}, {"zone": "gaer.loc.cc", "count": 99}, {"zone": "203.0.113.10"}):
                    with self.assertRaises(ControlError):
                        control.domain_advice(params)
                control.DOMAIN_ADVICE_TIMEOUT = 0
                with mock.patch.object(kvnctl, "probe_sni_target") as probe:
                    result = control.domain_advice({"zone": "gaer.loc.cc"})
                probe.assert_not_called()
            self.assertEqual(result["hostname_count"], 7)
            self.assertTrue(all(item["dns"] == "timeout" for item in result["hostnames"]))

    def test_list_users_exposes_only_supported_user_sni_systems(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            users_file = root / "users.json"
            atomic_write_json(users_file, base_state())
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.state_revision = state_revision

            with mock.patch.object(kvnctl, "STATE_STORE", JsonStateStore(users_file, root / ".lock")):
                data = control.list_users()

            self.assertEqual(data["sni_systems"], ["tls", "reality-xhttp", "reality-tcp", "hysteria"])
            self.assertIn("tls", data["sni_choices"])
            self.assertIn("www.microsoft.com", data["sni_choices"]["tls"])
            self.assertEqual(set(data["sni_matrix"]), set(kvnctl.ALL_SYSTEMS))
            self.assertEqual(data["sni_matrix"]["telemt"]["scope"], "service")
            self.assertEqual(data["sni_matrix"]["amneziawg"]["scope"], "not_applicable")
            self.assertEqual(data["users"][0]["effective_sni"]["tls"], "www.microsoft.com")
            serialized = json.dumps(data, ensure_ascii=False)
            self.assertNotIn(base_state()["users"][0]["uuid"], serialized)
            self.assertNotIn("StrongPass123", serialized)

    def test_amneziawg_material_is_committed_before_render(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["users"] = []
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            store = JsonStateStore(users_file, root / ".lock")
            control.StateRevisionConflict = StateRevisionConflict
            control.state_revision = state_revision
            before_revision = state_revision(state)

            fields = {
                "name": "Bob",
                "systems": ["amneziawg"],
                "enabled": True,
                "description": "",
            }
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=kvnctl.RenderResult()),
                mock.patch.object(kvnctl, "restart_services", return_value={"outcome": "applied"}),
            ):
                result = control.apply_user({"action": "create", "revision": before_revision, "fields": fields})

            stored = store.load()
            user = stored["users"][0]
            awg = user["amneziawg"]
            self.assertEqual(result["revision"], state_revision(stored))
            self.assertEqual(result["secrets"]["amneziawg_private_key"], awg["private_key"])
            self.assertTrue(awg["public_key"])
            self.assertTrue(awg["preshared_key"])
            self.assertRegex(awg["address"], r"^10\.66\.66\.\d+/32$")

            snapshot = copy.deepcopy(stored)
            _public, _tcp_public, changed = kvnctl.prepare_state(stored)
            self.assertFalse(changed)
            self.assertEqual(stored, snapshot)

    def test_user_apply_forces_host_vpn_sync_for_portal_created_peer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["users"] = []
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.StateRevisionConflict = StateRevisionConflict
            control.state_revision = state_revision
            store = JsonStateStore(users_file, root / ".lock")
            before_revision = state_revision(state)

            fields = {
                "name": "Bob",
                "systems": ["amneziawg", "wireguard"],
                "enabled": True,
                "description": "",
            }
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=kvnctl.RenderResult()),
                mock.patch.object(kvnctl, "restart_services", return_value={"outcome": "applied"}) as restart,
            ):
                control.apply_user({"action": "create", "revision": before_revision, "fields": fields})

            call = restart.call_args
            self.assertIsNotNone(call)
            self.assertIn("before_state", call.kwargs)
            self.assertIn("after_state", call.kwargs)
            self.assertEqual(
                call.kwargs["force_host_sync_services"],
                {"amneziawg", "wireguard"},
            )

    def test_apply_host_service_forces_wireguard_sync_even_without_state_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["users"][0]["systems"] = ["wireguard"]
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.StateRevisionConflict = StateRevisionConflict
            control.state_revision = state_revision
            store = JsonStateStore(users_file, root / ".lock")

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=kvnctl.RenderResult()) as render,
                mock.patch.object(kvnctl, "restart_services", return_value={"outcome": "applied"}) as restart,
            ):
                result = control.apply_host_service("wireguard")

            self.assertEqual(result["service"], "wireguard")
            render.assert_called_once()
            restart.assert_called_once()
            self.assertEqual(restart.call_args.kwargs["force_host_sync_services"], {"wireguard"})

    def test_reconcile_forces_configured_host_vpn_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            state["users"][0]["systems"] = ["amneziawg", "wireguard"]
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.StateRevisionConflict = StateRevisionConflict
            control.state_revision = state_revision
            store = JsonStateStore(users_file, root / ".lock")

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=kvnctl.RenderResult()),
                mock.patch.object(kvnctl, "restart_services", return_value={"outcome": "applied"}) as restart,
            ):
                control.reconcile_state()

            self.assertEqual(restart.call_args.kwargs["force_host_sync_services"], {"amneziawg", "wireguard"})

    def test_sni_route_apply_adds_alias_and_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.StateRevisionConflict = StateRevisionConflict
            control.state_revision = state_revision
            store = JsonStateStore(users_file, root / ".lock")
            before_revision = state_revision(state)

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=kvnctl.RenderResult(("nginx/nginx.conf",))),
                mock.patch.object(kvnctl, "restart_services", return_value={"outcome": "applied"}) as restart,
            ):
                result = control.apply_sni_route({
                    "action": "add-alias",
                    "revision": before_revision,
                    "system": "reality-xhttp",
                    "sni": "cdn.example.com",
                })

            stored = store.load()
            self.assertTrue(result["changed"])
            self.assertIn("cdn.example.com", stored["sni_routes"]["reality-xhttp"]["aliases"])
            restart.assert_called_once()

    def test_sni_route_apply_rejects_collision_before_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = base_state()
            users_file = root / "users.json"
            atomic_write_json(users_file, state)
            control = KvnControl.__new__(KvnControl)
            control.root = root
            control.kvnctl = kvnctl
            control.StateRevisionConflict = StateRevisionConflict
            control.state_revision = state_revision
            store = JsonStateStore(users_file, root / ".lock")
            before_revision = state_revision(state)

            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all") as render,
                mock.patch.object(kvnctl, "restart_services") as restart,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(ControlError):
                    control.apply_sni_route({
                        "action": "add-alias",
                        "revision": before_revision,
                        "system": "reality-xhttp",
                        "sni": "www.microsoft.com",
                    })

            stored = store.load()
            self.assertNotIn("www.microsoft.com", stored["sni_routes"]["reality-xhttp"]["aliases"])
            render.assert_not_called()
            restart.assert_not_called()


if __name__ == "__main__":
    unittest.main()
