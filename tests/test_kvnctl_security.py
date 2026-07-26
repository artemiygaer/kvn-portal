import copy
import contextlib
import io
import base64
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import kvnctl


def base_state():
    return {
        "server": "203.0.113.10",
        "sni_routes": {
            "tls": {
                "default": "www.microsoft.com",
                "dest": "xray:443",
                "aliases": ["www.microsoft.com"],
            },
            "reality-xhttp": {
                "default": "github.com",
                "dest": "xray:2053",
                "aliases": ["github.com"],
            },
            "reality-tcp": {
                "default": "apple.com",
                "dest": "xray:2054",
                "aliases": ["apple.com"],
            },
            "telemt": {
                "default": "yandex.com",
                "dest": "telemt:3129",
                "aliases": ["yandex.com"],
            },
            "mtg": {
                "default": "ya.ru",
                "dest": "mtg:3128",
                "aliases": ["ya.ru"],
            },
            "custom": [],
        },
        "users": [
            {
                "name": "Alice",
                "uuid": "18f0bddd-8871-4ba5-98c3-5aefb29732e0",
                "hysteria_password": "StrongPass123",
                "telemt_secret": "ebe46ad6c9458f8c5a57922f8d28fe38",
                "enabled": True,
                "description": "",
                "systems": ["tls", "reality-xhttp", "reality-tcp", "telemt", "mtg"],
                "sni_overrides": {},
            }
        ],
    }


class KvnctlSecurityTests(unittest.TestCase):
    def assert_raises_quietly(self, func, *args):
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                func(*args)

    def test_write_qr_png_keeps_existing_file_when_qrencode_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            qr_path = Path(tmp) / "amneziawg.png"
            qr_path.write_bytes(b"old-qr")

            with mock.patch("tools.kvnctl.shutil.which", return_value=None):
                self.assertFalse(kvnctl.write_qr_png("client config", qr_path))

            self.assertEqual(qr_path.read_bytes(), b"old-qr")

    def test_generate_cert_removes_temporary_openssl_config(self):
        completed = subprocess.CompletedProcess(["openssl"], 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            cert_dir = Path(tmp) / "certs"
            with mock.patch("tools.kvnctl.subprocess.run", return_value=completed):
                kvnctl.generate_cert(cert_dir, "203.0.113.10")

            self.assertFalse((cert_dir / "openssl.cnf").exists())

    def test_xray_user_stats_are_minimal_and_access_log_stays_disabled(self):
        state = base_state()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            with mock.patch.object(kvnctl, "XRAY_CONFIG", config_path):
                kvnctl.render_xray(state)
            config = json.loads(config_path.read_text(encoding="utf-8"))
        level0 = config["policy"]["levels"]["0"]
        self.assertTrue(level0["statsUserUplink"])
        self.assertTrue(level0["statsUserDownlink"])
        self.assertEqual(config["stats"], {})
        self.assertNotIn("access", config["log"])
        self.assertEqual(config["routing"]["domainStrategy"], "IPIfNonMatch")

    def test_sni_probe_has_bounded_safe_result_without_addresses_or_secrets(self):
        unavailable = None
        with mock.patch("tools.kvnctl.socket.getaddrinfo", side_effect=OSError("resolver down")):
            unavailable = kvnctl.probe_sni_target("example.com", timeout=0.5)
        self.assertEqual(unavailable["dns"], "unavailable")
        self.assertEqual(unavailable["tls"], "not_checked")
        self.assertEqual(unavailable["reason"], "dns_unavailable")
        self.assertNotIn("resolver down", str(unavailable))

        class FakeSocket:
            def settimeout(self, _value):
                pass

            def connect(self, _address):
                pass

            def close(self):
                pass

        class FakeTLS:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def do_handshake(self):
                pass

        context = mock.Mock(wrap_socket=mock.Mock(return_value=FakeTLS()))
        with (
            mock.patch("tools.kvnctl.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("203.0.113.7", 443))]),
            mock.patch("tools.kvnctl.socket.socket", return_value=FakeSocket()),
            mock.patch("tools.kvnctl.ssl.create_default_context", return_value=context),
        ):
            available = kvnctl.probe_sni_target("example.com", timeout=0.5)
        self.assertEqual(available["reason"], "ok")
        self.assertEqual(available["addresses"], 1)
        self.assertNotIn("203.0.113.7", str(available))

    @unittest.skipIf(os.name == "nt", "POSIX-права проверяются в WSL/Debian")
    def test_permission_matrix_keeps_secrets_private_and_portal_runtime_group_readable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            users = root / "users.json"
            users.write_text("{}", encoding="utf-8")
            runtime = root / "portal-runtime" / "users.json"
            runtime.parent.mkdir(parents=True)
            runtime.write_text("{}", encoding="utf-8")
            clients = root / "clients" / "alice"
            clients.mkdir(parents=True)
            (clients / "config.txt").write_text("private", encoding="utf-8")
            links = root / "CLIENT_LINKS.md"
            links.write_text("private", encoding="utf-8")
            paths = {
                "xray": root / "xray" / "config.json",
                "hy2": root / "hy2" / "config.yaml",
                "telemt": root / "telemt" / "config.toml",
                "mtg": root / "mtg" / "config.toml",
                "ocserv": root / "ocserv" / "ocserv.conf",
                "ocserv_env": root / "ocserv" / "ocserv.env",
                "ocserv_users": root / "ocserv" / "users.txt",
                "awg": root / "amneziawg" / "awg0.conf",
                "wg": root / "wireguard" / "wg0.conf",
            }
            for path in paths.values():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("private", encoding="utf-8")
            for cert_dir in (root / "certs", root / "site-certs", root / "hy2/certs", root / "ocserv/certs"):
                cert_dir.mkdir(parents=True, exist_ok=True)
                (cert_dir / "server.key").write_text("key", encoding="utf-8")
                (cert_dir / "server.crt").write_text("certificate", encoding="utf-8")
            static = root / "nginx" / "site" / "index.html"
            static.parent.mkdir(parents=True)
            static.write_text("public", encoding="utf-8")

            store = mock.Mock(path=users)
            with (
                mock.patch.object(kvnctl, "ROOT", root),
                mock.patch.object(kvnctl, "USERS_FILE", users),
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "PORTAL_RUNTIME_STATE", runtime),
                mock.patch.object(kvnctl, "CLIENTS_DIR", root / "clients"),
                mock.patch.object(kvnctl, "CLIENT_LINKS_FILE", links),
                mock.patch.object(kvnctl, "XRAY_CONFIG", paths["xray"]),
                mock.patch.object(kvnctl, "HY2_CONFIG", paths["hy2"]),
                mock.patch.object(kvnctl, "TELEMT_CONFIG", paths["telemt"]),
                mock.patch.object(kvnctl, "OCSERV_CONFIG", paths["ocserv"]),
                mock.patch.object(kvnctl, "OCSERV_ENV", paths["ocserv_env"]),
                mock.patch.object(kvnctl, "OCSERV_USERS", paths["ocserv_users"]),
                mock.patch.object(kvnctl, "AMNEZIAWG_CONFIG", paths["awg"]),
                mock.patch.object(kvnctl, "WIREGUARD_CONFIG", paths["wg"]),
                mock.patch.object(kvnctl, "load_state", return_value={"portal": {"enabled": True}}),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                kvnctl.fix_permissions()

            mode = lambda path: stat.S_IMODE(path.stat().st_mode)
            for path in paths.values():
                self.assertEqual(mode(path), 0o600, path)
            for cert_dir in (root / "certs", root / "site-certs", root / "hy2/certs", root / "ocserv/certs"):
                self.assertEqual(mode(cert_dir / "server.key"), 0o600)
                self.assertEqual(mode(cert_dir / "server.crt"), 0o644)
            self.assertEqual(mode(users), 0o600)
            self.assertEqual(mode(runtime), 0o640)
            self.assertEqual(mode(clients / "config.txt"), 0o600)
            self.assertEqual(mode(static), 0o644)

    def test_write_qr_png_keeps_existing_file_on_qrencode_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            qr_path = Path(tmp) / "amneziawg.png"
            qr_path.write_bytes(b"old-qr")

            def fake_run(cmd, **kwargs):
                Path(cmd[4]).write_bytes(b"partial-qr")
                return subprocess.CompletedProcess(cmd, 1, "", "qrencode failed")

            with (
                mock.patch("tools.kvnctl.shutil.which", return_value="qrencode"),
                mock.patch("tools.kvnctl.subprocess.run", side_effect=fake_run),
            ):
                self.assertFalse(kvnctl.write_qr_png("client config", qr_path))

            self.assertEqual(qr_path.read_bytes(), b"old-qr")
            self.assertFalse((Path(tmp) / ".amneziawg.png.tmp").exists())

    def test_client_renderer_creates_awg_and_happ_qr_from_exact_payloads(self):
        state = base_state()
        user = state["users"][0]
        user["systems"] = ["amneziawg", "wireguard"]
        kvnctl.prepare_state(state)
        public_key, _tcp, _changed = kvnctl.prepare_state(state)
        calls = []
        with tempfile.TemporaryDirectory() as tmp:
            clients = Path(tmp) / "clients"
            links = Path(tmp) / "CLIENT_LINKS.md"

            def fake_qr(text, path):
                calls.append((text, path.name))
                path.write_bytes(b"qr-png")
                return True

            with (
                mock.patch.object(kvnctl, "CLIENTS_DIR", clients),
                mock.patch.object(kvnctl, "CLIENT_LINKS_FILE", links),
                mock.patch.object(kvnctl.shutil, "which", return_value="qrencode"),
                mock.patch.object(kvnctl, "write_qr_png", side_effect=fake_qr),
            ):
                kvnctl.write_client_files(state, public_key)
            user_dir = clients / user["name"]
            happ_url = kvnctl.happ_sub_url(state, user)
            karing_url = kvnctl.karing_sub_url(state, user)
            karing_wg_url = kvnctl.karing_wireguard_sub_url(state, user)
            self.assertEqual((user_dir / "happ-subscription.txt").read_text(encoding="utf-8"), happ_url + "\n")
            self.assertEqual((user_dir / "karing-subscription.txt").read_text(encoding="utf-8"), karing_url + "\n")
            self.assertEqual((user_dir / "karing-wireguard.txt").read_text(encoding="utf-8"), karing_wg_url + "\n")
            payloads = {name: text for text, name in calls}
            self.assertEqual(payloads["amneziawg.png"], (user_dir / "amneziawg.conf").read_text(encoding="utf-8"))
            self.assertEqual(payloads["wireguard.png"], (user_dir / "wireguard.conf").read_text(encoding="utf-8"))
            self.assertEqual(payloads["happ-subscription.png"], happ_url)
            self.assertEqual(payloads["karing-subscription.png"], karing_url)
            self.assertEqual(payloads["karing-wireguard.png"], karing_wg_url)
            wireguard_conf = (user_dir / "wireguard.conf").read_text(encoding="utf-8")
            karing_wireguard = (user_dir / "karing-wireguard.yaml").read_text(encoding="utf-8")
            self.assertIn("[Interface]", wireguard_conf)
            self.assertIn("[Peer]", wireguard_conf)
            self.assertIn("Endpoint = 203.0.113.10:51821", wireguard_conf)
            self.assertIn("type: wireguard", karing_wireguard)
            self.assertIn("port: 51821", karing_wireguard)
            self.assertNotIn("51820", karing_wireguard)
            for awg_only in ["Jc =", "Jmin =", "Jmax =", "S1 =", "S2 =", "H1 =", "H2 =", "H3 =", "H4 =", "I1 ="]:
                self.assertNotIn(awg_only, wireguard_conf)
                self.assertNotIn(awg_only, karing_wireguard)

    def test_restart_services_skips_when_generated_files_unchanged(self):
        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl.subprocess.run") as run,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                kvnctl.restart_services(changed=False)

        run.assert_not_called()

    def test_setup_rechecks_amneziawg_package_when_awg_quick_exists(self):
        setup_text = (kvnctl.ROOT / "setup.sh").read_text(encoding="utf-8")
        function_text = setup_text.split("ensure_amneziawg_kernel_module() {", 1)[1].split("\n}\n", 1)[0]

        self.assertIn("Проверяю обновление пакета через apt", function_text)
        self.assertIn("bash ./amneziawg/install-kernel-module.sh", function_text)
        self.assertNotIn('awg-quick найден"\n        return', function_text)

    def test_amneziawg_installer_reboots_only_when_package_changed(self):
        installer = (kvnctl.ROOT / "amneziawg" / "install-kernel-module.sh").read_text(encoding="utf-8")

        self.assertIn("INSTALLED_VERSION_BEFORE=", installer)
        self.assertIn("INSTALLED_VERSION_AFTER=", installer)
        self.assertIn('if [ "$PACKAGE_CHANGED" -eq 1 ]; then', installer)
        self.assertIn("exit 3", installer)
        self.assertTrue(installer.rstrip().endswith("exit 0"))

    def test_amneziawg_enabled_user_is_rendered_as_service_peer(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("amneziawg")

        with tempfile.TemporaryDirectory() as tmp:
            awg_path = Path(tmp) / "awg0.conf"
            with mock.patch("tools.kvnctl.AMNEZIAWG_CONFIG", awg_path):
                kvnctl.ensure_amneziawg_state(state)
                with contextlib.redirect_stdout(io.StringIO()):
                    kvnctl.render_amneziawg(state)

            text = awg_path.read_text(encoding="utf-8")

        self.assertIn("[Peer]", text)
        self.assertIn("# Alice", text)
        self.assertIn(f"AllowedIPs = {user['amneziawg']['address']}", text)
        self.assertIn("iptables -I INPUT 1 -p udp --dport 51820 -j ACCEPT", text)

    def test_wireguard_enabled_user_is_rendered_as_standard_service_peer(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("wireguard")

        with tempfile.TemporaryDirectory() as tmp:
            wg_path = Path(tmp) / "wg0.conf"
            with mock.patch("tools.kvnctl.WIREGUARD_CONFIG", wg_path):
                kvnctl.prepare_state(state)
                with contextlib.redirect_stdout(io.StringIO()):
                    kvnctl.render_wireguard(state)

            text = wg_path.read_text(encoding="utf-8")

        self.assertIn("[Peer]", text)
        self.assertIn("# Alice", text)
        self.assertIn(f"AllowedIPs = {user['wireguard']['address']}", text)
        self.assertIn("iptables -I INPUT 1 -p udp --dport 51821 -j ACCEPT", text)
        self.assertNotIn("Jc =", text)

    def test_amneziawg_peer_present_requires_public_key_and_address(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("amneziawg")
        kvnctl.ensure_amneziawg_state(state)

        awg_user = user["amneziawg"]
        text = "\n".join([
            "[Peer]",
            f"PublicKey = {awg_user['public_key']}",
            f"AllowedIPs = {awg_user['address']}",
        ])

        self.assertTrue(kvnctl.amneziawg_peer_present(text, user))
        self.assertFalse(kvnctl.amneziawg_peer_present(text.replace(awg_user["address"], "10.66.66.99/32"), user))

    def test_amneziawg_runtime_verification_requires_exact_peer_set(self):
        state = base_state()
        state["users"][0]["systems"].append("amneziawg")
        kvnctl.prepare_state(state)
        user = state["users"][0]
        awg_user = user["amneziawg"]
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project.conf"
            host = Path(tmp) / "host.conf"
            with mock.patch.object(kvnctl, "AMNEZIAWG_CONFIG", project):
                kvnctl.render_amneziawg(state)
            host.write_text(project.read_text(encoding="utf-8"), encoding="utf-8")
            dump = (
                "private\tserver-public\t51820\toff\n"
                f"{awg_user['public_key']}\t(hidden)\t(endpoint)\t{awg_user['address']}\t0\t0\t0\toff\n"
            )

            def command(argv, timeout=30):
                if argv[-1] == "dump":
                    return 0, dump, ""
                return 0, "active", ""

            with (
                mock.patch.object(kvnctl, "AMNEZIAWG_CONFIG", project),
                mock.patch.object(kvnctl, "HOST_AMNEZIAWG_CONFIG", host),
                mock.patch.object(kvnctl, "run_command_text", side_effect=command),
                mock.patch.object(kvnctl.shutil, "which", return_value="/usr/bin/awg"),
            ):
                verified = kvnctl.verify_amneziawg_runtime(state)
                mismatch = kvnctl.verify_amneziawg_runtime({**state, "users": []})
            self.assertTrue(verified["ok"])
            self.assertEqual(verified["runtime_peers"], 1)
            self.assertFalse(mismatch["ok"])
            self.assertEqual(mismatch["reason"], "runtime_peer_mismatch")

    def test_amneziawg_expected_peers_tracks_enable_rotate_and_delete(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("amneziawg")
        kvnctl.prepare_state(state)
        original = kvnctl.expected_amneziawg_peers(state)
        self.assertEqual(len(original), 1)
        user["enabled"] = False
        self.assertEqual(kvnctl.expected_amneziawg_peers(state), {})
        user["enabled"] = True
        old_address = user["amneziawg"]["address"]
        user["amneziawg"] = {"private_key": kvnctl.random_wg_private_key(), "address": old_address}
        kvnctl.prepare_state(state)
        rotated = kvnctl.expected_amneziawg_peers(state)
        self.assertEqual(len(rotated), 1)
        self.assertNotEqual(set(original), set(rotated))
        state["users"] = []
        self.assertEqual(kvnctl.expected_amneziawg_peers(state), {})

    def test_amneziawg_host_config_allows_wan_interface_substitution(self):
        project = "PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE\n"
        host = "PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o ens3 -j MASQUERADE\n"

        self.assertTrue(kvnctl.amneziawg_configs_equivalent(project, host))
        self.assertFalse(kvnctl.amneziawg_configs_equivalent(project, host.replace("10.66.66.0/24", "10.77.77.0/24")))

    def test_wireguard_diagnostics_parse_transfer_and_rules(self):
        def command(argv, timeout=30):
            if argv[:4] == ["ip", "-4", "route", "show"]:
                return 0, "default via 203.0.113.1 dev ens3 proto dhcp\n", ""
            if argv[:3] == ["wg", "show", "wg0"]:
                return 0, "pubkey1\t128\t256\n", ""
            if argv[:3] == ["iptables", "-C", "FORWARD"]:
                return 0, "", ""
            if argv[:4] == ["iptables", "-t", "nat", "-C"]:
                return 0, "", ""
            return 1, "", "unexpected"

        with (
            mock.patch.object(kvnctl.shutil, "which", return_value="/usr/bin/tool"),
            mock.patch.object(kvnctl, "run_command_text", side_effect=command),
        ):
            self.assertEqual(kvnctl.default_wan_iface(), "ens3")
            self.assertEqual(kvnctl.wireguard_transfer_stats("wg0")[0], {"pubkey1": (128, 256)})
            self.assertEqual(kvnctl.iptables_wireguard_forward_status("wg0"), "ACCEPT inbound/outbound")
            self.assertEqual(
                kvnctl.iptables_masquerade_status("10.88.88.0/24", "ens3"),
                "MASQUERADE 10.88.88.0/24 -> ens3",
            )

    def test_amneziawg_key_pair_validation(self):
        private_key = kvnctl.random_wg_private_key()
        public_key = kvnctl.wg_public_key(private_key)

        self.assertTrue(kvnctl.amneziawg_key_pair_matches(private_key, public_key))
        self.assertFalse(kvnctl.amneziawg_key_pair_matches(private_key, kvnctl.wg_public_key(kvnctl.random_wg_private_key())))

    def test_decoy_site_uses_configured_site_title(self):
        state = base_state()
        state["site"] = {"title": "Мой узел"}

        html = kvnctl.render_decoy_site_text(state)

        self.assertIn("<title>Мой узел</title>", html)
        self.assertIn("<h1>Мой узел</h1>", html)

    def test_sni_alias_map_routes_default_even_without_alias_duplicate(self):
        state = base_state()
        state["sni_routes"]["tls"]["default"] = "edge.example.com"
        state["sni_routes"]["tls"]["aliases"] = []

        aliases = kvnctl.all_sni_aliases(state)

        self.assertEqual(aliases["edge.example.com"], "xray:443")

    def test_user_sni_overrides_are_routed_only_for_real_per_user_systems(self):
        state = base_state()
        user = state["users"][0]
        user["systems"] = ["tls", "telemt", "hysteria"]
        user["sni_overrides"] = {
            "tls": "edge.example.com",
            "telemt": "mtproto.example.com",
            "hysteria": "hysteria.example.com",
        }

        self.assertTrue(kvnctl.validate_state_inputs(state))
        kvnctl.validate_sni_uniqueness(state)
        aliases = kvnctl.all_sni_aliases(state)
        telemt_secret = kvnctl.telemt_tls_secret(state, user)

        self.assertNotIn("telemt", user["sni_overrides"])
        self.assertEqual(aliases["edge.example.com"], "xray:443")
        self.assertNotIn("mtproto.example.com", aliases)
        self.assertNotIn("hysteria.example.com", aliases)
        self.assertTrue(telemt_secret.endswith("yandex.com".encode("utf-8").hex()))

        with tempfile.TemporaryDirectory() as tmp:
            nginx_conf = Path(tmp) / "nginx.conf"
            telemt_conf = Path(tmp) / "telemt.toml"
            with mock.patch.object(kvnctl, "NGINX_CONFIG", nginx_conf):
                kvnctl.render_nginx(state)
            with mock.patch.object(kvnctl, "TELEMT_CONFIG", telemt_conf):
                kvnctl.render_telemt(state)
            text = nginx_conf.read_text(encoding="utf-8")
            telemt_text = telemt_conf.read_text(encoding="utf-8")
        self.assertNotIn("mtproto.example.com", text)
        self.assertRegex(text, r'"1:edge\.example\.com"\s+backend_xray_443_')
        self.assertIn('tls_domain = "yandex.com"', telemt_text)
        self.assertIn('unknown_sni_action = "mask"', telemt_text)
        self.assertNotIn("mtproto.example.com", telemt_text)
        openssl_config = kvnctl.generate_openssl_config("203.0.113.10", state)
        self.assertIn(" = edge.example.com", openssl_config)
        self.assertIn(" = hysteria.example.com", openssl_config)

    def test_global_telemt_sni_updates_config_route_and_qr_secret(self):
        state = base_state()
        user = state["users"][0]
        user["systems"] = ["telemt"]
        state["sni_routes"]["telemt"]["default"] = "mtproto.example.com"
        state["sni_routes"]["telemt"]["aliases"] = []

        aliases = kvnctl.all_sni_aliases(state)
        telemt_secret = kvnctl.telemt_tls_secret(state, user)

        self.assertEqual(aliases["mtproto.example.com"], "telemt:3129")
        self.assertTrue(telemt_secret.endswith("mtproto.example.com".encode("utf-8").hex()))
        with tempfile.TemporaryDirectory() as tmp:
            telemt_conf = Path(tmp) / "telemt.toml"
            with mock.patch.object(kvnctl, "TELEMT_CONFIG", telemt_conf):
                kvnctl.render_telemt(state)
            telemt_text = telemt_conf.read_text(encoding="utf-8")
        self.assertIn('tls_domain = "mtproto.example.com"', telemt_text)
        self.assertIn('unknown_sni_action = "mask"', telemt_text)

    def test_mtproto_legacy_state_uses_external_origin_and_upstream_mobile_defaults(self):
        state = base_state()
        state["mtg"] = {"secret16": "a" * 32}

        self.assertEqual(kvnctl.mtproto_camouflage_origin(state, "telemt"), "external")
        self.assertEqual(kvnctl.mtproto_camouflage_origin(state, "mtg"), "external")
        telemt = kvnctl.telemt_config_text(state)
        mtg = kvnctl.mtg_config_text(state)

        self.assertIn("secure = true", telemt)
        self.assertIn("me_keepalive_interval_secs = 8", telemt)
        self.assertIn("me_reconnect_backoff_cap_ms = 30000", telemt)
        self.assertIn("client_keepalive = 15", telemt)
        self.assertIn("replay_check_len = 65536", telemt)
        self.assertIn("show = []", telemt)
        self.assertNotIn('mask_host = "nginx"', telemt)
        self.assertIn('idle = "5m"', mtg)
        self.assertIn('interval = "15s"', mtg)
        self.assertIn("count = 9", mtg)
        self.assertIn("[defense.anti-replay]", mtg)
        self.assertIn("port = 443", mtg)
        self.assertTrue(kvnctl.tomllib.loads(telemt))
        self.assertTrue(kvnctl.tomllib.loads(mtg))

    def test_mtproto_local_site_uses_internal_8443_and_excludes_public_site_route(self):
        state = base_state()
        state["mtg"] = {"secret16": "a" * 32, "camouflage_origin": "local-site"}
        state["telemt"] = {"extra_users": {}, "camouflage_origin": "local-site"}
        state["sni_routes"]["telemt"] = {
            "default": "telemt.example.test", "dest": "telemt:3129",
            "aliases": ["telemt.example.test"],
        }
        state["sni_routes"]["mtg"] = {
            "default": "mtg.example.test", "dest": "mtg:3128",
            "aliases": ["mtg.example.test"],
        }
        state["letsencrypt"] = {
            "enabled": True, "domain": "site.example.test",
            "domains": ["site.example.test", "telemt.example.test", "mtg.example.test"],
        }

        self.assertIn('mask_host = "nginx"', kvnctl.telemt_config_text(state))
        self.assertIn("mask_port = 8443", kvnctl.telemt_config_text(state))
        self.assertIn("port = 8443", kvnctl.mtg_config_text(state))
        self.assertEqual(kvnctl.mtg_compose_alias(state), "mtg.example.test")
        self.assertEqual(kvnctl.site_domains(state), ["site.example.test"])
        aliases = kvnctl.all_sni_aliases(state)
        self.assertEqual(aliases["telemt.example.test"], "telemt:3129")
        self.assertEqual(aliases["mtg.example.test"], "mtg:3128")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mtg").mkdir()
            (root / ".env").write_text("KVN_PORTAL_PORT=8444\n", encoding="utf-8")
            with mock.patch.object(kvnctl, "ROOT", root):
                kvnctl.render_mtg(state)
            env = (root / ".env").read_text(encoding="utf-8")
        self.assertIn("KVN_PORTAL_PORT=8444", env)
        self.assertIn("KVN_MTG_CAMOUFLAGE_HOST=mtg.example.test", env)

    def test_mtproto_diagnosis_is_bounded_redacted_and_detects_static_errors(self):
        state = base_state()
        state["mtg"] = {"secret16": "a" * 32, "camouflage_origin": "local-site"}
        state["sni_routes"]["mtg"] = {
            "default": "mtg.example.test", "dest": "mtg:3128",
            "aliases": ["mtg.example.test"],
        }
        with (
            mock.patch.object(kvnctl, "probe_sni_target", return_value={"dns": "ok", "tls": "ok", "reason": "ok"}),
            mock.patch.object(kvnctl, "bounded_resolve_addresses", return_value=("ok", {"203.0.113.10"})),
            mock.patch.object(kvnctl, "certificate_sans", return_value=["mtg.example.test"]),
        ):
            ready = kvnctl.mtproto_diagnose(state, "mtg", timeout=0.5, runtime_checks=False)
        self.assertTrue(ready["can_apply"])
        self.assertEqual(ready["target"], "nginx:8443")
        self.assertLessEqual(ready["timeout_seconds"], 0.5)
        rendered = str(ready)
        self.assertNotIn("a" * 32, rendered)
        self.assertNotIn("203.0.113.10", rendered)

        state["sni_routes"]["tls"]["aliases"].append("mtg.example.test")
        with (
            mock.patch.object(kvnctl, "probe_sni_target", return_value={"dns": "unavailable", "tls": "not_checked"}),
            mock.patch.object(kvnctl, "bounded_resolve_addresses", return_value=("unavailable", set())),
            mock.patch.object(kvnctl, "certificate_sans", return_value=[]),
        ):
            failed = kvnctl.mtproto_diagnose(state, "mtg", timeout=0.5, runtime_checks=False)
        self.assertFalse(failed["can_apply"])
        self.assertIn("route_collision", failed["errors"])
        self.assertIn("certificate_san", failed["errors"])
        self.assertIn("dns", failed["warnings"])

    def test_telegram_links_keep_public_faketls_and_direct_secure_scope(self):
        state = base_state()
        state["mtg"] = {"secret16": "b" * 32}
        user = state["users"][0]
        public = kvnctl.telemt_link(state, user)
        secure = kvnctl.telemt_secure_link(state, user)
        shared = kvnctl.mtg_link(state)

        self.assertIn("port=443", public)
        self.assertIn("secret=ee", public)
        self.assertIn("port=2446", secure)
        self.assertIn("secret=dd", secure)
        self.assertIn("port=443", shared)
        self.assertIn("secret=ee", shared)
        self.assertIn("общий endpoint/secret", kvnctl.mtg_client_text(state))

    def test_sni_collision_is_fatal(self):
        state = base_state()
        state["sni_routes"]["reality-xhttp"]["aliases"].append("www.microsoft.com")

        self.assert_raises_quietly(kvnctl.validate_sni_uniqueness, state)

    def test_custom_route_dest_collision_is_fatal(self):
        state = base_state()
        state["sni_routes"]["custom"].append({"sni": "github.com", "dest": "mtg:3128"})

        self.assert_raises_quietly(kvnctl.validate_sni_uniqueness, state)

    def test_unregistered_reality_user_sni_is_rejected(self):
        state = base_state()
        state["users"][0]["sni_overrides"] = {"reality-xhttp": "www.github.com"}

        self.assert_raises_quietly(kvnctl.validate_sni_uniqueness, state)

    def test_registered_reality_user_sni_is_routed_and_accepted(self):
        state = base_state()
        user = state["users"][0]
        state["sni_routes"]["reality-xhttp"]["aliases"].append("cdn.example.com")
        user["sni_overrides"] = {"reality-xhttp": "cdn.example.com"}

        kvnctl.validate_sni_uniqueness(state)
        aliases = kvnctl.all_sni_aliases(state)

        self.assertEqual(aliases["cdn.example.com"], "xray:2053")
        self.assertIn("cdn.example.com", kvnctl.reality_xhttp_server_names(state))

    def test_prepare_state_removes_unsupported_legacy_user_sni_overrides(self):
        state = base_state()
        user = state["users"][0]
        user["sni_overrides"] = {
            "tls": "edge.example.com",
            "telemt": "mtproto.example.com",
            "reality-xhttp": "www.github.com",
            "mtg": "fake.example.com",
        }

        kvnctl.prepare_state(state)

        self.assertEqual(
            user["sni_overrides"],
            {"tls": "edge.example.com", "reality-xhttp": "www.github.com"},
        )
        self.assertIn("www.github.com", state["sni_routes"]["reality-xhttp"]["aliases"])

    def test_prepare_state_preserves_manual_tls_and_hysteria_sni_with_device_profile(self):
        state = base_state()
        user = state["users"][0]
        user["systems"] = ["tls", "hysteria"]
        user["device"] = "ios"
        user["sni_overrides"] = {
            "tls": "edge.example.com",
            "hysteria": "hysteria.example.com",
        }

        kvnctl.prepare_state(state)

        self.assertEqual(
            user["sni_overrides"],
            {"tls": "edge.example.com", "hysteria": "hysteria.example.com"},
        )

    def test_validate_state_rejects_control_chars_in_description(self):
        state = base_state()
        state["users"][0]["description"] = "ops\x1b[31m"

        self.assert_raises_quietly(kvnctl.validate_state_inputs, state)

    def test_validate_state_rejects_short_hysteria_password(self):
        state = base_state()
        state["users"][0]["hysteria_password"] = "short"

        self.assert_raises_quietly(kvnctl.validate_state_inputs, state)

    def test_valid_state_passes_security_validation(self):
        state = copy.deepcopy(base_state())

        kvnctl.validate_state_inputs(state)
        kvnctl.validate_sni_uniqueness(state)

        self.assertEqual(state["server"], "203.0.113.10")

    def test_validate_state_rejects_duplicate_user_names(self):
        state = base_state()
        duplicate = copy.deepcopy(state["users"][0])
        duplicate["uuid"] = "891352d7-868b-4155-a62e-5e66c1bed253"
        duplicate["name"] = "alice"
        state["users"].append(duplicate)

        self.assert_raises_quietly(kvnctl.validate_state_inputs, state)

    def test_validate_state_rejects_unknown_user_system(self):
        state = base_state()
        state["users"][0]["systems"].append("shadowtls")

        self.assert_raises_quietly(kvnctl.validate_state_inputs, state)

    def test_validate_state_rejects_invalid_subscription_token(self):
        state = base_state()
        state["users"][0]["sub_token"] = "../not-a-token"

        self.assert_raises_quietly(kvnctl.validate_state_inputs, state)

    def test_subscription_port_cannot_conflict_with_sni_router(self):
        state = base_state()
        state["subscription"] = {"enabled": True, "port": 443}

        self.assert_raises_quietly(kvnctl.sub_config, state)

    def test_letsencrypt_domain_routes_to_https_site(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}
        state["sni_routes"]["tls"]["aliases"].append("vpn.example.com")

        changed = kvnctl.validate_state_inputs(state)
        aliases = kvnctl.all_sni_aliases(state)

        self.assertTrue(changed)
        self.assertNotIn("vpn.example.com", state["sni_routes"]["tls"]["aliases"])
        self.assertEqual(aliases["vpn.example.com"], "127.0.0.1:8443")

    def test_nginx_render_exposes_http_health_for_domain_checks(self):
        state = base_state()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nginx_conf = root / "nginx.conf"
            portal_gateway = root / "portal-gateway.conf"
            with (
                mock.patch.object(kvnctl, "NGINX_CONFIG", nginx_conf),
                mock.patch.object(kvnctl, "PORTAL_GATEWAY_CONFIG", portal_gateway),
            ):
                kvnctl.render_nginx(state)

            text = nginx_conf.read_text(encoding="utf-8")

        self.assertIn("listen 80 default_server", text)
        self.assertIn('return 200 "ok\\n"', text)
        self.assertIn("return 301 https://$host$request_uri", text)

    def test_service_cert_keeps_camouflage_cn_when_letsencrypt_enabled(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}

        config = kvnctl.generate_openssl_config("203.0.113.10", state)

        self.assertIn("CN = www.microsoft.com", config)
        self.assertIn(" = www.microsoft.com", config)
        self.assertNotIn("CN = vpn.example.com", config)

    def test_site_cert_fallback_uses_letsencrypt_domain_in_san_and_cn(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}

        config = kvnctl.generate_openssl_config("203.0.113.10", state, site_domain="vpn.example.com")

        self.assertIn("CN = vpn.example.com", config)
        self.assertIn("DNS.", config)
        self.assertIn(" = vpn.example.com", config)
        self.assertNotIn(" = www.microsoft.com", config)

    def test_happ_uri_subscription_contains_tls_as_last_fallback(self):
        systems = ["tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg", "amneziawg"]

        self.assertEqual(
            kvnctl.preferred_uri_systems(systems),
            ["hysteria", "reality-tcp", "reality-xhttp", "tls"],
        )
        self.assertEqual(
            kvnctl.karing_uri_systems(systems),
            ["hysteria", "reality-tcp", "reality-xhttp", "tls"],
        )

    def test_legacy_reality_uri_and_payload_match_golden_fixture(self):
        state = base_state()
        user = state["users"][0]
        expected_tcp = (
            "vless://18f0bddd-8871-4ba5-98c3-5aefb29732e0@203.0.113.10:443?"
            "type=tcp&security=reality&encryption=none&sni=apple.com&fp=chrome&pbk=pubkey&"
            "sid=e7a4b2c91f5d8e30&flow=xtls-rprx-vision#KVN-Alice-Reality-TCP"
        )
        expected_xhttp = (
            "vless://18f0bddd-8871-4ba5-98c3-5aefb29732e0@203.0.113.10:443?"
            "type=xhttp&security=reality&encryption=none&sni=github.com&fp=chrome&pbk=pubkey&"
            "sid=a3f9c1b82d4e6f90&path=%2Fapi%2Fv1%2Fdata&mode=stream-one#KVN-Alice-Reality"
        )
        expected_tls = (
            "vless://18f0bddd-8871-4ba5-98c3-5aefb29732e0@203.0.113.10:443?"
            "type=tcp&security=tls&encryption=none&flow=xtls-rprx-vision&"
            "sni=www.microsoft.com&fp=chrome#KVN-Alice-TLS"
        )
        expected_raw = "\n".join((expected_tcp, expected_xhttp, expected_tls)) + "\n"

        with mock.patch.object(kvnctl, "certificate_sha256_hex", return_value=None):
            self.assertEqual(kvnctl.vless_reality_tcp_link(state, user, "pubkey"), expected_tcp)
            self.assertEqual(kvnctl.vless_reality_link(state, user, "pubkey"), expected_xhttp)
            self.assertEqual(kvnctl.subscription_raw_txt(state, user, "pubkey"), expected_raw)
            expected_payload = base64.b64encode(expected_raw.encode("utf-8")).decode("ascii")
            self.assertEqual(kvnctl.legacy_subscription_txt(state, user, "pubkey"), expected_payload)
            self.assertEqual(kvnctl.subscription_txt(state, user, "pubkey"), expected_payload)

    def test_reality_xhttp_server_and_clients_share_transport_parameters(self):
        state = base_state()
        user = state["users"][0]
        public_key, _tcp_key, _changed = kvnctl.prepare_state(state)

        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            with mock.patch.object(kvnctl, "XRAY_CONFIG", config_path):
                kvnctl.render_xray(state)
            server = json.loads(config_path.read_text(encoding="utf-8"))

        inbound = next(item for item in server["inbounds"] if item["tag"] == kvnctl.REALITY_XHTTP_INBOUND_TAG)
        stream = inbound["streamSettings"]
        client = kvnctl.client_json_reality(state, user, public_key)
        link = kvnctl.vless_reality_link(state, user, public_key)
        self.assertEqual(stream["network"], client["streamSettings"]["network"])
        self.assertEqual(stream["security"], client["streamSettings"]["security"])
        self.assertEqual(stream["xhttpSettings"]["path"], client["streamSettings"]["xhttpSettings"]["path"])
        self.assertEqual(stream["xhttpSettings"]["mode"], client["streamSettings"]["xhttpSettings"]["mode"])
        self.assertIn(f"sni={kvnctl.user_sni(user, 'reality-xhttp', state)}", link)
        self.assertIn(f"pbk={public_key}", link)
        self.assertIn(f"sid={state['reality']['short_id']}", link)

    def test_named_subscription_urls_cover_domain_ip_custom_port_and_portal_path(self):
        state = base_state()
        user = state["users"][0]
        user["sub_token"] = "0123456789abcdef0123456789abcdef"
        state["portal"] = {"enabled": True, "domain": "portal.example.com", "path": "/private/control"}
        state["subscription"] = {
            "enabled": True,
            "port": 2096,
            "public_host": "cfg.example.com",
            "public_port": 8443,
        }

        self.assertEqual(
            kvnctl.happ_sub_url(state, user),
            "https://cfg.example.com:8443/happ/0123456789abcdef0123456789abcdef",
        )
        self.assertEqual(
            kvnctl.karing_sub_url(state, user),
            "https://cfg.example.com:8443/karing/0123456789abcdef0123456789abcdef",
        )
        self.assertEqual(
            kvnctl.named_sub_url(state, user, "karing-wg", direct=True),
            "https://203.0.113.10:2096/karing-wg/0123456789abcdef0123456789abcdef",
        )
        self.assertNotIn("/private/control", kvnctl.happ_sub_url(state, user))

        state["subscription"].pop("public_host")
        state["subscription"].pop("public_port")
        self.assertEqual(
            kvnctl.karing_wireguard_sub_url(state, user),
            "https://203.0.113.10:2096/karing-wg/0123456789abcdef0123456789abcdef",
        )

    def test_karing_payload_and_wireguard_profile_exclude_amneziawg(self):
        state = base_state()
        user = state["users"][0]
        user["systems"] = ["tls", "reality-xhttp", "reality-tcp", "hysteria", "amneziawg", "wireguard"]
        kvnctl.prepare_state(state)

        decoded = base64.b64decode(kvnctl.karing_subscription_txt(state, user, "pubkey")).decode("utf-8")
        profile = kvnctl.karing_wireguard_yaml(state, user)
        self.assertIn("type=tcp&security=reality", decoded)
        self.assertIn("hysteria2://", decoded)
        self.assertIn("type=xhttp", decoded)
        self.assertNotIn("amnezia", decoded.lower())
        self.assertEqual(kvnctl.wireguard_config(state)["interface"], "wg0")
        self.assertEqual(kvnctl.wireguard_config(state)["port"], 51821)
        self.assertIn("type: wireguard", profile)
        self.assertIn("port: 51821", profile)
        self.assertNotIn("port: 51820", profile)
        self.assertNotIn(user["amneziawg"]["private_key"], profile)

    def test_subscription_web_render_keeps_legacy_and_writes_named_profiles(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].extend(["hysteria", "wireguard"])
        user["sub_token"] = "0123456789abcdef0123456789abcdef"
        state["subscription"] = {"enabled": True, "port": 2096}
        public_key, _tcp_key, _changed = kvnctl.prepare_state(state)

        with tempfile.TemporaryDirectory() as tmp:
            web = Path(tmp) / "web"
            with mock.patch.object(kvnctl, "SUB_WEB_DIR", web):
                kvnctl.write_sub_web(state, public_key)
                token = user["sub_token"]
                self.assertEqual((web / token).read_text(encoding="utf-8"), kvnctl.subscription_txt(state, user, public_key))
                self.assertEqual((web / "happ" / token).read_text(encoding="utf-8"), kvnctl.happ_subscription_txt(state, user, public_key))
                self.assertEqual((web / "karing" / token).read_text(encoding="utf-8"), kvnctl.karing_subscription_txt(state, user, public_key))
                self.assertIn("port: 51821", (web / "karing-wg" / token).read_text(encoding="utf-8"))

                user["systems"].remove("wireguard")
                kvnctl.write_sub_web(state, public_key)
                self.assertFalse((web / "karing-wg" / token).exists())

    def test_nginx_subscription_blocks_allow_only_legacy_and_named_token_paths(self):
        state = base_state()
        state["subscription"] = {"enabled": True, "port": 2096}
        direct = kvnctl.sub_server_block(state)
        public = kvnctl.decoy_server_block(state)

        for rendered in (direct, public):
            self.assertIn("(?:happ|karing|karing-wg)", rendered)
            self.assertIn("[0-9a-f]{32}", rendered)
            self.assertIn("try_files $uri =404", rendered)

    def test_happ_url_subscription_payload_includes_tls_uri(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("hysteria")

        payload = base64.b64decode(kvnctl.subscription_txt(state, user, "pubkey")).decode("utf-8")
        lines = [line for line in payload.splitlines() if line]

        self.assertEqual(len(lines), 4)
        self.assertIn("security=tls", lines[-1])
        self.assertIn("sni=www.microsoft.com", lines[-1])

    def test_happ_subscription_uses_selected_user_sni_choices(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("hysteria")
        state["sni_routes"]["tls"]["aliases"].append("edge.example.com")
        state["sni_routes"]["reality-xhttp"]["aliases"].append("cdn.example.com")
        state["sni_routes"]["reality-tcp"]["aliases"].append("tcp.example.com")
        state["sni_routes"]["hysteria"] = {
            "default": "www.apple.com",
            "dest": "hysteria:443",
            "aliases": ["hysteria.example.com"],
        }
        user["sni_overrides"] = {
            "tls": "edge.example.com",
            "reality-xhttp": "cdn.example.com",
            "reality-tcp": "tcp.example.com",
            "hysteria": "hysteria.example.com",
        }
        kvnctl.prepare_state(state)

        payload = base64.b64decode(kvnctl.subscription_txt(state, user, "pubkey")).decode("utf-8")

        self.assertIn("sni=hysteria.example.com", payload)
        self.assertIn("sni=tcp.example.com", payload)
        self.assertIn("sni=cdn.example.com", payload)
        self.assertIn("sni=edge.example.com", payload)

    def test_vless_tls_clients_use_browser_tls_fingerprint(self):
        state = base_state()
        user = state["users"][0]

        link = kvnctl.vless_tls_link(state, user)
        xray_json = kvnctl.client_json_tls(state, user)
        singbox = kvnctl.singbox_subscription(state, user, "pubkey")
        tls_outbound = next(outbound for outbound in singbox["outbounds"] if outbound["tag"] == "VLESS-TLS")

        self.assertIn("fp=chrome", link)
        self.assertEqual(xray_json["streamSettings"]["tlsSettings"]["fingerprint"], "chrome")
        self.assertEqual(tls_outbound["tls"]["utls"]["fingerprint"], "chrome")

    def test_vless_tls_clients_use_xray_routed_sni_not_site_domain(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}
        user = state["users"][0]

        link = kvnctl.vless_tls_link(state, user)
        xray_json = kvnctl.client_json_tls(state, user)
        singbox = kvnctl.singbox_subscription(state, user, "pubkey")
        tls_outbound = next(outbound for outbound in singbox["outbounds"] if outbound["tag"] == "VLESS-TLS")

        self.assertIn("sni=www.microsoft.com", link)
        self.assertEqual(xray_json["streamSettings"]["tlsSettings"]["serverName"], "www.microsoft.com")
        self.assertEqual(tls_outbound["tls"]["server_name"], "www.microsoft.com")

    def test_reality_tcp_client_json_uses_vision_flow(self):
        state = base_state()
        user = state["users"][0]

        xray_json = kvnctl.client_json_reality_tcp(state, user, "pubkey")
        client = xray_json["vnext"][0]["users"][0]

        self.assertEqual(client["flow"], "xtls-rprx-vision")

    def test_telegram_proxy_qr_files_are_generated(self):
        state = base_state()
        user = state["users"][0]
        user["systems"] = ["telemt", "mtg"]
        state["subscription"] = {"enabled": True, "domain": "sub.example.com", "port": 2096}
        state["mtg"] = {"secret16": "a" * 32}
        calls = {}

        def fake_qr(payload, path):
            calls[path.name] = payload
            path.write_bytes(b"png")
            return True

        with tempfile.TemporaryDirectory() as tmp:
            clients_dir = Path(tmp) / "clients"
            links_file = Path(tmp) / "CLIENT_LINKS.md"
            with (
                mock.patch.object(kvnctl, "CLIENTS_DIR", clients_dir),
                mock.patch.object(kvnctl, "CLIENT_LINKS_FILE", links_file),
                mock.patch.object(kvnctl.shutil, "which", return_value="/usr/bin/qrencode"),
                mock.patch.object(kvnctl, "write_qr_png", side_effect=fake_qr),
            ):
                kvnctl.write_client_files(state, "pubkey")

            self.assertIn("telemt.png", calls)
            self.assertIn("mtg.png", calls)
            self.assertIn("happ-subscription.png", calls)
            self.assertTrue(calls["telemt.png"].startswith("tg://proxy?"))
            self.assertTrue(calls["mtg.png"].startswith("tg://proxy?"))
            user_dir = clients_dir / state["users"][0]["name"]
            telemt_text = (user_dir / "telemt.txt").read_text(encoding="utf-8")
            mtg_text = (user_dir / "mtg.txt").read_text(encoding="utf-8")
            combined_text = (user_dir / "telegram-proxy.txt").read_text(encoding="utf-8")
            self.assertIn("Telemt MTProto TLS", telemt_text)
            self.assertIn("MTProto mtg FakeTLS", mtg_text)
            self.assertIn("Telemt MTProto TLS", combined_text)
            self.assertIn("MTProto mtg FakeTLS", combined_text)
            self.assertIn("secret:", combined_text)

    def test_ocserv_can_claim_custom_sni_on_443_when_enabled(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}
        state["ocserv"] = {"enabled": True, "sni_enabled": True, "sni": "vpn.example.com"}
        state["users"][0]["systems"].append("ocserv")
        state["users"][0]["ocserv_password"] = "OpenConnect123"

        kvnctl.validate_state_inputs(state)
        kvnctl.validate_sni_uniqueness(state)
        aliases = kvnctl.all_sni_aliases(state)

        self.assertEqual(aliases["vpn.example.com"], "ocserv:443")
        self.assertNotEqual(aliases["vpn.example.com"], "xray:443")

    def test_ocserv_separate_sni_keeps_site_domain_for_site(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}
        state["ocserv"] = {"enabled": True, "sni_enabled": True, "sni": "ocgerv.example.com"}
        user = state["users"][0]
        user["systems"].append("ocserv")
        user["ocserv_password"] = "OpenConnect123"

        kvnctl.validate_state_inputs(state)
        kvnctl.validate_sni_uniqueness(state)
        aliases = kvnctl.all_sni_aliases(state)
        client = kvnctl.openconnect_client_text(state, user)

        self.assertEqual(aliases["vpn.example.com"], "127.0.0.1:8443")
        self.assertEqual(aliases["ocgerv.example.com"], "ocserv:443")
        self.assertIn("https://ocgerv.example.com:443/", client)
        self.assertNotIn("--sni=icloud.apple.com", client)

    def test_extra_site_domains_and_public_subscription_host_route_to_site(self):
        state = base_state()
        state["server"] = "gaer.duckdns.org"
        state["subscription"] = {
            "enabled": True,
            "port": 2096,
            "public_host": "cfg.gaer.loc.cc",
            "public_port": 443,
        }
        state["letsencrypt"] = {
            "enabled": True,
            "domain": "gaer.duckdns.org",
            "domains": ["gaer.duckdns.org", "www.gaer.loc.cc", "cfg.gaer.loc.cc"],
        }
        user = state["users"][0]
        user["sub_token"] = "0123456789abcdef0123456789abcdef"

        kvnctl.validate_state_inputs(state)
        aliases = kvnctl.all_sni_aliases(state)

        self.assertEqual(aliases["gaer.duckdns.org"], "127.0.0.1:8443")
        self.assertEqual(aliases["www.gaer.loc.cc"], "127.0.0.1:8443")
        self.assertEqual(aliases["cfg.gaer.loc.cc"], "127.0.0.1:8443")
        self.assertEqual(kvnctl.sub_url(state, user), "https://cfg.gaer.loc.cc/0123456789abcdef0123456789abcdef")
        self.assertIn("https://gaer.duckdns.org:2096/0123456789abcdef0123456789abcdef", kvnctl.sub_urls(state, user))

    def test_ocserv_primary_sni_and_legacy_front_sni_route_to_ocserv(self):
        state = base_state()
        state["ocserv"] = {
            "enabled": True,
            "sni_enabled": True,
            "sni": "ocserv.gaer.loc.cc",
            "front_snis": ["ocgerv.duckdns.org"],
        }
        user = state["users"][0]
        user["systems"].append("ocserv")
        user["ocserv_password"] = "OpenConnect123"

        kvnctl.validate_state_inputs(state)
        kvnctl.validate_sni_uniqueness(state)
        aliases = kvnctl.all_sni_aliases(state)
        client = kvnctl.openconnect_client_text(state, user)

        self.assertEqual(aliases["ocserv.gaer.loc.cc"], "ocserv:443")
        self.assertEqual(aliases["ocgerv.duckdns.org"], "ocserv:443")
        self.assertIn("https://ocserv.gaer.loc.cc:443/", client)
        self.assertIn("https://ocgerv.duckdns.org:443/", client)

    def test_letsencrypt_target_domains_use_site_and_ocserv_config(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {
            "enabled": True,
            "domain": "vpn.example.com",
            "domains": ["vpn.example.com", "www.example.com"],
        }
        state["ocserv"] = {
            "enabled": True,
            "sni_enabled": True,
            "sni": "oc.example.com",
            "front_snis": ["legacy.example.com"],
        }

        self.assertEqual(kvnctl.letsencrypt_target_domains(state, "site"), ["vpn.example.com", "www.example.com"])
        self.assertEqual(kvnctl.letsencrypt_target_domains(state, "ocserv"), ["oc.example.com", "legacy.example.com"])

    def test_explicit_letsencrypt_issue_replaces_old_site_sans(self):
        state = base_state()
        state["server"] = "tst.gaer.loc.cc"
        state["letsencrypt"] = {
            "enabled": True,
            "domain": "tst.gaer.loc.cc",
            "domains": ["tst.gaer.loc.cc", "cfg2.gaer.loc.cc"],
        }

        changed = kvnctl.configure_letsencrypt_state(state, ["gaer.loc.cc"])

        self.assertTrue(changed)
        self.assertEqual(state["server"], "gaer.loc.cc")
        self.assertEqual(state["letsencrypt"]["domain"], "gaer.loc.cc")
        self.assertEqual(state["letsencrypt"]["domains"], ["gaer.loc.cc"])
        self.assertEqual(kvnctl.letsencrypt_target_domains(state, "site"), ["gaer.loc.cc"])

    def test_manual_site_issue_keeps_portal_domain_in_san(self):
        state = base_state()
        state["server"] = "old.gaer.loc.cc"
        state["letsencrypt"] = {
            "enabled": True,
            "domain": "old.gaer.loc.cc",
            "domains": ["old.gaer.loc.cc", "cfg2.gaer.loc.cc"],
        }
        state["portal"] = {
            "enabled": True,
            "domain": "ztv.gaer.loc.cc",
            "port": 8443,
            "path": "/gaer",
        }

        domains = kvnctl.site_issue_domains(state, ["gaer.loc.cc"])
        changed = kvnctl.configure_letsencrypt_state(state, domains)

        self.assertTrue(changed)
        self.assertEqual(domains, ["gaer.loc.cc", "ztv.gaer.loc.cc"])
        self.assertEqual(state["letsencrypt"]["domain"], "gaer.loc.cc")
        self.assertEqual(state["letsencrypt"]["domains"], ["gaer.loc.cc", "ztv.gaer.loc.cc"])
        self.assertEqual(kvnctl.letsencrypt_target_domains(state, "site"), ["gaer.loc.cc", "ztv.gaer.loc.cc"])

    def test_letsencrypt_target_domains_skip_private_tlds_but_keep_portal(self):
        state = base_state()
        state["server"] = "tst.gaer.loc"
        state["letsencrypt"] = {
            "enabled": True,
            "domain": "tst.gaer.loc",
            "domains": ["tst.gaer.loc", "cfg2.gaer.loc.cc"],
        }
        state["portal"] = {"enabled": True, "domain": "tst.gaer.loc.cc", "port": 8443, "path": "/gaer"}

        self.assertEqual(
            kvnctl.letsencrypt_target_domains(state, "site"),
            ["cfg2.gaer.loc.cc", "tst.gaer.loc.cc"],
        )

    def test_run_certbot_issue_force_renewal_flag(self):
        completed = subprocess.CompletedProcess(["certbot"], 0, "", "")

        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="/usr/bin/certbot"),
            mock.patch("tools.kvnctl.subprocess.run", return_value=completed) as run,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                kvnctl.run_certbot_issue(["vpn.example.com"], force_renewal=True)

        command = run.call_args.args[0]
        self.assertIn("--force-renewal", command)
        self.assertNotIn("--keep-until-expiring", command)

    def test_letsencrypt_renew_temporarily_frees_http_port(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}
        completed = subprocess.CompletedProcess(["certbot"], 0, "", "")
        args = kvnctl.argparse.Namespace(action="renew", target="site", restart=False)

        with (
            mock.patch("tools.kvnctl.load_state", return_value=state),
            mock.patch("tools.kvnctl.shutil.which", return_value="/usr/bin/certbot"),
            mock.patch("tools.kvnctl.subprocess.run", return_value=completed) as run,
            mock.patch("tools.kvnctl._stop_docker_service_best_effort", return_value=True) as stop,
            mock.patch("tools.kvnctl._start_docker_service_best_effort", return_value=True) as start,
            mock.patch("tools.kvnctl.existing_letsencrypt_live_domain", return_value=None),
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                kvnctl.cmd_letsencrypt(args)

        stop.assert_called_once_with("nginx")
        self.assertEqual(run.call_args.args[0], ["certbot", "renew", "--non-interactive"])
        start.assert_called_once_with("nginx")

    def test_ocserv_no_sni_mode_keeps_letsencrypt_domain_for_site(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["letsencrypt"] = {"enabled": True, "domain": "vpn.example.com"}
        state["ocserv"] = {"enabled": True, "sni_enabled": False}

        kvnctl.validate_state_inputs(state)
        aliases = kvnctl.all_sni_aliases(state)

        self.assertEqual(aliases["vpn.example.com"], "127.0.0.1:8443")
        self.assertEqual(kvnctl.ocserv_public_tcp_port(state), 443)

    def test_ocserv_rendered_users_and_client_text(self):
        state = base_state()
        state["server"] = "vpn.example.com"
        state["ocserv"] = {
            "enabled": True,
            "sni_enabled": True,
            "sni": "vpn.example.com",
            "network": "10.77.77.0/24",
        }
        user = state["users"][0]
        user["systems"].append("ocserv")
        user["ocserv_password"] = "OpenConnect123"

        conf = kvnctl.ocserv_conf_text(state)
        users = kvnctl.ocserv_users_text(state)
        client = kvnctl.openconnect_client_text(state, user)

        self.assertIn('auth = "plain[passwd=/run/ocserv/ocpasswd]"', conf)
        self.assertIn("ipv4-network = 10.77.77.0", conf)
        self.assertIn("Alice:OpenConnect123", users)
        self.assertIn("https://vpn.example.com:443/", client)

    def test_edit_user_sets_manual_ocserv_password(self):
        state = base_state()
        user = state["users"][0]
        user["systems"].append("ocserv")
        args = kvnctl.argparse.Namespace(
            name="Alice",
            new_name=None,
            description=None,
            systems=None,
            device=None,
            sni=None,
            uuid=None,
            hysteria_password=None,
            telemt_secret=None,
            ocserv_password="ManualPass123",
            regenerate_keys=False,
            enable=None,
            server=None,
            restart=False,
        )

        with (
            mock.patch("tools.kvnctl.load_state", return_value=state),
            mock.patch("tools.kvnctl.render_all", return_value=True),
            mock.patch("tools.kvnctl.save_state"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            kvnctl.cmd_edit_user(args)

        self.assertEqual(user["ocserv_password"], "ManualPass123")

    def test_parser_accepts_manual_ocserv_password(self):
        parser = kvnctl.build_parser()

        add_args = parser.parse_args(["add-user", "Bob", "--ocserv-password", "ManualPass123"])
        edit_args = parser.parse_args(["edit-user", "Alice", "--ocserv-password", "AnotherPass123"])

        self.assertEqual(add_args.ocserv_password, "ManualPass123")
        self.assertEqual(edit_args.ocserv_password, "AnotherPass123")

    def test_decoy_site_has_no_obsolete_speed_downloads(self):
        state = base_state()

        html = kvnctl.render_decoy_site_text(state)

        self.assertNotIn("/speed/", html)
        self.assertNotIn("Скачать тестовый файл", html)


if __name__ == "__main__":
    unittest.main()
