import argparse
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from tools import kvnctl
from tools.kvnlib.apply import ChangeSet
from tools.kvnlib.state import JsonStateStore, atomic_write_json


def portal_args(**overrides):
    values = {
        "action": "configure", "enable": True, "confirm_disable": False,
        "name": "KVN Control", "domain": "portal.example.com", "port": 443,
        "path": "/gaer", "login": "admin", "reset_credentials": False,
        "restart": False, "allow_self_signed_ip": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def portal_state(port=443):
    return {
        "server": "198.51.100.10",
        "users": [],
        "site": {"title": "Site"},
        "subscription": {"enabled": False, "port": 2096},
        "letsencrypt": {
            "enabled": True, "domain": "portal.example.com",
            "domains": ["portal.example.com"],
        },
        "portal": {
            "enabled": True, "name": "KVN Control", "domain": "portal.example.com",
            "port": port, "path": "/gaer", "login": "admin",
            "password_hash": "scrypt$131072$8$1$salt$hash",
            "proxy_secret": "p" * 64, "hysteria_secret": "h" * 64,
        },
        "ocserv": {"enabled": False, "sni_enabled": False},
        "sni_routes": {},
    }


def portal_ip_state(*, allow_self_signed=False):
    state = portal_state(8443)
    state["portal"]["domain"] = "46.29.239.64"
    state["portal"]["allow_self_signed_ip"] = allow_self_signed
    state["letsencrypt"] = {"enabled": False, "domain": "", "domains": []}
    return state


class PortalSchemaTests(unittest.TestCase):
    def test_missing_schema_defaults_disabled_without_secrets(self):
        state = {"users": []}
        cfg = kvnctl.portal_config(state)
        self.assertEqual(cfg, {"enabled": False})
        self.assertNotIn("password_hash", json.dumps(state))
        self.assertNotIn("proxy_secret", json.dumps(state))

    def test_legacy_domain_state_gets_standard_performance_defaults(self):
        state = portal_state(8443)

        cfg = kvnctl.portal_config(state)

        self.assertEqual(cfg["domain"], "portal.example.com")
        self.assertEqual(cfg["port"], 8443)
        self.assertEqual(cfg["path"], "/gaer")
        self.assertEqual(cfg["performance_profile"], "standard")
        self.assertEqual(cfg["features"], {"monitoring": True, "background_refresh": True})
        self.assertEqual(f"https://{cfg['domain']}:{cfg['port']}{cfg['path']}/", "https://portal.example.com:8443/gaer/")

    def test_performance_profiles_and_explicit_overrides_are_deterministic(self):
        portal = {"performance_profile": "light"}
        self.assertEqual(
            kvnctl.portal_performance_config(portal),
            {"profile": "light", "monitoring": False, "background_refresh": False},
        )
        portal = {
            "performance_profile": "light",
            "features": {"monitoring": True, "background_refresh": False},
        }
        self.assertEqual(
            kvnctl.portal_performance_config(portal),
            {"profile": "custom", "monitoring": True, "background_refresh": False},
        )
        self.assertEqual(portal["performance_profile"], "custom")

    def test_performance_config_rejects_unknown_profiles_keys_and_non_bool_values(self):
        invalid = [
            {"performance_profile": "turbo"},
            {"features": {"monitoring": "yes"}},
            {"features": {"telemetry": False}},
            {"performance_profile": "custom", "features": {"monitoring": False}},
        ]
        for portal in invalid:
            with self.subTest(portal=portal), self.assertRaises(SystemExit):
                kvnctl.portal_performance_config(portal)

    def test_portal_host_accepts_domain_and_public_ipv4_only(self):
        self.assertEqual(kvnctl.validate_portal_host("Portal.Example.COM."), "portal.example.com")
        self.assertEqual(kvnctl.validate_portal_host("46.29.239.64"), "46.29.239.64")
        self.assertEqual(kvnctl.portal_host_kind("46.29.239.64"), "ipv4")
        self.assertEqual(kvnctl.portal_host_kind("portal.example.com"), "domain")
        invalid = [
            "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255", "::1",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                kvnctl.validate_portal_host(value)

    def test_ip_portal_requires_custom_port_and_explicit_self_signed_flag(self):
        state = portal_ip_state()
        cfg = kvnctl.portal_config(state)
        self.assertEqual(cfg["domain"], "46.29.239.64")
        self.assertFalse(cfg["allow_self_signed_ip"])
        state["portal"]["port"] = 443
        with self.assertRaisesRegex(SystemExit, "отдельный HTTPS-порт"):
            kvnctl.portal_config(state)
        state = portal_ip_state()
        state["portal"]["allow_self_signed_ip"] = "yes"
        with self.assertRaises(SystemExit):
            kvnctl.portal_config(state)

    def test_portal_normalization_does_not_write_runtime_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = portal_state(8443)
            with (
                mock.patch.object(kvnctl, "ROOT", root),
                mock.patch.object(kvnctl, "PORTAL_RUNTIME_STATE", root / "portal-runtime" / "users.json"),
            ):
                kvnctl.portal_config(state)
            self.assertEqual(list(root.iterdir()), [])

    def test_path_validation_rejects_unsafe_values(self):
        invalid = ["", "/", "/../x", "/a//b", "/a?x=1", "/a#x", "/a\n", "/" + "a" * 121]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(SystemExit):
                kvnctl.validate_portal_path(value)
        self.assertEqual(kvnctl.validate_portal_path("/gaer/mobile"), "/gaer/mobile")

    def test_port_validation_allows_443_and_custom_but_rejects_conflicts(self):
        state = {"subscription": {"port": 2096}}
        self.assertEqual(kvnctl.validate_portal_port(443, state), 443)
        self.assertEqual(kvnctl.validate_portal_port(8443, state), 8443)
        for port in [0, 80, 2096, 2443, 2448, 65536]:
            with self.subTest(port=port), self.assertRaises(SystemExit):
                kvnctl.validate_portal_port(port, state)

    def test_configure_hashes_password_and_rerun_preserves_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "users.json"
            atomic_write_json(state_path, {"users": [], "subscription": {"port": 2096}})
            store = JsonStateStore(state_path)
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=ChangeSet()),
                mock.patch.object(kvnctl.getpass, "getpass", side_effect=["StrongPassword-2026", "StrongPassword-2026"]) as passwords,
            ):
                kvnctl.cmd_portal(portal_args())
            first = store.load()["portal"]
            first_hash = first["password_hash"]
            first_proxy = first["proxy_secret"]
            runtime_state = state_path.parent / "portal-runtime" / "users.json"
            self.assertEqual(json.loads(runtime_state.read_text(encoding="utf-8"))["portal"]["path"], "/gaer")
            self.assertTrue(first_hash.startswith("scrypt$"))
            self.assertNotIn("StrongPassword-2026", state_path.read_text(encoding="utf-8"))
            self.assertEqual(passwords.call_count, 2)
            rerun_args = portal_args(
                enable=None, name=None, domain=None, port=None, path=None, login=None,
            )
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=ChangeSet()),
                mock.patch.object(kvnctl.getpass, "getpass") as passwords,
                mock.patch("builtins.input", side_effect=["", "", "", "", "", "", ""]),
            ):
                kvnctl.cmd_portal(rerun_args)
            second = store.load()["portal"]
            self.assertEqual(second["password_hash"], first_hash)
            self.assertEqual(second["proxy_secret"], first_proxy)
            passwords.assert_not_called()

    def test_noninteractive_configure_accepts_public_ip_without_touching_letsencrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "users.json"
            initial = {
                "users": [], "subscription": {"port": 2096},
                "letsencrypt": {"enabled": False, "domain": "", "domains": []},
            }
            atomic_write_json(state_path, initial)
            store = JsonStateStore(state_path)
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=ChangeSet()),
                mock.patch.object(kvnctl, "hash_portal_password", return_value="scrypt$131072$8$1$salt$hash"),
                mock.patch.object(kvnctl, "_portal_password_twice", return_value="StrongPassword-2026"),
            ):
                kvnctl.cmd_portal(portal_args(
                    domain="46.29.239.64", port=8443, allow_self_signed_ip=True,
                ))
            state = store.load()
            self.assertEqual(state["portal"]["domain"], "46.29.239.64")
            self.assertTrue(state["portal"]["allow_self_signed_ip"])
            self.assertFalse(state["letsencrypt"]["enabled"])

    def test_interactive_configure_repeats_invalid_fields_and_passwords(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "users.json"
            atomic_write_json(state_path, {"users": [], "subscription": {"port": 2096}})
            store = JsonStateStore(state_path)
            answers = [
                "maybe", "y",
                "KVN Control",
                "bad domain", "portal.example.com",
                "text", "8443",
                "gaer", "/gaer",
                "x", "admin",
            ]
            passwords = [
                "FirstStrongPassword", "DifferentStrongPassword",
                "short", "short",
                "StrongPassword-2026", "StrongPassword-2026",
            ]
            with (
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl, "render_all", return_value=ChangeSet()),
                mock.patch("builtins.input", side_effect=answers) as entered,
                mock.patch.object(kvnctl.getpass, "getpass", side_effect=passwords) as secret_input,
            ):
                kvnctl.cmd_portal(portal_args(
                    enable=None, name=None, domain=None, port=None, path=None, login=None,
                ))
            cfg = store.load()["portal"]
            self.assertEqual(cfg["domain"], "portal.example.com")
            self.assertEqual(cfg["port"], 8443)
            self.assertEqual(cfg["path"], "/gaer")
            self.assertEqual(cfg["login"], "admin")
            self.assertEqual(entered.call_count, len(answers))
            self.assertEqual(secret_input.call_count, len(passwords))

    def test_explicit_disable_requires_confirmation_and_preserves_vpn_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "users.json"
            state = portal_state()
            state["users"] = [{"name": "Alice"}]
            atomic_write_json(state_path, state)
            store = JsonStateStore(state_path)
            with mock.patch.object(kvnctl, "STATE_STORE", store):
                with self.assertRaises(SystemExit):
                    kvnctl.cmd_portal(portal_args(enable=False))
                kvnctl.cmd_portal(portal_args(enable=False, confirm_disable=True))
            disabled = store.load()
            self.assertFalse(disabled["portal"]["enabled"])
            self.assertEqual(disabled["users"], [{"name": "Alice"}])

    def test_reset_credentials_invalidates_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "users.json"
            atomic_write_json(state_path, portal_state())
            store = JsonStateStore(state_path)
            database = root / "portal-data" / "portal.db"
            database.parent.mkdir()
            with closing(sqlite3.connect(database)) as db:
                db.execute("CREATE TABLE sessions(value TEXT)")
                db.execute("INSERT INTO sessions VALUES ('active')")
                db.commit()
            args = argparse.Namespace(action="reset-credentials", login="new-admin")
            with (
                mock.patch.object(kvnctl, "ROOT", root),
                mock.patch.object(kvnctl, "STATE_STORE", store),
                mock.patch.object(kvnctl.getpass, "getpass", side_effect=["AnotherStrongPassword", "AnotherStrongPassword"]),
                mock.patch.object(kvnctl, "restart_portal_container_best_effort"),
            ):
                kvnctl.cmd_portal(args)
            with closing(sqlite3.connect(database)) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0], 0)
            self.assertEqual(store.load()["portal"]["login"], "new-admin")


class PortalNginxTests(unittest.TestCase):
    def render(self, state, ready):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        nginx = root / "nginx.conf"
        gateway = root / "portal-gateway.conf"
        with (
            mock.patch.object(kvnctl, "NGINX_CONFIG", nginx),
            mock.patch.object(kvnctl, "PORTAL_GATEWAY_CONFIG", gateway),
            mock.patch.object(kvnctl, "portal_public_ready", return_value=ready),
        ):
            kvnctl.render_nginx(state)
        return temporary, nginx.read_text(encoding="utf-8"), gateway.read_text(encoding="utf-8")

    def test_443_route_is_exact_and_domain_is_site_sni(self):
        temporary, nginx, gateway = self.render(portal_state(443), True)
        self.addCleanup(temporary.cleanup)
        self.assertIn('"1:portal.example.com"', nginx)
        self.assertIn("location = /gaer", nginx)
        self.assertIn("location ^~ /gaer/", nginx)
        self.assertIn("X-KVN-Proxy-Secret", nginx)
        self.assertIn("proxy_pass http://$portal_backend$request_uri", nginx)
        self.assertNotIn("proxy_pass http://$portal_backend$request_uri", gateway)

    def test_custom_port_routes_only_through_gateway(self):
        temporary, nginx, gateway = self.render(portal_state(8443), True)
        self.addCleanup(temporary.cleanup)
        self.assertIn('"1:portal.example.com"', nginx)
        self.assertNotIn("location ^~ /gaer/", nginx)
        self.assertIn("location ^~ /gaer/", gateway)
        self.assertIn("listen 8443 ssl", gateway)

    def test_ip_gateway_uses_http_host_guard_and_keeps_secret_path_protection(self):
        temporary, nginx, gateway = self.render(portal_ip_state(allow_self_signed=True), True)
        self.addCleanup(temporary.cleanup)
        self.assertNotIn("46.29.239.64", nginx)
        self.assertIn("server_name 46.29.239.64", gateway)
        self.assertIn("if ($host != 46.29.239.64) { return 404; }", gateway)
        self.assertIn("location ^~ /gaer/", gateway)
        self.assertIn("X-KVN-Proxy-Secret", gateway)

    def test_ip_certificate_readiness_requires_matching_san_and_policy(self):
        cert = kvnctl.SITE_CERTS_DIR / "server.crt"
        cases = [
            ("self-signed", ["46.29.239.64"], False, False),
            ("self-signed", ["46.29.239.64"], True, True),
            ("self-signed", ["46.29.239.65"], True, False),
            ("letsencrypt", ["46.29.239.64"], False, True),
        ]
        for source, sans, allow, expected in cases:
            with (
                self.subTest(source=source, sans=sans, allow=allow),
                mock.patch.object(kvnctl, "certificate_source", return_value=source),
                mock.patch.object(kvnctl, "certificate_sans", return_value=sans),
            ):
                self.assertEqual(
                    kvnctl.portal_public_ready(portal_ip_state(allow_self_signed=allow)),
                    expected,
                )

    def test_certificate_sans_parses_dns_and_ip_entries(self):
        output = "X509v3 Subject Alternative Name:\n    DNS:portal.example.com, IP Address:46.29.239.64"
        with mock.patch.object(kvnctl, "openssl_x509", return_value=output):
            self.assertEqual(
                kvnctl.certificate_sans(Path("server.crt")),
                ["portal.example.com", "46.29.239.64"],
            )

    def test_certbot_ip_support_and_short_lived_command_are_strict(self):
        self.assertFalse(kvnctl.certbot_supports_ip_certificates("certbot 5.3.1"))
        self.assertTrue(kvnctl.certbot_supports_ip_certificates("certbot 5.4.0"))
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.object(kvnctl, "certbot_supports_ip_certificates", return_value=True),
            mock.patch.object(kvnctl, "_stop_docker_service_best_effort", return_value=False),
            mock.patch.object(kvnctl.subprocess, "run", return_value=completed) as run,
        ):
            kvnctl.run_certbot_issue_ip("46.29.239.64")
        command = run.call_args.args[0]
        self.assertIn("--preferred-profile", command)
        self.assertIn("shortlived", command)
        self.assertIn("--ip-address", command)
        self.assertIn("46.29.239.64", command)
        self.assertNotIn("-d", command)

    def test_empty_docker_directory_is_replaced_with_gateway_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = Path(tmp) / "nginx" / "portal-gateway.conf"
            gateway.mkdir(parents=True)
            with mock.patch.object(kvnctl, "PORTAL_GATEWAY_CONFIG", gateway):
                kvnctl.render_portal_gateway(portal_state(8443))
            self.assertTrue(gateway.is_file())
            self.assertIn("listen 8443 ssl", gateway.read_text(encoding="utf-8"))

    def test_nonempty_gateway_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = Path(tmp) / "nginx" / "portal-gateway.conf"
            gateway.mkdir(parents=True)
            marker = gateway / "keep.txt"
            marker.write_text("не удалять", encoding="utf-8")
            with (
                mock.patch.object(kvnctl, "PORTAL_GATEWAY_CONFIG", gateway),
                self.assertRaises(SystemExit),
            ):
                kvnctl.render_portal_gateway(portal_state(8443))
            self.assertEqual(marker.read_text(encoding="utf-8"), "не удалять")

    def test_letsencrypt_failure_keeps_both_public_routes_closed(self):
        temporary, nginx, gateway = self.render(portal_state(8443), False)
        self.addCleanup(temporary.cleanup)
        self.assertNotIn("proxy_pass http://$portal_backend$request_uri", nginx)
        self.assertNotIn("proxy_pass http://$portal_backend$request_uri", gateway)
        self.assertIn("location ^~ /gaer/ { return 404; }", gateway)

    def test_portal_domain_is_in_letsencrypt_sans(self):
        state = portal_state()
        state["letsencrypt"] = {"enabled": True, "domain": "site.example.com", "domains": ["site.example.com"]}
        self.assertEqual(
            kvnctl.letsencrypt_domains(state),
            ["site.example.com", "portal.example.com"],
        )

    def test_certificate_reload_touches_only_consumers(self):
        state = portal_state(443)
        with (
            mock.patch.object(kvnctl, "_docker_service_files_visible", return_value=True),
            mock.patch.object(kvnctl, "_reload_docker_service", return_value=True) as reload_service,
            mock.patch.object(kvnctl, "_restart_docker_services") as restart_services,
        ):
            report = kvnctl.reload_certificate_consumers(state, "site")
        reload_service.assert_called_once_with("nginx")
        restart_services.assert_not_called()
        self.assertEqual(report["reloaded"], ["nginx"])

    def test_missing_certificate_bind_mount_recreates_only_consumer(self):
        state = portal_state(443)
        with (
            mock.patch.object(kvnctl, "_docker_service_files_visible", return_value=False),
            mock.patch.object(kvnctl, "_reload_docker_service") as reload_service,
            mock.patch.object(kvnctl, "_recreate_docker_service", return_value=True) as recreate_service,
        ):
            report = kvnctl.reload_certificate_consumers(state, "site")
        reload_service.assert_not_called()
        recreate_service.assert_called_once_with("nginx")
        self.assertEqual(report["recreated"], ["nginx"])


class SetupSourceTests(unittest.TestCase):
    def test_portal_dockerfile_quotes_wsgi_factory_for_sh(self):
        source = Path("portal/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("--workers=${KVN_PORTAL_WORKERS:-1}", source)
        self.assertIn("'app:create_app()'", source)
        self.assertNotIn(" app:create_app()\"]", source)

    def test_portal_dockerfile_uses_offline_wheelhouse(self):
        source = Path("portal/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY wheels ./wheels", source)
        self.assertIn("--no-index --find-links=/app/wheels", source)
        self.assertNotIn("pip install --no-cache-dir -r requirements.txt", source)
        wheels = sorted(Path("portal/wheels").glob("*.whl"))
        self.assertGreaterEqual(len(wheels), 8)
        wheel_names = {item.name for item in wheels}
        for expected in [
            "flask-3.1.3-py3-none-any.whl",
            "gunicorn-26.0.0-py3-none-any.whl",
            "markupsafe-3.0.3-cp313-cp313-musllinux_1_2_x86_64.whl",
        ]:
            self.assertIn(expected, wheel_names)
        hashes = Path("portal/wheels/SHA256SUMS").read_text(encoding="utf-8")
        self.assertIn(
            "40233d26a5f0d1872916188c276e21641155111c2853f0c2cd55260aec0d24fc"
            "  gunicorn-26.0.0-py3-none-any.whl",
            hashes,
        )
        self.assertIn("sha256sum -c SHA256SUMS", source)

    def test_setup_contains_secure_prompts_profiles_permissions_and_recovery(self):
        source = Path("setup.sh").read_text(encoding="utf-8")
        required = [
            "portal configure", "Обязательный сертификат Let's Encrypt",
            "letsencrypt_eligible_domain(portal_domain)", "PORTAL_PUBLIC_READY",
            "пробую отдельный сертификат только для web-портала",
            "--profile portal", "--profile portal-custom", "chmod 0600 ./users.json",
            "portal/install-host-agent.sh",
            "prompt_domain_csv", "prompt_site_title", "validate_domain_csv_input", "prompt_yes_no",
            "repair_portal_gateway_config_target", "docker rm -f kvn-portal-gateway",
            "verify_portal_agent_bridge", "portal → host-agent health и metrics RPC работают",
            'client.call("metrics.current", {})', 'client.call("metrics.history",',
            "repair_stale_bind_mounts", "Откройте порт web-портала",
            "BUILDX_NO_DEFAULT_ATTESTATIONS=1", "COMPOSE_PROFILE_LIST", "atomic_write_text",
            "ensure_wireguard_tools", "wireguard/install-host-service.sh",
            "verify_wireguard_host_service", "kvn-wireguard.service", "51821/udp",
            'install -d -o root -g "$PORTAL_GID" -m 0750 /backup',
        ]
        for value in required:
            self.assertIn(value, source)
        for forbidden in ["PORTAL_PASSWORD=", "--password", "export PORTAL_PASSWORD"]:
            self.assertNotIn(forbidden, source)
        for forbidden in ["tools/tune-host-network.sh", "98-kvn-network-tuning.conf", "tcp_bbr", "ethtool"]:
            self.assertNotIn(forbidden, source)
        self.assertNotIn("systemctl restart kvn-portal-agent.service", source)
        self.assertNotIn("rm -rf certs/ site-certs/", source)

    def test_setup_has_ip_branch_without_dns_or_unstable_install(self):
        source = Path("setup.sh").read_text(encoding="utf-8")
        ip_branch = source.split('if [ "$PORTAL_HOST_KIND" = "ipv4" ]', 1)[1].split("else", 1)[0]
        for marker in [
            "certbot_supports_ip_certificates", "run_certbot_issue_ip",
            "deploy_letsencrypt_ip_certificate", "explicit self-signed fallback",
            "verify_portal_public_https", "--resolve",
        ]:
            self.assertIn(marker, source)
        self.assertNotIn("getent ahosts", ip_branch)
        self.assertNotRegex(source, r"pip(3)? install.*certbot|unstable.*apt")

    def test_update_script_preserves_runtime_and_applies_host_services(self):
        source = Path("update.sh").read_text(encoding="utf-8")
        for marker in [
            "kvn-vpn-deploy.tar.gz", "users.json", ".update-backups",
            "tools/canonical-files.txt", "python3 tools/kvnctl.py render",
            "amneziawg/sync-host-service.sh", "wireguard/sync-host-service.sh",
            "docker compose -f docker-compose.yml", "COMPOSE_PROFILES",
            "kvn-vpn-deploy*.tar.gz", "kvn-vpn-release-linux-amd64*.tar.gz",
            ".kvn-canonical-files", "Список обновляемых файлов проверен",
            "tools/deploy_archive.py", "--no-same-owner", "STAGE_DIR=",
            "SNAPSHOT_DIR=", "restore_source_snapshot", "COMPOSE_STARTED=1",
            "--no-build --pull never", "tools.release_archive",
            "service-plan --format lines", "EFFECTIVE_DOCKER_SERVICES",
            "DISABLED_DOCKER_SERVICES", "atomic_write_text",
        ]:
            self.assertIn(marker, source)
        self.assertIn("if [ ! -f users.json ]; then", source)
        self.assertNotIn("cp -f \"$SRC/users.json\" users.json", source)
        self.assertNotIn("python3 tools/kvnctl.py render --restart", source)

        marker = "python3 - \"$PORTAL_GID\" \"$PORTAL_PORT\" \"$COMPOSE_PROFILE_LIST\" <<'PY'\n"
        self.assertIn(marker, source)
        env_block = source.split(marker, 1)[1].split("\nPY\n", 1)[0]
        compile(env_block, "update-env-block", "exec")
        self.assertIn("import json", env_block)

    def test_host_network_helper_keeps_only_required_routing(self):
        source = Path("tools/tune-host-network.sh").read_text(encoding="utf-8")
        self.assertIn("net.ipv4.ip_forward = 1", source)
        self.assertIn("99-kvn-vpn.conf", source)
        for forbidden in [
            "tcp_bbr", "ethtool", "net.core.rmem_max", "net.core.wmem_max",
            "tcp_congestion_control", "netdev_max_backlog", "nf_conntrack",
        ]:
            self.assertNotIn(forbidden, source)

    def test_agent_installer_restarts_only_for_unit_or_source_change(self):
        source = Path("portal/install-host-agent.sh").read_text(encoding="utf-8")
        for marker in [
            "StateDirectory=kvn-portal", "StateDirectoryMode=0750",
            "agent-source.sha256", "source_fingerprint", "restart_required=0",
            'if [[ "$restart_required" = "1" ]]',
            'client.call("metrics.current", {})', 'client.call("metrics.history",',
            "/etc/amnezia/amneziawg", "/etc/wireguard",
            "/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt", "/etc/systemd/system",
        ]:
            self.assertIn(marker, source)
        self.assertIn("seq 1 120", source)

    def test_host_sync_scripts_keep_peer_only_apply_and_forwarding(self):
        scripts = [
            Path("amneziawg/sync-host-service.sh").read_text(encoding="utf-8"),
            Path("wireguard/sync-host-service.sh").read_text(encoding="utf-8"),
        ]
        for source in scripts:
            self.assertIn("STRUCTURAL_CHANGED=false", source)
            self.assertIn("syncconf", source)
            self.assertIn("verify_ipv4_forwarding", source)
            self.assertIn("/proc/sys/net/ipv4/ip_forward", source)
            self.assertNotIn("sysctl -w", source)
            self.assertNotIn("/etc/sysctl.d", source)

    def test_portal_gateway_has_only_required_nginx_capabilities(self):
        source = Path("docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("./portal-runtime:/project/runtime:ro", source)
        self.assertNotIn("./users.json:/project/users.json:ro", source)
        self.assertIn('- "80:80/tcp"', source)
        ocserv = source.split("  ocserv:\n", 1)[1].split("\n  xray:\n", 1)[0]
        self.assertIn("network: host", ocserv)
        gateway = source.split("  portal-gateway:\n", 1)[1].split("\n  nginx:\n", 1)[0]
        self.assertIn("read_only: true", gateway)
        self.assertIn("- ALL", gateway)
        self.assertIn("no-new-privileges:true", gateway)
        self.assertIn("cap_add:", gateway)
        for capability in ["CHOWN", "SETGID", "SETUID"]:
            self.assertIn(f"- {capability}", gateway)
        for capability in ["SYS_ADMIN", "NET_ADMIN", "DAC_OVERRIDE"]:
            self.assertNotIn(capability, gateway)


if __name__ == "__main__":
    unittest.main()
