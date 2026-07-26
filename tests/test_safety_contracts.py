"""Контрактные проверки границ безопасности без обращения к runtime-данным."""

from __future__ import annotations

import ast
import base64
import json
import re
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import parse_qs, urlparse

from portal.agent_protocol import ALLOWED_METHODS, READ_ONLY_METHODS
from portal.control import KvnControl
from tools.kvnlib.services import configured_service_preferences
from tools import kvnctl


ROOT = Path(__file__).resolve().parents[1]


class SafetyContractsTests(unittest.TestCase):
    """Проверяет только исходники и чистый deploy-шаблон."""

    def test_deploy_template_contains_no_runtime_state(self):
        """Чистый deploy остаётся переносимым без пользовательских данных."""
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "users.json"
            fixture.write_text(
                (ROOT / "deploy" / "users.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            state = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertEqual(state["server"], "YOUR_SERVER_IP")
        self.assertEqual(state["users"], [])
        self.assertEqual(state["portal"], {"enabled": False})

        forbidden = {
            "CLIENT_LINKS.md", "nginx/nginx.conf", "nginx/portal-gateway.conf",
            "xray/config.json", "hy2/config.yaml", "amneziawg/awg0.conf",
            "wireguard/wg0.conf", "telemt/config.toml", "mtg/config.toml",
            "ocserv/ocserv.conf", "ocserv/users.txt", "ocserv/ocserv.env",
            "portal-runtime/users.json",
        }
        deploy_paths = {
            path.relative_to(ROOT / "deploy").as_posix()
            for path in (ROOT / "deploy").rglob("*")
            if path.is_file()
        }
        for path in deploy_paths:
            self.assertNotIn(path, forbidden, path)

    def test_portal_compose_boundary_stays_unprivileged(self):
        """Web-контейнер не получает Docker socket или привилегии хоста."""
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        portal = re.search(r"^  portal:\n(?P<body>.*?)(?=^  [a-z][\w-]*:\n|\Z)", compose, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(portal)
        body = portal.group("body")
        self.assertNotIn("/var/run/docker.sock", body)
        self.assertNotIn("privileged: true", body)
        self.assertNotIn("network_mode: host", body)
        self.assertIn("read_only: true", body)
        self.assertIn("cap_drop:", body)
        self.assertIn("- ALL", body)
        self.assertIn("no-new-privileges:true", body)

    def test_host_sync_keeps_peer_only_and_structural_paths(self):
        """AWG и WG имеют отдельные fast/structural apply-пути."""
        for relative, binary, marker in [
            ("amneziawg/sync-host-service.sh", "awg", "KVN_AWG_APPLY_MODE"),
            ("wireguard/sync-host-service.sh", "wg", "KVN_WG_APPLY_MODE"),
        ]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("STRUCTURAL_CHANGED=false", source, relative)
            self.assertIn(f"{binary} syncconf", source, relative)
            self.assertIn("systemctl restart", source, relative)
            self.assertIn(marker, source, relative)

    def test_mobile_navigation_and_assets_remain_local(self):
        """Мобильная навигация сохраняет все разделы без внешних assets."""
        base = (ROOT / "portal" / "app" / "templates" / "base.html").read_text(encoding="utf-8")
        mobile = base.split('<nav class="mobile-nav"', 1)[1].split("</nav>", 1)[0]
        navigation = (ROOT / "portal" / "app" / "navigation.py").read_text(encoding="utf-8")
        self.assertIn("navigation_links(navigation_items)", mobile)
        for endpoint in [
            "dashboard", "users_list", "services_list", "logs_view", "root_shell_view",
            "network_view",
            "terminal_view", "certificates_view", "health_view", "audit_view",
            "backups_view", "project_info", "settings_view",
        ]:
            self.assertIn(f'"endpoint": "{endpoint}"', navigation)

        assets = [
            ROOT / "portal" / "app" / "static" / "style.css",
            *sorted((ROOT / "portal" / "app" / "static").glob("*.js")),
        ]
        content = "\n".join(path.read_text(encoding="utf-8") for path in assets)
        self.assertNotRegex(content, r"https?://|@import|url\s*\(")
        self.assertLessEqual(sum(path.stat().st_size for path in assets), 106 * 1024)

    def test_network_template_is_canonical_and_contains_no_secret_fields(self):
        template = ROOT / "portal" / "app" / "templates" / "network.html"
        canonical = (ROOT / "tools" / "canonical-files.txt").read_text(encoding="utf-8")
        self.assertTrue(template.is_file())
        self.assertIn("portal/app/templates/network.html", canonical)
        source = template.read_text(encoding="utf-8").lower()
        for forbidden in ["private_key", "preshared", "password", "sub_token", "shortids", "content_base64"]:
            self.assertNotIn(forbidden, source)

    def test_shell_inventory_is_strict_and_deploy_mirror_is_exact(self):
        """Все канонические shell entry points известны и синхронизированы."""
        canonical = sorted(
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*.sh")
            if "deploy" not in path.relative_to(ROOT).parts
            and "tests" not in path.relative_to(ROOT).parts
            and ".supergoal" not in path.relative_to(ROOT).parts
        )
        self.assertEqual(len(canonical), 20, canonical)
        self.assertEqual(len(list((ROOT / "deploy").rglob("*.sh"))), 19)
        self.assertEqual(len(list((ROOT / "tests").rglob("*.sh"))), 1)

        for relative in canonical:
            source = (ROOT / relative).read_bytes()
            self.assertIn(b"set -euo pipefail", source, relative)
            text = source.decode("utf-8")
            self.assertNotRegex(
                text,
                r"(?m)^[ \t]*(?:sudo[ \t]+)?eval(?:[ \t]|$)",
                f"{relative}: запрещён eval",
            )
            if "mktemp" in text:
                self.assertRegex(
                    text,
                    r"(?m)^[ \t]*trap[ \t]+",
                    f"{relative}: временные файлы должны очищаться через trap",
                )
            if relative == "tools/build-deploy.sh":
                continue
            mirror = ROOT / "deploy" / relative
            self.assertTrue(mirror.is_file(), relative)
            self.assertEqual(source, mirror.read_bytes(), relative)

        legacy = ROOT / "tests" / "fixtures" / "legacy-deploy" / "update.sh"
        self.assertTrue(legacy.is_file())
        self.assertIn("tools/deploy_archive.py", legacy.read_text(encoding="utf-8"))

    def test_service_preferences_are_backward_compatible(self):
        """Отсутствующая настройка сервиса означает legacy enabled=true."""
        class FixtureStore:
            def __init__(self):
                self.state = {"users": []}

            def load(self):
                return self.state

        store = FixtureStore()
        control = KvnControl.__new__(KvnControl)
        control.kvnctl = SimpleNamespace(
            STATE_STORE=store,
            configured_service_preferences=configured_service_preferences,
        )

        self.assertEqual(control.service_preferences(), {})
        self.assertTrue(control.service_preferences().get("xray", True))
        store.state["services"] = {"xray": {"enabled": False}, "nginx": {}}
        self.assertEqual(control.service_preferences(), {"xray": False, "nginx": True})

    def test_reality_and_subscription_characterization_uses_fixture_only(self):
        """Reality Vision и legacy URI-порядок проверяются без production state."""
        state = {
            "server": "203.0.113.10",
            "sni_routes": {
                "tls": {"default": "tls.example.test", "aliases": ["tls.example.test"]},
                "reality-xhttp": {"default": "xhttp.example.test", "aliases": ["xhttp.example.test"]},
                "reality-tcp": {"default": "tcp.example.test", "aliases": ["tcp.example.test"]},
                "hysteria": {"default": "hy.example.test", "aliases": ["hy.example.test"]},
            },
            "reality": {"short_id": "a3f9c1b82d4e6f90"},
            "reality_tcp": {"short_id": "e7a4b2c91f5d8e30"},
        }
        user = {
            "name": "AuditFixture",
            "uuid": "00000000-0000-4000-8000-000000000001",
            "hysteria_password": "fixture-password",
            "enabled": True,
            "systems": ["tls", "reality-xhttp", "reality-tcp", "hysteria"],
            "sni_overrides": {},
        }
        with (
            mock.patch("tools.kvnctl.certificate_sha256_hex", return_value=""),
            mock.patch("tools.kvnctl.certificate_pin_sha256", return_value=""),
        ):
            payload = base64.b64decode(
                kvnctl.subscription_txt(state, user, "fixture-public-key")
            ).decode("utf-8").splitlines()
            reality_link = kvnctl.vless_reality_tcp_link(
                state, user, "fixture-public-key"
            )

        self.assertEqual(
            [urlparse(link).scheme for link in payload],
            ["hysteria2", "vless", "vless", "vless"],
        )
        self.assertIn("Reality-TCP", payload[1])
        self.assertIn("Reality", payload[2])
        self.assertIn("TLS", payload[3])
        query = parse_qs(urlparse(reality_link).query)
        self.assertEqual(query["type"], ["tcp"])
        self.assertEqual(query["security"], ["reality"])
        self.assertEqual(query["flow"], ["xtls-rprx-vision"])

    def test_agent_dispatch_matches_versioned_rpc_allowlist(self):
        """Host-agent не получает неописанный универсальный exec RPC."""
        source = (ROOT / "portal" / "agent.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        handler_methods = None
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != "dispatch":
                continue
            for item in node.body:
                if not isinstance(item, ast.Assign):
                    continue
                if not any(isinstance(target, ast.Name) and target.id == "handlers" for target in item.targets):
                    continue
                self.assertIsInstance(item.value, ast.Dict)
                handler_methods = {
                    key.value
                    for key in item.value.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                }
        self.assertIsNotNone(handler_methods)
        self.assertEqual(handler_methods, ALLOWED_METHODS)
        self.assertIn("logs.tail", READ_ONLY_METHODS)
        self.assertIn("sni.diagnose", READ_ONLY_METHODS)
        for forbidden in {"exec", "shell.command", "docker.exec", "docker.socket"}:
            self.assertNotIn(forbidden, ALLOWED_METHODS)

    def test_container_logging_and_hardened_services_are_bounded(self):
        """Все контейнеры имеют единый bounded security/logging baseline."""
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        size = re.search(r'max-size:\s*"(?P<mb>\d+)m"', compose)
        files = re.search(r'max-file:\s*"(?P<count>\d+)"', compose)
        self.assertIsNotNone(size)
        self.assertIsNotNone(files)
        self.assertLessEqual(int(size.group("mb")), 10)
        self.assertLessEqual(int(files.group("count")), 2)
        self.assertEqual(compose.count("logging: *default-logging"), 8)

        for service in [
            "portal", "portal-gateway", "nginx", "telemt", "mtg",
            "hysteria", "ocserv", "xray",
        ]:
            block = re.search(
                rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-z][\w-]*:\n|\Z)",
                compose,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(block, service)
            body = block.group("body")
            self.assertIn("read_only: true", body, service)
            self.assertRegex(body, r"cap_drop:\s*\n\s*- ALL", service)
            self.assertIn("no-new-privileges:true", body, service)
            self.assertRegex(body, r"pids_limit:\s*\d+", service)
            self.assertRegex(body, r"stop_grace_period:\s*\d+s", service)

        self.assertEqual(compose.count("healthcheck:"), 1)
        self.assertEqual(compose.count('max-size: "10m"'), 1)


if __name__ == "__main__":
    unittest.main()
