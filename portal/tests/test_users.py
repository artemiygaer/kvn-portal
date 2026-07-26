import base64
import copy
import json
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from agent_client import AgentClientError
from app import STATE_MUTATION_TIMEOUT_SECONDS, create_app
from app.security import hash_password
from app.storage import PortalStorage


PASSWORD = "PortalPassword-2026-Strong"
SECRET = "ONE-TIME-FIXTURE-SECRET"
FILE_CONTENT = b"<script>alert('fixture')</script>"
ALL_SYSTEMS = [
    "tls", "reality-xhttp", "reality-tcp", "hysteria",
    "telemt", "mtg", "amneziawg", "wireguard", "ocserv",
]


class FakeAgent:
    def __init__(self):
        self.revision = "a" * 64
        self.calls = []
        self.timeouts = []
        self.users = [{
            "name": "Alice",
            "description": "Основной телефон",
            "enabled": True,
            "systems": ["hysteria", "ocserv"],
            "device": "",
            "sni_overrides": {},
            "uuid_mask": "12345678…",
            "subscription_mask": "abcdef…",
            "files": [{"name": "send.txt", "kind": "file", "label": "send.txt", "size": len(FILE_CONTENT), "content_type": "text/plain; charset=utf-8", "can_preview": True, "can_download": True}],
        }]
        self.export_error = ""
        self.client_export = {
            "revision": self.revision,
            "address_mode": "server",
            "public_ip": "8.8.4.4",
            "include_alternate": True,
            "server_address": "vpn.example.test",
            "effective_address": "vpn.example.test",
            "ip_bundle_ready": True,
            "subscription": {
                "port": 2096,
                "route_ready": True,
                "certificate_ready": False,
                "ready": False,
                "certificate_target": "site",
            },
        }

    def _data(self):
        users = copy.deepcopy(self.users)
        defaults = {"tls": "www.microsoft.com", "reality-xhttp": "github.com", "reality-tcp": "apple.com", "hysteria": "www.apple.com"}
        for user in users:
            user["effective_sni"] = {
                system: user.get("sni_overrides", {}).get(system, default)
                for system, default in defaults.items() if system in user["systems"]
            }
        return {
            "revision": self.revision,
            "client_export": copy.deepcopy(self.client_export),
            "users": users,
            "systems": ALL_SYSTEMS,
            "sni_systems": ["tls", "reality-xhttp", "reality-tcp", "hysteria"],
            "sni_choices": {
                "tls": ["www.microsoft.com", "example.com"],
                "reality-xhttp": ["github.com", "cdn.example.com"],
                "reality-tcp": ["apple.com", "tcp.example.com"],
                "hysteria": ["www.apple.com", "hysteria.example.com"],
            },
            "sni_matrix": {
                "tls": {"scope": "per_user", "default": "www.microsoft.com"},
                "reality-xhttp": {"scope": "per_user", "default": "github.com"},
                "reality-tcp": {"scope": "per_user", "default": "apple.com"},
                "hysteria": {"scope": "per_user", "default": "www.apple.com"},
                "telemt": {"scope": "service", "default": "telegram.org"},
                "mtg": {"scope": "service", "default": "cloudflare.com"},
                "amneziawg": {"scope": "not_applicable", "default": ""},
                "wireguard": {"scope": "not_applicable", "default": ""},
                "ocserv": {"scope": "service", "default": "vpn.example.com"},
            },
            "devices": ["mobile", "router"],
        }

    def call(self, method, params, timeout=None):
        self.calls.append((method, copy.deepcopy(params)))
        self.timeouts.append((method, timeout))
        if method == "state.users":
            return self._data()
        if method == "state.user":
            user = next((item for item in self.users if item["name"] == params["name"]), None)
            if user is None:
                raise AgentClientError("not_found: missing")
            return {
                "revision": self.revision,
                "user": copy.deepcopy(user),
                "client_export": copy.deepcopy(self.client_export),
            }
        if method == "user.file":
            if params != {"name": "Alice", "filename": "send.txt"}:
                raise AgentClientError("invalid_file: denied")
            return {
                "filename": "send.txt",
                "content_type": "text/plain; charset=utf-8",
                "kind": "file",
                "content_base64": base64.b64encode(FILE_CONTENT).decode("ascii"),
            }
        if method == "user.export":
            if self.export_error:
                raise AgentClientError(self.export_error)
            if (
                params.get("name") != "Alice"
                or params.get("address_mode") not in {"server", "public-ip"}
                or set(params) != {"name", "address_mode"}
            ):
                raise AgentClientError("invalid_params: denied")
            mode = params["address_mode"]
            archive = b"PK\x03\x04fixture-" + SECRET.encode("ascii")
            return {
                "address_mode": mode,
                "archive_filename": f"kvn-Alice-{mode}.zip",
                "archive_content_type": "application/zip",
                "archive_size": len(archive),
                "archive_base64": base64.b64encode(archive).decode("ascii"),
                "text_filename": f"kvn-Alice-{mode}.txt",
                "text_content_type": "text/plain; charset=utf-8",
                "text_size": len(FILE_CONTENT),
                "text_base64": base64.b64encode(FILE_CONTENT).decode("ascii"),
                "manifest": {"schema": 1},
            }
        if method == "user.activity":
            if params != {"name": "Alice"}:
                raise AgentClientError("not_found: missing")
            return {
                "name": "Alice", "generated_at": 1_800_000_000,
                "privacy": {"client_endpoints": "hidden", "raw_logs": "excluded"},
                "systems": [
                    {
                        "system": "hysteria", "status": "active", "source": "hysteria-api", "reason": "",
                        "rx_bytes": 12, "tx_bytes": 34, "connections": 1, "online": True,
                        "endpoint": "198.51.100.77:443", "private_key": SECRET, "config": FILE_CONTENT.decode(),
                    },
                    {
                        "system": "mtg", "status": "unsupported", "source": "mtg-shared-secret",
                        "reason": "shared_secret_has_no_attribution", "secret": SECRET,
                    },
                ],
            }
        if method == "state.reconcile":
            if params:
                raise AgentClientError("invalid_params: denied")
            return {
                "changed": True,
                "revision": self.revision,
                "plan": {"changed": True, "changed_paths": ["amneziawg/awg0.conf"], "services": {}},
                "apply": {"outcome": "applied", "warnings": [], "reconcile_required": False},
                "user": None,
                "secrets": {},
            }
        if method != "state.apply":
            raise AssertionError(method)
        if params["revision"] != self.revision:
            raise AgentClientError("revision_conflict: stale")
        action = params["action"]
        fields = params["fields"]
        if action == "update" and fields["description"] == self.users[0]["description"]:
            return {
                "changed": False,
                "revision": self.revision,
                "plan": {"changed": False, "changed_paths": [], "services": {}},
                "apply": {"hot_updated": [], "reloaded": [], "restarted": [], "warnings": []},
                "user": copy.deepcopy(self.users[0]),
                "secrets": {},
            }
        secrets = {}
        user = None
        if action == "create":
            user = {
                "name": fields["name"], "description": fields["description"],
                "enabled": fields["enabled"], "systems": fields["systems"],
                "device": fields["device"], "sni_overrides": fields["sni_overrides"],
                "uuid_mask": "masked", "subscription_mask": "masked", "files": [],
            }
            self.users.append(user)
            secrets = {"uuid": SECRET}
        elif action == "delete":
            self.users = [item for item in self.users if item["name"] != fields["name"]]
        elif action in {"rotate", "rotate-subscription", "reset-ocserv"}:
            user = self.users[0]
            secrets = {"new_secret": SECRET}
        elif action == "set-enabled":
            user = self.users[0]
            user["enabled"] = fields["enabled"]
        else:
            user = self.users[0]
            user.update({key: fields[key] for key in ["description", "enabled", "systems", "device"]})
        self.revision = "b" * 64 if self.revision[0] == "a" else "c" * 64
        return {
            "changed": True,
            "revision": self.revision,
            "plan": {"changed": True, "changed_paths": ["clients/redacted/send.txt"], "services": {}},
            "apply": {"hot_updated": ["xray"], "reloaded": [], "restarted": [], "warnings": []},
            "user": copy.deepcopy(user),
            "secrets": secrets,
        }


class PortalUserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = hash_password(PASSWORD)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "portal.db"
        self.users_file = root / "users.json"
        self.users_file.write_text(json.dumps({"users": []}), encoding="utf-8")
        self.agent = FakeAgent()
        self.app = create_app({
            "TESTING": True,
            "DATABASE": self.db,
            "USERS_FILE": self.users_file,
            "PORTAL_PATH": "/gaer",
            "PORTAL_NAME": "KVN",
            "ADMIN_LOGIN": "admin",
            "ADMIN_PASSWORD_HASH": self.password_hash,
            "PROXY_SECRET": "proxy-secret",
            "HYSTERIA_SECRET": "hysteria-secret",
            "NOW_PROVIDER": lambda: 1_800_000_000,
            "AGENT_CLIENT": self.agent,
        })
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy-secret",
            "X-Real-IP": "198.51.100.8",
            "X-Forwarded-Proto": "https",
        }
        login_page = self.client.get("/gaer/login", headers=self.headers)
        csrf = self.csrf(login_page)
        response = self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": PASSWORD, "csrf_token": csrf},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 302)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def csrf(response):
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        return match.group(1).decode("ascii")

    def test_list_search_filter_and_detail_are_masked(self):
        users = self.client.get("/gaer/users?q=alice&system=hysteria&enabled=true", headers=self.headers)
        self.assertEqual(users.status_code, 200)
        self.assertIn(b"Alice", users.data)
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        self.assertEqual(detail.status_code, 200)
        self.assertIn("12345678…".encode(), detail.data)
        self.assertNotIn(SECRET.encode(), detail.data)

    def test_activity_endpoint_is_authenticated_typed_and_redacted(self):
        anonymous = self.app.test_client().get("/gaer/users/Alice/activity.json", headers=self.headers)
        self.assertEqual(anonymous.status_code, 302)
        storage = self.app.extensions["kvn_storage"]
        storage.audit(
            "admin", "198.51.100.10", "user.update", "success",
            "password=must-not-leak", now=1_800_000_000,
            target_type="user", target_name="Alice",
        )
        storage.audit(
            "admin", "198.51.100.10", "<script>alert(1)</script>", "success",
            now=1_800_000_001, target_type="user", target_name="Alice",
        )
        response = self.client.get("/gaer/users/Alice/activity.json", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["activity"]["systems"][0]["connections"], 1)
        self.assertEqual(payload["activity"]["systems"][1]["status"], "unsupported")
        self.assertEqual(payload["events"], [{
            "created_at": 1_800_000_000, "action": "user.update", "result": "success",
        }])
        serialized = json.dumps(payload, ensure_ascii=False)
        for forbidden in [SECRET, "198.51.100", "private_key", "password", "config", "<script>"]:
            self.assertNotIn(forbidden, serialized)

    def test_light_mode_has_no_background_activity_request(self):
        self.users_file.write_text(json.dumps({
            "users": [],
            "portal": {"features": {"monitoring": False, "background_refresh": False}},
        }), encoding="utf-8")
        before = len([call for call in self.agent.calls if call[0] == "user.activity"])
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        after = len([call for call in self.agent.calls if call[0] == "user.activity"])
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b'data-background-refresh="false"', detail.data)
        self.assertEqual(before, after)
        script = (Path(__file__).resolve().parents[1] / "app" / "static" / "user-activity.js").read_text(encoding="utf-8")
        self.assertIn('userActivity.dataset.backgroundRefresh !== "false"', script)

    def test_user_matrix_has_nine_columns_mixed_states_and_safe_sni(self):
        self.agent.users[0].update({
            "systems": ["tls", "telemt", "amneziawg"],
            "sni_overrides": {"tls": "example.com"},
        })
        self.agent.users.append({
            "name": "Bob", "description": "Отключённый профиль", "enabled": False,
            "systems": ["reality-xhttp", "mtg", "wireguard", "ocserv"],
            "device": "", "sni_overrides": {}, "uuid_mask": "masked", "subscription_mask": "masked", "files": [],
        })
        page = self.client.get("/gaer/users?view=matrix", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page.data.count(b"data-protocol-column"), 9)
        for marker in [b'data-access-state="enabled"', b'data-access-state="disabled"', b'data-access-state="not-assigned"', b"override", b"example.com", b"service-level SNI", b"not applicable"]:
            self.assertIn(marker, page.data)
        for forbidden in [SECRET.encode(), FILE_CONTENT, b"uuid_mask", b"subscription_mask"]:
            self.assertNotIn(forbidden, page.data)

    def test_user_matrix_distinguishes_empty_source_and_filter_no_match(self):
        no_match = self.client.get("/gaer/users?view=matrix&q=missing", headers=self.headers)
        self.assertIn(b"data-users-no-match", no_match.data)
        self.assertNotIn(b"data-users-empty", no_match.data)
        self.agent.users = []
        empty = self.client.get("/gaer/users?view=matrix", headers=self.headers)
        self.assertIn(b"data-users-empty", empty.data)
        self.assertNotIn(b"data-users-no-match", empty.data)

    def test_create_supports_all_nine_systems_and_shows_secret_once(self):
        form = self.client.get("/gaer/users/new", headers=self.headers)
        self.assertNotIn(b'name="sni_telemt"', form.data)
        self.assertNotIn(b'name="sni_mtg"', form.data)
        self.assertIn(b'name="sni_reality-xhttp"', form.data)
        self.assertIn(b"cdn.example.com", form.data)
        response = self.client.post(
            "/gaer/users/new",
            data={
                "csrf_token": self.csrf(form), "revision": "a" * 64,
                "name": "Bob", "description": "Все протоколы", "enabled": "on",
                "systems": ALL_SYSTEMS, "device": "mobile",
                "sni_tls": "example.com", "sni_hysteria": "hysteria.example.com",
                "sni_reality-xhttp": "cdn.example.com",
                "sni_reality-tcp": "tcp.example.com",
                "sni_telemt": "mtproto.example.com",
                "sni_mtg": "ignored.example.com",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(SECRET.encode(), response.data)
        apply = [params for method, params in self.agent.calls if method == "state.apply"][-1]
        self.assertIn(("state.apply", STATE_MUTATION_TIMEOUT_SECONDS), self.agent.timeouts)
        self.assertEqual(apply["fields"]["systems"], ALL_SYSTEMS)
        self.assertEqual(
            apply["fields"]["sni_overrides"],
            {
                "tls": "example.com",
                "reality-xhttp": "cdn.example.com",
                "reality-tcp": "tcp.example.com",
                "hysteria": "hysteria.example.com",
            },
        )
        detail = self.client.get("/gaer/users/Bob", headers=self.headers)
        self.assertNotIn(SECRET.encode(), detail.data)

    def test_unchanged_form_is_noop_and_audited_without_service_actions(self):
        form = self.client.get("/gaer/users/Alice/edit", headers=self.headers)
        response = self.client.post(
            "/gaer/users/Alice/edit",
            data={
                "csrf_token": self.csrf(form), "revision": "a" * 64,
                "new_name": "Alice", "description": "Основной телефон",
                "systems": ["hysteria", "ocserv"], "enabled": "on", "device": "",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Фактических изменений нет".encode(), response.data)
        with closing(sqlite3.connect(self.db)) as db:
            result, target_type, target_name = db.execute(
                "SELECT result, target_type, target_name FROM audit_events WHERE action='user.update'"
            ).fetchone()
        self.assertEqual(result, "unchanged")
        self.assertEqual((target_type, target_name), ("user", "Alice"))

    def test_stale_revision_returns_409_without_mutation(self):
        form = self.client.get("/gaer/users/Alice/edit", headers=self.headers)
        before = copy.deepcopy(self.agent.users)
        response = self.client.post(
            "/gaer/users/Alice/edit",
            data={
                "csrf_token": self.csrf(form), "revision": "0" * 64,
                "new_name": "Alice", "description": "Изменение", "systems": ["hysteria"],
                "enabled": "on",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.agent.users, before)
        self.assertIn("Обновите страницу".encode(), response.data)

    def test_user_can_be_disabled_without_confirmation(self):
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        response = self.client.post(
            "/gaer/users/Alice/toggle",
            data={
                "csrf_token": self.csrf(detail), "revision": "a" * 64,
                "enabled": "false",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(self.agent.users[0]["enabled"])

    def test_destructive_confirmation_is_required_and_single_use(self):
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        csrf = self.csrf(detail)
        missing = self.client.post(
            "/gaer/users/Alice/action",
            data={"csrf_token": csrf, "action": "rotate", "confirmation_token": ""},
            headers=self.headers,
        )
        self.assertEqual(missing.status_code, 403)
        match = re.search(
            rb'name="action" value="rotate"><input type="hidden" name="confirmation_token" value="([^"]+)"',
            detail.data,
        )
        token = match.group(1).decode("ascii")
        payload = {"csrf_token": csrf, "action": "rotate", "confirmation_token": token}
        first = self.client.post("/gaer/users/Alice/action", data=payload, headers=self.headers)
        self.assertEqual(first.status_code, 200)
        self.assertIn(SECRET.encode(), first.data)
        second = self.client.post("/gaer/users/Alice/action", data=payload, headers=self.headers)
        self.assertEqual(second.status_code, 403)
        detail_again = self.client.get("/gaer/users/Alice", headers=self.headers)
        self.assertNotIn(SECRET.encode(), detail_again.data)

    def test_download_requires_auth_and_rejects_traversal(self):
        anonymous = self.app.test_client().get(
            "/gaer/users/Alice/files/send.txt", headers=self.headers
        )
        self.assertEqual(anonymous.status_code, 302)
        valid = self.client.get("/gaer/users/Alice/files/send.txt", headers=self.headers)
        self.assertEqual(valid.status_code, 200)
        self.assertEqual(valid.data, FILE_CONTENT)
        self.assertEqual(valid.headers["Cache-Control"], "no-store")
        self.assertEqual(valid.headers["X-Content-Type-Options"], "nosniff")
        denied = self.client.get("/gaer/users/Alice/files/%2e%2e", headers=self.headers)
        self.assertEqual(denied.status_code, 400)
        with closing(sqlite3.connect(self.db)) as db:
            target = db.execute(
                "SELECT target_type, target_name FROM audit_events WHERE action='user.link.download'"
            ).fetchone()
        self.assertEqual(target, ("user", "Alice"))

    def test_export_routes_are_authenticated_no_store_and_safely_audited(self):
        anonymous = self.app.test_client().get(
            "/gaer/users/Alice/export.zip", headers=self.headers,
        )
        self.assertEqual(anonymous.status_code, 302)

        archive = self.client.get(
            "/gaer/users/Alice/export.zip?address_mode=public-ip",
            headers=self.headers,
        )
        self.assertEqual(archive.status_code, 200)
        self.assertEqual(archive.content_type, "application/zip")
        self.assertEqual(
            archive.headers["Content-Disposition"],
            'attachment; filename="kvn-Alice-public-ip.zip"',
        )
        self.assertEqual(archive.headers["Cache-Control"], "no-store")
        self.assertEqual(archive.headers["X-Content-Type-Options"], "nosniff")

        text = self.client.get(
            "/gaer/users/Alice/export.txt?address_mode=server",
            headers=self.headers,
        )
        self.assertEqual(text.status_code, 200)
        self.assertEqual(text.data, FILE_CONTENT)
        self.assertEqual(text.content_type, "text/plain; charset=utf-8")
        self.assertEqual(
            text.headers["Content-Disposition"],
            'attachment; filename="kvn-Alice-server.txt"',
        )
        self.assertEqual(text.headers["Cache-Control"], "no-store")

        before = len(self.agent.calls)
        denied = self.client.get(
            "/gaer/users/Alice/export.zip?address_mode=dns&extra=1",
            headers=self.headers,
        )
        self.assertEqual(denied.status_code, 400)
        self.assertEqual(len(self.agent.calls), before)

        with closing(sqlite3.connect(self.db)) as db:
            rows = db.execute(
                "SELECT detail, target_type, target_name "
                "FROM audit_events WHERE action='user.export' ORDER BY id"
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1:], ("user", "Alice"))
        detail = json.loads(rows[0][0])
        self.assertEqual(
            set(detail),
            {"format", "address_mode", "size", "result"},
        )
        raw = self.db.read_bytes()
        self.assertNotIn(FILE_CONTENT, raw)
        self.assertNotIn(SECRET.encode("ascii"), raw)
        self.assertNotIn(b"archive_base64", raw)

    def test_export_is_one_action_from_list_and_detail_without_secret_dom(self):
        users = self.client.get("/gaer/users", headers=self.headers)
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        for response in (users, detail):
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"data-user-export-trigger", response.data)
            self.assertIn(b"data-user-export-dialog", response.data)
            self.assertIn("ZIP для Telegram".encode(), response.data)
            self.assertIn(b"8.8.4.4", response.data)
            self.assertIn("HTTPS-подписки ограничены".encode(), response.data)
            for forbidden in (
                SECRET.encode(), FILE_CONTENT, b"archive_base64",
                b"text_base64", b"sub_token", b"private_key",
            ):
                self.assertNotIn(forbidden, response.data)

    def test_export_agent_error_is_safe_and_ip_bundle_does_not_require_ip_san(self):
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        self.assertIn(b'value="public-ip" data-export-mode', detail.data)
        self.assertNotIn(
            b'value="public-ip" data-export-mode disabled',
            detail.data,
        )
        self.agent.export_error = "agent_unavailable: fixture"
        response = self.client.get(
            "/gaer/users/Alice/export.txt?address_mode=public-ip",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(SECRET.encode(), response.data)
        self.assertNotIn(FILE_CONTENT, response.data)

    def test_preview_is_authenticated_escaped_and_no_store(self):
        anonymous = self.app.test_client().get(
            "/gaer/users/Alice/files/send.txt/view", headers=self.headers
        )
        self.assertEqual(anonymous.status_code, 302)
        response = self.client.get("/gaer/users/Alice/files/send.txt/view", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertNotIn(b"<script>alert", response.data)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        denied = self.client.get("/gaer/users/Alice/files/send.txt/inline", headers=self.headers)
        self.assertEqual(denied.status_code, 400)

    def test_karing_wireguard_qr_has_preview_and_inline_routes(self):
        original_call = self.agent.call

        def call(method, params, timeout=None):
            if method == "user.file" and params.get("filename") == "karing-wireguard.png":
                content = b"\x89PNG\r\n\x1a\nfixture"
                return {
                    "filename": "karing-wireguard.png",
                    "content_type": "image/png",
                    "kind": "karing-wireguard-qr",
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
            return original_call(method, params, timeout=timeout)

        self.agent.call = call
        preview = self.client.get(
            "/gaer/users/Alice/files/karing-wireguard.png/view", headers=self.headers,
        )
        self.assertEqual(preview.status_code, 200)
        self.assertIn(b"/gaer/users/Alice/files/karing-wireguard.png/inline", preview.data)
        inline = self.client.get(
            "/gaer/users/Alice/files/karing-wireguard.png/inline", headers=self.headers,
        )
        self.assertEqual(inline.status_code, 200)
        self.assertEqual(inline.content_type, "image/png")

    def test_audit_database_does_not_contain_secret_or_file_content(self):
        detail = self.client.get("/gaer/users/Alice", headers=self.headers)
        match = re.search(
            rb'name="action" value="rotate"><input type="hidden" name="confirmation_token" value="([^"]+)"',
            detail.data,
        )
        self.client.post(
            "/gaer/users/Alice/action",
            data={
                "csrf_token": self.csrf(detail), "action": "rotate",
                "confirmation_token": match.group(1).decode("ascii"),
            },
            headers=self.headers,
        )
        self.client.get("/gaer/users/Alice/files/send.txt", headers=self.headers)
        raw = self.db.read_bytes()
        self.assertNotIn(SECRET.encode(), raw)
        self.assertNotIn(FILE_CONTENT, raw)

    def test_reconcile_route_is_csrf_protected_and_audited(self):
        page = self.client.get("/gaer/users", headers=self.headers)
        denied = self.client.post("/gaer/reconcile", headers=self.headers)
        self.assertEqual(denied.status_code, 403)
        response = self.client.post(
            "/gaer/reconcile",
            data={"csrf_token": self.csrf(page)},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Состояние повторно применено".encode(), response.data)
        self.assertIn(("state.reconcile", {}), self.agent.calls)
        self.assertIn(("state.reconcile", STATE_MUTATION_TIMEOUT_SECONDS), self.agent.timeouts)
        with closing(sqlite3.connect(self.db)) as db:
            event = db.execute(
                "SELECT result FROM audit_events WHERE action='state.reconcile'"
            ).fetchone()
        self.assertEqual(event[0], "success")


class PortalAuditMigrationTests(unittest.TestCase):
    def test_target_migration_is_idempotent_and_preserves_sessions_and_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legacy.db"
            with closing(sqlite3.connect(database)) as db:
                db.executescript("""
                    CREATE TABLE sessions (
                        session_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL,
                        created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                        absolute_expires_at INTEGER NOT NULL, ip TEXT NOT NULL,
                        user_agent TEXT NOT NULL
                    );
                    CREATE TABLE audit_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL,
                        actor TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL,
                        result TEXT NOT NULL, detail TEXT NOT NULL,
                        correlation_id TEXT NOT NULL DEFAULT ''
                    );
                """)
                db.execute("INSERT INTO sessions VALUES ('hash','csrf',1,1,9999999999,'127.0.0.1','agent')")
                db.execute("INSERT INTO audit_events VALUES (1,1,'admin','127.0.0.1','user.update','success','','legacy')")
                db.commit()
            PortalStorage(database)
            PortalStorage(database)
            with closing(sqlite3.connect(database)) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(audit_events)")}
                session_count = db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                event = db.execute(
                    "SELECT action, target_type, target_name FROM audit_events WHERE id=1"
                ).fetchone()
            self.assertTrue({"target_type", "target_name"}.issubset(columns))
            self.assertEqual(session_count, 1)
            self.assertEqual(event, ("user.update", "", ""))


if __name__ == "__main__":
    unittest.main()
