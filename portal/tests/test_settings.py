import io
import json
import os
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app import create_app
from agent_client import AgentClientError
from app.security import hash_password


PASSWORD = "SettingsPortalPassword-2026"


class FakeSettingsAgent:
    def __init__(self, update_dir):
        self.calls = []
        self.timeouts = []
        self.update_dir = Path(update_dir)
        self.update_error = ""
        self.inspect_error = ""
        self.github_settings_error = ""
        self.github_check_error = ""
        self.github_prepare_error = ""
        self.github_settings = {
            "enabled": True,
            "repository": "artemiygaer/kvn-portal",
            "channel": "stable",
            "tag": "",
            "asset_preference": "deploy",
        }
        self.github_release = {
            "ok": True,
            "repository": "artemiygaer/kvn-portal",
            "channel": "stable",
            "tag": "v2026.07.24",
            "release_id": 71,
            "release_name": "KVN VPN 2026.07.24",
            "published_at": "2026-07-24T10:00:00Z",
            "notes": "<script>alert('fixture')</script>\nБезопасное описание.",
            "assets": [{
                "id": 72,
                "name": "kvn-vpn-deploy.tar.gz",
                "kind": "deploy",
                "size": 4096,
                "sha256": "d" * 64,
            }],
            "asset": {
                "id": 72,
                "name": "kvn-vpn-deploy.tar.gz",
                "kind": "deploy",
                "size": 4096,
                "sha256": "d" * 64,
            },
            "authenticated": False,
        }
        self.performance = {
            "revision": "a" * 64, "profile": "standard",
            "features": {"monitoring": True, "background_refresh": True},
        }
        self.client_export = {
            "revision": "a" * 64,
            "address_mode": "server",
            "public_ip": "",
            "include_alternate": False,
            "server_address": "vpn.example.test",
            "effective_address": "vpn.example.test",
            "ip_bundle_ready": False,
            "subscription": {
                "port": 2096,
                "route_ready": False,
                "certificate_ready": False,
                "ready": False,
                "certificate_target": "site",
            },
        }

    def call(self, method, params, *, timeout=None):
        self.calls.append((method, dict(params)))
        self.timeouts.append(timeout)
        if method == "sni.routes":
            return {"revision": "a" * 64, "systems": [], "routes": {}}
        if method == "project.release.settings":
            if self.github_settings_error:
                raise AgentClientError(self.github_settings_error)
            return dict(self.github_settings)
        if method == "project.release.check":
            if self.github_check_error:
                raise AgentClientError(self.github_check_error)
            return json.loads(json.dumps(self.github_release))
        if method == "project.release.prepare":
            if self.github_prepare_error:
                raise AgentClientError(self.github_prepare_error)
            self.update_dir.mkdir(parents=True, exist_ok=True)
            sha256 = params["asset_sha256"]
            path = self.update_dir / f"kvn-vpn-deploy-github-{sha256[:12]}.tar.gz"
            path.write_bytes(b"\x1f\x8b" + b"g" * 4094)
            return {
                "ok": True,
                "ready": True,
                "reused": False,
                "repository": "artemiygaer/kvn-portal",
                "channel": "stable",
                "tag": self.github_release["tag"],
                "release_id": params["release_id"],
                "asset_id": params["asset_id"],
                "archive": f"portal-data/updates/{path.name}",
                "archive_name": "kvn-vpn-deploy.tar.gz",
                "archive_size": path.stat().st_size,
                "archive_sha256": sha256,
                "archive_members": 42,
                "archive_kind": "deploy",
                "validation": {
                    "api_digest": True,
                    "download_sha256": True,
                    "internal_manifest": {
                        "internal": "deploy-inspector",
                        "member_count": 42,
                    },
                },
            }
        if method == "mtproto.status":
            return {
                "revision": "a" * 64,
                "origins": ["external", "local-site"],
                "services": {
                    "telemt": {
                        "label": "Telemt", "origin": "external", "sni": "yandex.com",
                        "target": "yandex.com:443", "credential_scope": "per-user",
                        "public_port": 443, "direct_port": 2446,
                    },
                    "mtg": {
                        "label": "mtg", "origin": "external", "sni": "ya.ru",
                        "target": "ya.ru:443", "credential_scope": "shared",
                        "public_port": 443, "direct_port": 2447,
                    },
                },
            }
        if method == "mtproto.diagnose":
            return {
                "system": params["system"], "origin": "external", "sni": "example.com",
                "target": "example.com:443", "status": "ready", "can_apply": True,
                "timeout_seconds": 3.0, "checks": [],
            }
        if method == "mtproto.apply":
            return {"changed": True, "apply": {"outcome": "applied"}}
        if method == "portal.performance":
            return dict(self.performance, features=dict(self.performance["features"]))
        if method == "portal.performance.update":
            profile = params["profile"]
            if profile == "standard":
                features = {"monitoring": True, "background_refresh": True}
            elif profile == "light":
                features = {"monitoring": False, "background_refresh": False}
            else:
                features = {
                    "monitoring": params["monitoring"],
                    "background_refresh": params["background_refresh"],
                }
            changed_features = [name for name, value in features.items() if value != self.performance["features"][name]]
            self.performance = {
                "revision": "b" * 64, "profile": profile,
                "features": features,
            }
            return dict(self.performance, changed=bool(changed_features), changed_features=changed_features)
        if method == "client.export.settings":
            return json.loads(json.dumps(self.client_export))
        if method == "client.export.update":
            if params["revision"] != self.client_export["revision"]:
                raise AgentClientError("revision_conflict: stale")
            self.client_export.update({
                "revision": "b" * 64,
                "address_mode": params["address_mode"],
                "public_ip": params["public_ip"],
                "include_alternate": params["include_alternate"],
                "effective_address": (
                    params["public_ip"]
                    if params["address_mode"] == "public-ip"
                    else "vpn.example.test"
                ),
                "ip_bundle_ready": bool(params["public_ip"]),
                "subscription": {
                    "port": 2096,
                    "route_ready": bool(params["public_ip"]),
                    "certificate_ready": False,
                    "ready": False,
                    "certificate_target": "site",
                },
            })
            return {
                "changed": True,
                "revision": self.client_export["revision"],
                "settings": json.loads(json.dumps(self.client_export)),
                "plan": {"changed": True, "changed_paths": ["clients/"]},
                "apply": {
                    "outcome": "applied", "reconcile_required": False,
                    "warnings": [], "fallbacks": [], "failed": [],
                },
            }
        if method == "sni.diagnose":
            return {"sni": params["sni"], "dns": "ok", "addresses": 1, "tls": "ok", "reason": "ok"}
        if method == "project.update.inspect":
            if self.inspect_error:
                raise AgentClientError(self.inspect_error)
            path = self.update_dir / Path(params["archive"]).name
            is_release = "release-linux-amd64" in params["archive"]
            return {
                "ok": True,
                "archive": params["archive"],
                "archive_name": path.name,
                "archive_size": path.stat().st_size,
                "archive_sha256": "c" * 64,
                "archive_members": 42,
                "archive_kind": "release" if is_release else "deploy",
                "release_source": {},
                "release_images": {},
                "required_free_bytes": 0,
            }
        if method == "project.update":
            if self.update_error:
                raise AgentClientError(self.update_error)
            return {
                "ok": True,
                "archive": params["archive"],
                "archive_name": "kvn-vpn-deploy-test.tar.gz",
                "archive_size": 4096,
                "archive_sha256": "c" * 64,
                "archive_members": 42,
                "unit": "kvn-project-update-test",
                "journal_command": "journalctl -u kvn-project-update-test -n 200 --no-pager",
                "recovery_command": "sudo ls -ld .update-backups/* 2>/dev/null || true",
                "command": {"stderr": ""},
                "correlation_id": "update-test",
            }
        raise AssertionError(method)


class PortalSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "portal.db"
        self.users = root / "users.json"
        self.users.write_text(json.dumps({"users": []}), encoding="utf-8")
        self.upload_dir = root / "updates"
        self.agent = FakeSettingsAgent(self.upload_dir)
        self.app = create_app({
            "TESTING": True, "DATABASE": self.db, "USERS_FILE": self.users,
            "PORTAL_PATH": "/gaer", "ADMIN_LOGIN": "admin",
            "ADMIN_PASSWORD_HASH": hash_password(PASSWORD), "PROXY_SECRET": "proxy",
            "HYSTERIA_SECRET": "hysteria", "AGENT_CLIENT": self.agent,
            "UPDATE_UPLOAD_DIR": self.upload_dir, "UPDATE_UPLOAD_RELATIVE_DIR": "portal-data/updates",
            "BUILD_ID": "fixture-build",
            "NOW_PROVIDER": lambda: 1_800_000_000,
        })
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy", "X-Real-IP": "198.51.100.9",
            "X-Forwarded-Proto": "https",
        }
        login = self.client.get("/gaer/login", headers=self.headers)
        self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": PASSWORD, "csrf_token": self.csrf(login)},
            headers=self.headers,
        )

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def csrf(response):
        return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()

    def test_update_requires_reauth_and_never_audits_password(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        self.assertNotIn(b"update_root_password", page.data)
        for marker in [b"data-update-prepare", b"data-update-progress", b"data-update-cancel", b"data-update-retry"]:
            self.assertIn(marker, page.data)
        self.assertNotIn(PASSWORD.encode(), page.data)
        prepared = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"x" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data", headers={**self.headers, "Accept": "application/json"},
        ).get_json()["prepared"]
        ready_page = self.client.get("/gaer/settings", headers=self.headers)
        for marker in [b"update_root_password", b"data-sensitive-submit", b"project-update-hint", b"data-sensitive-submit-status"]:
            self.assertIn(marker, ready_page.data)
        response = self.client.post(
            "/gaer/settings/update/start",
            data={
                "csrf_token": self.csrf(ready_page), "prepared_id": prepared["id"],
                "root_password": PASSWORD, "update_mode": "full",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn((b"c" * 64), response.data)
        self.assertNotIn(PASSWORD.encode(), response.data)
        method, params = self.agent.calls[-1]
        self.assertEqual(method, "project.update")
        self.assertEqual(params["root_password"], PASSWORD)
        self.assertRegex(params["session_owner"], r"^[0-9a-f]{64}$")
        with closing(sqlite3.connect(self.db)) as db:
            detail = db.execute("SELECT detail FROM audit_events WHERE action='project.update'").fetchone()[0]
        self.assertNotIn(PASSWORD, detail)
        self.assertIn("sha256", detail)

    def test_github_check_is_read_only_and_release_notes_are_escaped(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        for marker in [
            "Текущая сборка".encode(),
            b"artemiygaer/kvn-portal",
            "Обновление вручную с сервера".encode(),
            b"sudo ./tools/project-backup.sh",
            b"sha256sum &lt;archive&gt;",
            b"sudo ./update.sh &lt;archive&gt;",
            b"sudo ./update.sh --bootstrap-only &lt;archive&gt;",
        ]:
            self.assertIn(marker, page.data)

        checked = self.client.post(
            "/gaer/settings/update/github/check",
            data={"csrf_token": self.csrf(page)},
            headers=self.headers,
        )
        self.assertEqual(checked.status_code, 200)
        self.assertIn(b"&lt;script&gt;", checked.data)
        self.assertNotIn(b"<script>", checked.data)
        self.assertIn("Безопасное описание".encode(), checked.data)
        methods = [method for method, _params in self.agent.calls]
        self.assertIn("project.release.check", methods)
        self.assertNotIn("project.release.prepare", methods)
        self.assertNotIn("project.update", methods)
        with closing(sqlite3.connect(self.db)) as db:
            detail = db.execute(
                "SELECT detail FROM audit_events WHERE action='project.release.check'"
            ).fetchone()[0]
        self.assertNotIn("script", detail)
        self.assertNotIn("fixture", detail)

    def test_github_check_prepare_and_start_are_three_separate_actions(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        checked_response = self.client.post(
            "/gaer/settings/update/github/check",
            data={"csrf_token": self.csrf(page)},
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(checked_response.status_code, 200)
        release = checked_response.get_json()["release"]
        self.assertNotIn("authenticated", release)
        self.assertFalse(any(method == "project.release.prepare" for method, _ in self.agent.calls))
        self.assertFalse(any(method == "project.update" for method, _ in self.agent.calls))

        prepared_response = self.client.post(
            "/gaer/settings/update/github/prepare",
            data={
                "csrf_token": self.csrf(page),
                "release_id": release["release_id"],
                "asset_id": release["asset"]["id"],
                "asset_sha256": release["asset"]["sha256"],
            },
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(prepared_response.status_code, 201)
        prepared = prepared_response.get_json()["prepared"]
        stored = self.app.extensions["kvn_storage"].get_prepared_update(prepared["id"])
        self.assertEqual(stored["metadata"]["source"], "github")
        self.assertEqual(stored["metadata"]["tag"], "v2026.07.24")
        self.assertFalse(any(method == "project.update" for method, _ in self.agent.calls))

        ready_page = self.client.get("/gaer/settings", headers=self.headers)
        self.assertIn("Готов к обновлению".encode(), ready_page.data)
        self.assertIn("Проверено на сервере · GitHub".encode(), ready_page.data)
        self.assertIn(b'name="root_password"', ready_page.data)
        started = self.client.post(
            "/gaer/settings/update/start",
            data={
                "csrf_token": self.csrf(ready_page),
                "prepared_id": prepared["id"],
                "root_password": PASSWORD,
                "update_mode": "full",
            },
            headers=self.headers,
        )
        self.assertEqual(started.status_code, 200)
        sequence = [
            method for method, _params in self.agent.calls
            if method in {
                "project.release.check",
                "project.release.prepare",
                "project.update",
            }
        ]
        self.assertEqual(sequence, [
            "project.release.check",
            "project.release.prepare",
            "project.update",
        ])
        with closing(sqlite3.connect(self.db)) as db:
            audit_actions = [
                row[0] for row in db.execute(
                    "SELECT action FROM audit_events "
                    "WHERE action LIKE 'project.release.%' OR action='project.update' "
                    "ORDER BY id"
                ).fetchall()
            ]
        self.assertEqual(audit_actions, [
            "project.release.check",
            "project.release.prepare",
            "project.update",
        ])

    def test_github_error_states_are_safe_and_point_to_manual_fallback(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        cases = [
            ("release_not_found: private fixture", 404),
            ("github_rate_limited: token=fixture-secret", 429),
            ("github_unavailable: dns fixture", 502),
        ]
        for agent_error, expected_status in cases:
            with self.subTest(agent_error=agent_error):
                self.agent.github_check_error = agent_error
                response = self.client.post(
                    "/gaer/settings/update/github/check",
                    data={"csrf_token": self.csrf(page)},
                    headers={**self.headers, "Accept": "application/json"},
                )
                self.assertEqual(response.status_code, expected_status)
                payload = response.get_json()
                self.assertTrue(payload["manual_fallback"])
                self.assertIn("ручн", payload["error"].lower())
                serialized = json.dumps(payload, ensure_ascii=False)
                self.assertNotIn("fixture-secret", serialized)
                self.assertNotIn("token=", serialized)
        self.agent.github_check_error = ""

        self.agent.github_prepare_error = "digest_mismatch: fixture-secret"
        rejected = self.client.post(
            "/gaer/settings/update/github/prepare",
            data={
                "csrf_token": self.csrf(page),
                "release_id": 71,
                "asset_id": 72,
                "asset_sha256": "d" * 64,
            },
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(rejected.status_code, 409)
        self.assertIn("SHA-256".encode(), rejected.data)
        self.assertNotIn(b"fixture-secret", rejected.data)
        self.assertIsNone(self.app.extensions["kvn_storage"].latest_prepared_update())
        rendered = self.client.post(
            "/gaer/settings/update/github/prepare",
            data={
                "csrf_token": self.csrf(page),
                "release_id": 71,
                "asset_id": 72,
                "asset_sha256": "d" * 64,
            },
            headers=self.headers,
        )
        self.assertEqual(rendered.status_code, 409)
        self.assertIn("Архив удалён".encode(), rendered.data)
        self.assertIn("Ручная загрузка".encode(), rendered.data)

    def test_github_disabled_up_to_date_and_agent_restart_states(self):
        self.agent.github_settings["enabled"] = False
        disabled = self.client.get("/gaer/settings", headers=self.headers)
        self.assertIn("Источник отключён".encode(), disabled.data)
        self.assertIn("Ручная загрузка".encode(), disabled.data)
        self.assertNotIn(b"github_pat_", disabled.data)

        self.agent.github_settings["enabled"] = True
        self.app.config["BUILD_ID"] = "2026.07.24"
        checked = self.client.post(
            "/gaer/settings/update/github/check",
            data={"csrf_token": self.csrf(disabled)},
            headers=self.headers,
        )
        self.assertEqual(checked.status_code, 200)
        self.assertIn("Уже установлено".encode(), checked.data)

        self.agent.github_settings_error = "unknown_method: restart agent"
        unavailable = self.client.get("/gaer/settings", headers=self.headers)
        self.assertIn("Перезапустите kvn-portal-agent.service".encode(), unavailable.data)
        self.assertIn("ручную загрузку".encode(), unavailable.data)
        self.assertNotIn(b"restart agent", unavailable.data)

    def test_github_prepared_archive_uses_common_discard_path(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        first = self.client.post(
            "/gaer/settings/update/github/prepare",
            data={
                "csrf_token": self.csrf(page),
                "release_id": 71,
                "asset_id": 72,
                "asset_sha256": "d" * 64,
            },
            headers={**self.headers, "Accept": "application/json"},
        ).get_json()["prepared"]
        archive = next(self.upload_dir.glob("*-github-*.tar.gz"))
        prepared = self.client.post(
            "/gaer/settings/update/github/prepare",
            data={
                "csrf_token": self.csrf(page),
                "release_id": 71,
                "asset_id": 72,
                "asset_sha256": "d" * 64,
            },
            headers={**self.headers, "Accept": "application/json"},
        ).get_json()["prepared"]
        self.assertNotEqual(first["id"], prepared["id"])
        self.assertTrue(archive.exists())
        self.assertIsNone(
            self.app.extensions["kvn_storage"].get_prepared_update(first["id"])
        )
        ready_page = self.client.get("/gaer/settings", headers=self.headers)
        discarded = self.client.post(
            "/gaer/settings/update/discard",
            data={
                "csrf_token": self.csrf(ready_page),
                "prepared_id": prepared["id"],
            },
            headers=self.headers,
        )
        self.assertEqual(discarded.status_code, 302)
        self.assertFalse(archive.exists())
        self.assertIsNone(self.app.extensions["kvn_storage"].latest_prepared_update())

    def test_started_github_archive_can_be_prepared_again_without_unique_error(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        payload = {
            "csrf_token": self.csrf(page),
            "release_id": 71,
            "asset_id": 72,
            "asset_sha256": "d" * 64,
        }
        first = self.client.post(
            "/gaer/settings/update/github/prepare",
            data=payload,
            headers={**self.headers, "Accept": "application/json"},
        ).get_json()["prepared"]
        started = self.client.post(
            "/gaer/settings/update/start",
            data={
                "csrf_token": self.csrf(page),
                "prepared_id": first["id"],
                "root_password": PASSWORD,
                "update_mode": "full",
            },
            headers=self.headers,
        )
        self.assertEqual(started.status_code, 200)
        second_response = self.client.post(
            "/gaer/settings/update/github/prepare",
            data=payload,
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(second_response.status_code, 201)
        second = second_response.get_json()["prepared"]
        self.assertNotEqual(first["id"], second["id"])
        self.assertIsNone(
            self.app.extensions["kvn_storage"].get_prepared_update(first["id"])
        )
        self.assertEqual(
            self.app.extensions["kvn_storage"].latest_prepared_update()["id"],
            second["id"],
        )
        self.assertTrue(next(self.upload_dir.glob("*-github-*.tar.gz")).exists())

    def test_reprepare_does_not_replace_archive_while_start_is_being_claimed(self):
        storage = self.app.extensions["kvn_storage"]
        metadata = {
            "archive": "portal-data/updates/kvn-vpn-deploy-github-busy.tar.gz",
            "archive_name": "kvn-vpn-deploy.tar.gz",
            "archive_size": 4096,
            "archive_sha256": "d" * 64,
            "archive_kind": "deploy",
            "source": "github",
        }
        first = storage.publish_prepared_update(metadata, 1_800_000_000)["update"]
        claimed = storage.claim_prepared_update(first["id"], 1_800_000_001)
        self.assertEqual(claimed["status"], "starting")
        repeated = storage.publish_prepared_update(metadata, 1_800_000_002)
        self.assertTrue(repeated["busy"])
        self.assertEqual(repeated["update"]["id"], first["id"])
        self.assertIsNone(storage.latest_prepared_update())

    def test_client_export_invalid_ip_stays_in_portal_and_valid_save_is_typed(self):
        page = self.client.get("/gaer/settings#client-export", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'id="client-export"', page.data)
        self.assertIn("Публичный IPv4 ещё не задан".encode(), page.data)
        csrf = self.csrf(page)
        before = len([
            call for call in self.agent.calls
            if call[0] == "client.export.update"
        ])
        denied = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": csrf,
                "action": "client_export",
                "revision": "a" * 64,
                "address_mode": "public-ip",
                "public_ip": "10.0.0.1",
                "include_alternate": "on",
            },
            headers=self.headers,
        )
        self.assertEqual(denied.status_code, 200)
        self.assertIn("Нужен публичный глобальный IPv4".encode(), denied.data)
        after = len([
            call for call in self.agent.calls
            if call[0] == "client.export.update"
        ])
        self.assertEqual(after, before)

        allowed = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(denied),
                "action": "client_export",
                "revision": "a" * 64,
                "address_mode": "public-ip",
                "public_ip": "8.8.4.4",
                "include_alternate": "on",
            },
            headers=self.headers,
        )
        self.assertEqual(allowed.status_code, 200)
        method, params = next(
            call for call in reversed(self.agent.calls)
            if call[0] == "client.export.update"
        )
        self.assertEqual(method, "client.export.update")
        self.assertEqual(params, {
            "revision": "a" * 64,
            "address_mode": "public-ip",
            "public_ip": "8.8.4.4",
            "include_alternate": True,
        })
        self.assertIn("IP SAN сертификата".encode(), allowed.data)
        self.assertIn("не выдаются по IP".encode(), allowed.data)
        with closing(sqlite3.connect(self.db)) as db:
            detail = db.execute(
                "SELECT detail FROM audit_events "
                "WHERE action='client.export.settings'"
            ).fetchone()[0]
        self.assertNotIn("8.8.4.4", detail)
        self.assertNotIn("password", detail)
        self.assertEqual(
            json.loads(detail),
            {
                "address_mode": "public-ip",
                "include_alternate": True,
                "has_public_ip": True,
            },
        )

    def test_client_export_revision_conflict_returns_409(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        self.agent.client_export["revision"] = "b" * 64
        response = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page),
                "action": "client_export",
                "revision": "a" * 64,
                "address_mode": "server",
                "public_ip": "",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 409)
        self.assertIn("Данные уже изменились".encode(), response.data)
        static = Path(__file__).resolve().parents[1] / "app/static"
        script = "\n".join(
            (static / name).read_text(encoding="utf-8")
            for name in ("base.js", "update.js")
        )
        for marker in ["formdata", "clearPassword", "aria-busy", "XMLHttpRequest", "setUpdateState"]:
            self.assertIn(marker, script)

    def test_staged_update_is_persisted_and_started_by_opaque_id(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        response = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"x" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(response.status_code, 201)
        prepared = response.get_json()["prepared"]
        self.assertRegex(prepared["id"], r"^[A-Za-z0-9_-]{32}$")
        self.assertNotIn("archive", prepared)
        self.assertEqual(self.agent.calls[-1][0], "project.update.inspect")
        self.assertEqual(self.agent.timeouts[-1], 1800.0)
        self.assertFalse(any(method == "project.update" for method, _params in self.agent.calls))
        self.assertEqual(self.app.extensions["kvn_storage"].latest_prepared_update()["id"], prepared["id"])

        start = self.client.post(
            "/gaer/settings/update/start",
            data={
                "csrf_token": self.csrf(page),
                "prepared_id": prepared["id"],
                "update_mode": "full",
                "root_password": PASSWORD,
            },
            headers=self.headers,
        )
        self.assertEqual(start.status_code, 200)
        method, params = self.agent.calls[-1]
        self.assertEqual(method, "project.update")
        self.assertEqual(params["expected_sha256"], "c" * 64)
        self.assertEqual(params["root_password"], PASSWORD)
        self.assertRegex(params["session_owner"], r"^[0-9a-f]{64}$")
        self.assertEqual(self.app.extensions["kvn_storage"].get_prepared_update(prepared["id"])["status"], "started")
        duplicate = self.client.post(
            "/gaer/settings/update/start",
            data={"csrf_token": self.csrf(page), "prepared_id": prepared["id"], "root_password": PASSWORD},
            headers=self.headers,
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(sum(method == "project.update" for method, _params in self.agent.calls), 1)
        with closing(sqlite3.connect(self.db)) as db:
            audit = json.dumps(db.execute("SELECT action, detail FROM audit_events").fetchall())
        self.assertNotIn(PASSWORD, audit)

    def test_failed_start_returns_archive_to_ready(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        prepared = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"y" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        ).get_json()["prepared"]
        self.agent.update_error = "root_password_denied: неверный пароль"
        response = self.client.post(
            "/gaer/settings/update/start",
            data={"csrf_token": self.csrf(page), "prepared_id": prepared["id"], "root_password": "wrong"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.app.extensions["kvn_storage"].latest_prepared_update()["id"], prepared["id"])

    def test_no_js_prepare_redirects_to_ready_card_and_discard(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        prepared_response = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"j" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers=self.headers,
        )
        self.assertEqual(prepared_response.status_code, 302)
        self.assertTrue(prepared_response.headers["Location"].endswith("/gaer/settings?prepared=1"))
        ready_page = self.client.get(prepared_response.headers["Location"], headers=self.headers)
        self.assertIn("Готов к обновлению".encode(), ready_page.data)
        prepared = self.app.extensions["kvn_storage"].latest_prepared_update()
        discard = self.client.post(
            "/gaer/settings/update/discard",
            data={"csrf_token": self.csrf(ready_page), "prepared_id": prepared["id"]},
            headers=self.headers,
        )
        self.assertEqual(discard.status_code, 302)
        self.assertIsNone(self.app.extensions["kvn_storage"].latest_prepared_update())
        self.assertFalse(any(self.upload_dir.glob("kvn-vpn-deploy-*.tar.gz")))

    def test_prepared_update_claim_is_atomic(self):
        storage = self.app.extensions["kvn_storage"]
        published = storage.publish_prepared_update({
            "archive": "portal-data/updates/kvn-vpn-deploy-1800000000-123456789abc.tar.gz",
            "archive_name": "kvn-vpn-deploy-1800000000-123456789abc.tar.gz",
            "archive_size": 2048,
            "archive_sha256": "d" * 64,
            "archive_kind": "deploy",
        }, 1_800_000_000)["update"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda _item: storage.claim_prepared_update(published["id"]), range(2)))
        self.assertEqual(sum(claim is not None for claim in claims), 1)

    def test_failed_prepare_keeps_previous_ready_after_new_login(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        first = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"a" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        ).get_json()["prepared"]
        first_path = next(self.upload_dir.glob("kvn-vpn-deploy-*.tar.gz"))
        os.utime(first_path, (1_800_000_000, 1_800_000_000))
        self.agent.inspect_error = "invalid_archive: повреждён manifest"
        failed = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"b" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(failed.status_code, 400)
        self.assertEqual(self.app.extensions["kvn_storage"].latest_prepared_update()["id"], first["id"])
        self.assertTrue(first_path.exists())
        self.assertEqual(len(list(self.upload_dir.glob("kvn-vpn-deploy-*.tar.gz"))), 1)

        self.app.extensions["kvn_storage"].invalidate_all_sessions()
        login = self.client.get("/gaer/login", headers=self.headers)
        self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": PASSWORD, "csrf_token": self.csrf(login)},
            headers=self.headers,
        )
        restored = self.client.get("/gaer/settings", headers=self.headers)
        self.assertIn(first["id"].encode(), restored.data)

    def test_retention_removes_old_record_but_respects_running_marker(self):
        storage = self.app.extensions["kvn_storage"]
        self.app.config.update(UPDATE_UPLOAD_RETENTION_SECONDS=1, UPDATE_UPLOAD_MIN_AGE_SECONDS=0)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

        def old_started(suffix):
            name = f"kvn-vpn-deploy-1700000000-{suffix}.tar.gz"
            path = self.upload_dir / name
            path.write_bytes(b"\x1f\x8b" + b"o" * 2048)
            os.utime(path, (1_700_000_000, 1_700_000_000))
            row = storage.publish_prepared_update({
                "archive": f"portal-data/updates/{name}",
                "archive_name": name,
                "archive_size": path.stat().st_size,
                "archive_sha256": suffix[0] * 64,
                "archive_kind": "deploy",
            }, 1_700_000_000)["update"]
            storage.claim_prepared_update(row["id"], 1_700_000_001)
            storage.finish_prepared_update(row["id"], 1_700_000_002)
            return row, path

        removed, removed_path = old_started("aaaaaaaaaaaa")
        running, running_path = old_started("bbbbbbbbbbbb")
        running_path.with_name(running_path.name + ".running").touch()
        page = self.client.get("/gaer/settings", headers=self.headers)
        response = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"n" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertFalse(removed_path.exists())
        self.assertIsNone(storage.get_prepared_update(removed["id"]))
        self.assertTrue(running_path.exists())
        self.assertIsNotNone(storage.get_prepared_update(running["id"]))

    def test_update_endpoints_reject_unauthorized_stale_missing_and_changed(self):
        anonymous = self.app.test_client()
        self.assertEqual(
            anonymous.post("/gaer/settings/update/start", data={"prepared_id": "A" * 32}, headers=self.headers).status_code,
            403,
        )
        page = self.client.get("/gaer/settings", headers=self.headers)
        update_calls_before = sum(method == "project.update" for method, _params in self.agent.calls)
        stale = self.client.post(
            "/gaer/settings/update/start",
            data={"csrf_token": self.csrf(page), "prepared_id": "A" * 32, "root_password": PASSWORD},
            headers=self.headers,
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(sum(method == "project.update" for method, _params in self.agent.calls), update_calls_before)

        for index, (agent_error, expected_status) in enumerate([
            ("not_found: архив отсутствует", 404),
            ("archive_changed: архив изменён", 409),
        ]):
            prepared = self.client.post(
                "/gaer/settings/update/prepare",
                data={
                    "csrf_token": self.csrf(page),
                    "archive": (io.BytesIO(b"\x1f\x8b" + bytes([65 + index]) * 2048), "kvn-vpn-deploy.tar.gz"),
                },
                content_type="multipart/form-data",
                headers={**self.headers, "Accept": "application/json"},
            ).get_json()["prepared"]
            self.agent.update_error = agent_error
            response = self.client.post(
                "/gaer/settings/update/start",
                data={"csrf_token": self.csrf(page), "prepared_id": prepared["id"], "root_password": PASSWORD},
                headers={**self.headers, "Accept": "application/json"},
            )
            self.assertEqual(response.status_code, expected_status)
            self.assertEqual(self.app.extensions["kvn_storage"].latest_prepared_update()["id"], prepared["id"])
            self.agent.update_error = ""

    def test_upload_limits_streaming_and_timeout_are_scoped(self):
        self.assertEqual(self.app.config["UPDATE_UPLOAD_MAX_BYTES"], 2 * 1024 * 1024 * 1024)
        self.assertEqual(self.app.config["UPDATE_UPLOAD_DISK_RESERVE_BYTES"], 512 * 1024 * 1024)
        self.assertEqual(self.app.config["UPDATE_RPC_TIMEOUT_SECONDS"], 1800)
        app_dir = Path(__file__).resolve().parents[1] / "app"
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (app_dir / "__init__.py", app_dir / "blueprints/views.py")
        )
        self.assertIn("upload_stream.read(1024 * 1024)", source)
        self.assertIn('request.mimetype == "application/octet-stream"', source)
        self.assertIn("SpooledTemporaryFile", source)
        self.assertIn("shutil.disk_usage(destination.parent).free", source)
        self.client.get("/gaer/settings", headers=self.headers)
        settings_timeouts = {
            method: timeout
            for (method, _params), timeout in zip(
                self.agent.calls,
                self.agent.timeouts,
                strict=True,
            )
        }
        self.assertEqual(settings_timeouts["project.release.settings"], 5.0)
        for method in (
            "sni.routes",
            "mtproto.status",
            "portal.performance",
            "client.export.settings",
        ):
            self.assertIsNone(settings_timeouts[method])

    def test_raw_release_upload_does_not_use_multipart_tmp(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        payload = b"\x1f\x8b" + b"r" * (2 * 1024 * 1024)
        response = self.client.post(
            "/gaer/settings/update/prepare",
            data=payload,
            content_type="application/octet-stream",
            headers={
                **self.headers,
                "Accept": "application/json",
                "X-CSRF-Token": self.csrf(page),
                "X-KVN-Archive-Name": "kvn-vpn-release-linux-amd64.tar.gz",
            },
        )

        self.assertEqual(response.status_code, 201)
        _method, params = self.agent.calls[-1]
        published = self.upload_dir / Path(params["archive"]).name
        self.assertEqual(published.stat().st_size, len(payload))
        self.assertEqual(list(self.upload_dir.glob("*.part-*")), [])

    def test_sni_diagnosis_uses_agent_and_keeps_result_safe(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        response = self.client.post(
            "/gaer/settings",
            data={"csrf_token": self.csrf(page), "action": "sni_diagnose", "sni": "example.com"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"DNS", response.data)
        method, params = next(
            (method, params) for method, params in reversed(self.agent.calls)
            if method == "sni.diagnose"
        )
        self.assertEqual(method, "sni.diagnose")
        self.assertEqual(params, {"sni": "example.com"})

    def test_light_profile_is_revision_safe_and_audits_only_feature_names(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        self.assertIn(b'id="portal-performance"', page.data)
        response = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page), "action": "performance",
                "revision": "a" * 64, "profile": "light",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        method, params = next(
            (method, params) for method, params in reversed(self.agent.calls)
            if method == "portal.performance.update"
        )
        self.assertEqual(method, "portal.performance.update")
        self.assertEqual(params, {
            "revision": "a" * 64, "profile": "light",
            "monitoring": False, "background_refresh": False,
        })
        with closing(sqlite3.connect(self.db)) as db:
            detail = db.execute(
                "SELECT detail FROM audit_events WHERE action='portal.performance'"
            ).fetchone()[0]
        self.assertEqual(json.loads(detail), {
            "changed_features": ["monitoring", "background_refresh"]
        })

    def test_light_runtime_hides_history_and_keeps_manual_refresh(self):
        self.users.write_text(json.dumps({
            "portal": {
                "performance_profile": "light",
                "features": {"monitoring": False, "background_refresh": False},
            },
            "users": [],
        }), encoding="utf-8")
        page = self.client.get("/gaer/", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'data-monitoring-enabled="false"', page.data)
        self.assertIn(b'data-background-refresh="false"', page.data)
        self.assertIn(b"data-dashboard-refresh", page.data)
        self.assertIn("Мониторинг отключён".encode(), page.data)
        self.assertNotIn(b"data-history aria-busy", page.data)
        static = Path(__file__).resolve().parents[1] / "app/static"
        script = "\n".join(
            (static / name).read_text(encoding="utf-8")
            for name in ("dashboard.js", "network.js")
        )
        self.assertIn('if (backgroundRefresh)', script)
        self.assertIn('networkPanel.dataset.backgroundRefresh !== "false"', script)


if __name__ == "__main__":
    unittest.main()
