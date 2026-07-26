import json
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

HAS_FLASK = importlib.util.find_spec("flask") is not None
if HAS_FLASK:
    from portal.app import create_app
    from portal.agent_client import AgentClientError
    from portal.app.security import hash_password


PASSWORD = "SettingsPassword-2026"
NEW_PASSWORD = "SettingsPassword-2026-New"


class FakeSettingsAgent:
    def __init__(self, update_dir):
        self.calls = []
        self.timeouts = []
        self.update_error = ""
        self.update_dir = Path(update_dir)

    def call(self, method, params, *, timeout=None):
        self.calls.append((method, dict(params)))
        self.timeouts.append(timeout)
        if method == "portal.credentials":
            return {"changed": True, "revision": "a" * 64}
        if method == "project.update.inspect":
            if self.update_error:
                raise AgentClientError(self.update_error)
            path = self.update_dir / Path(params["archive"]).name
            is_release = "release-linux-amd64" in params["archive"]
            return {
                "ok": True,
                "archive": params["archive"],
                "archive_name": path.name,
                "archive_size": path.stat().st_size,
                "archive_sha256": "b" * 64,
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
                "action": "update",
                "mode": params["mode"],
                "archive_kind": "release" if "release-linux-amd64" in params["archive"] else "deploy",
                "archive": params["archive"],
                "archive_name": "kvn-vpn-deploy-test.tar.gz",
                "archive_size": 4096,
                "archive_sha256": "b" * 64,
                "archive_members": 42,
                "unit": "kvn-project-update-test",
                "journal_command": "journalctl -u kvn-project-update-test -n 200 --no-pager",
                "recovery_command": "sudo ls -ld .update-backups/* 2>/dev/null || true",
                "command": {"stderr": ""},
                "correlation_id": "update-test",
            }
        if method == "sni.routes":
            return {
                "revision": "a" * 64,
                "systems": ["tls", "telemt"],
                "user_systems": ["tls"],
                "routes": {
                    "tls": {
                        "system": "tls", "label": "VLESS TLS", "default": "www.microsoft.com",
                        "dest": "xray:443", "aliases": ["www.microsoft.com"],
                        "choices": ["www.microsoft.com"], "user_selectable": True,
                    },
                    "telemt": {
                        "system": "telemt", "label": "Telemt", "default": "yandex.com",
                        "dest": "telemt:3129", "aliases": ["yandex.com"],
                        "choices": ["yandex.com"], "user_selectable": False,
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
                "target": "example.com:443", "status": "needs_attention", "can_apply": True,
                "timeout_seconds": 3.0, "checks": [
                    {"id": "dns", "status": "warning", "detail": "unavailable"}
                ],
            }
        if method == "mtproto.apply":
            return {"changed": True, "apply": {"outcome": "applied"}}
        if method == "sni.apply":
            return {"changed": True, "revision": "b" * 64, "plan": {"changed": True}, "apply": {"outcome": "applied"}}
        if method == "protocol.apply":
            if params.get("revision") == "0" * 64:
                raise AgentClientError("revision_conflict: stale fixture")
            return {
                "changed": params["mode"] != "stream-one", "revision": "b" * 64,
                "plan": {"changed": True}, "apply": {"outcome": "applied", "reconcile_required": False},
                "protocol": {"system": "reality-xhttp", "xhttp_mode": params["mode"]},
            }
        raise AssertionError(method)


@unittest.skipUnless(HAS_FLASK, "Flask установлен только в portal test image")
class PortalSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.users_file = root / "users.json"
        self.users_file.write_text(json.dumps({"users": []}), encoding="utf-8")
        self.upload_dir = root / "updates"
        self.agent = FakeSettingsAgent(self.upload_dir)
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": root / "portal.db",
                "USERS_FILE": self.users_file,
                "PORTAL_PATH": "/gaer",
                "ADMIN_LOGIN": "admin",
                "ADMIN_PASSWORD_HASH": hash_password(PASSWORD),
                "PROXY_SECRET": "proxy",
                "HYSTERIA_SECRET": "hysteria",
                "AGENT_CLIENT": self.agent,
                "UPDATE_UPLOAD_DIR": self.upload_dir,
                "UPDATE_UPLOAD_RELATIVE_DIR": "portal-data/updates",
                "NOW_PROVIDER": lambda: 1_800_000_000,
            }
        )
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy",
            "X-Real-IP": "198.51.100.9",
            "X-Forwarded-Proto": "https",
        }
        self.login(PASSWORD)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def csrf(response):
        return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()

    def login(self, password):
        page = self.client.get("/gaer/login", headers=self.headers)
        return self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": password, "csrf_token": self.csrf(page)},
            headers=self.headers,
        )

    def test_admin_password_change_uses_agent_hash_and_invalidates_sessions(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        self.assertEqual(page.status_code, 200)

        wrong = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page),
                "action": "password",
                "current_password": "WrongPassword-2026",
                "new_password": NEW_PASSWORD,
                "repeat_password": NEW_PASSWORD,
            },
            headers=self.headers,
        )
        self.assertEqual(wrong.status_code, 200)
        self.assertFalse(any(method == "portal.credentials" for method, _params in self.agent.calls))

        changed = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page),
                "action": "password",
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "repeat_password": NEW_PASSWORD,
            },
            headers=self.headers,
        )

        self.assertEqual(changed.status_code, 302)
        self.assertIn("/gaer/login?changed=1", changed.headers["Location"])
        credential_call = next((params for method, params in self.agent.calls if method == "portal.credentials"), None)
        self.assertIsNotNone(credential_call)
        sent_hash = credential_call["password_hash"]
        self.assertTrue(sent_hash.startswith("scrypt$"))
        self.assertNotIn(NEW_PASSWORD, sent_hash)
        self.assertEqual(self.client.get("/gaer/", headers=self.headers).status_code, 302)
        self.assertEqual(self.login(NEW_PASSWORD).status_code, 302)

    def test_project_update_prepare_only_inspects_archive(self):
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
        self.assertEqual(prepared["archive_sha256"], "b" * 64)
        method, params = self.agent.calls[-1]
        self.assertEqual(method, "project.update.inspect")
        self.assertRegex(params["archive"], r"^portal-data/updates/kvn-vpn-deploy-\d+-[0-9a-f]{12}\.tar\.gz$")
        self.assertFalse(any(item_method == "project.update" for item_method, _item_params in self.agent.calls))
        audit = self.app.extensions["kvn_storage"].list_audit()["events"]
        self.assertNotIn(PASSWORD, json.dumps(audit))

    def test_project_update_error_shows_safe_reason_and_recovery(self):
        self.agent.update_error = (
            "invalid_archive: Архив обновления отклонён: "
            "в архиве отсутствуют файлы из manifest: tools/canonical-files.txt"
        )
        page = self.client.get("/gaer/settings", headers=self.headers)
        response = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"x" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Архив отклонён проверкой".encode(), response.data)
        self.assertNotIn(b"tools/canonical-files.txt", response.data)
        self.assertNotIn(PASSWORD.encode(), response.data)

    def test_full_release_upload_is_atomically_published(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        payload = b"\x1f\x8b" + b"r" * (2 * 1024 * 1024)
        response = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(payload), "kvn-vpn-release-linux-amd64.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(response.status_code, 201)
        _method, params = self.agent.calls[-1]
        self.assertRegex(
            params["archive"],
            r"^portal-data/updates/kvn-vpn-release-linux-amd64-\d+-[0-9a-f]{12}\.tar\.gz$",
        )
        upload_dir = Path(self.app.config["UPDATE_UPLOAD_DIR"])
        published = list(upload_dir.glob("kvn-vpn-release-linux-amd64-*.tar.gz"))
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].stat().st_size, len(payload))
        self.assertEqual(list(upload_dir.glob("*.part-*")), [])

    def test_full_release_raw_upload_bypasses_multipart_tmpfs(self):
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

    def test_staged_update_prepares_then_starts_with_saved_sha256(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        prepared_response = self.client.post(
            "/gaer/settings/update/prepare",
            data={
                "csrf_token": self.csrf(page),
                "archive": (io.BytesIO(b"\x1f\x8b" + b"z" * 2048), "kvn-vpn-deploy.tar.gz"),
            },
            content_type="multipart/form-data",
            headers={**self.headers, "Accept": "application/json"},
        )
        self.assertEqual(prepared_response.status_code, 201)
        prepared = prepared_response.get_json()["prepared"]
        self.assertNotIn("archive", prepared)
        self.assertEqual(self.agent.calls[-1][0], "project.update.inspect")
        self.assertEqual(self.agent.timeouts[-1], 1800.0)
        self.assertEqual(self.app.extensions["kvn_storage"].latest_prepared_update()["id"], prepared["id"])

        response = self.client.post(
            "/gaer/settings/update/start",
            data={
                "csrf_token": self.csrf(page),
                "prepared_id": prepared["id"],
                "root_password": PASSWORD,
                "update_mode": "full",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        _method, params = self.agent.calls[-1]
        self.assertEqual(params["expected_sha256"], "b" * 64)
        self.assertEqual(params["root_password"], PASSWORD)
        self.assertEqual(self.app.extensions["kvn_storage"].get_prepared_update(prepared["id"])["status"], "started")
        duplicate = self.client.post(
            "/gaer/settings/update/start",
            data={"csrf_token": self.csrf(page), "prepared_id": prepared["id"], "root_password": PASSWORD},
            headers=self.headers,
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(sum(method == "project.update" for method, _params in self.agent.calls), 1)
        self.assertNotIn(PASSWORD, json.dumps(self.app.extensions["kvn_storage"].list_audit()))

    def test_sni_settings_use_agent(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"SNI", page.data)
        response = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page),
                "action": "sni_add",
                "revision": "a" * 64,
                "system": "tls",
                "sni": "cdn.example.com",
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        method, params = next(
            (method, params) for method, params in reversed(self.agent.calls)
            if method == "sni.apply"
        )
        self.assertEqual(method, "sni.apply")
        self.assertEqual(params["action"], "add-alias")
        self.assertEqual(params["system"], "tls")
        self.assertEqual(params["sni"], "cdn.example.com")

    def test_mtproto_settings_show_scope_and_use_typed_agent_methods(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn("shared secret".encode(), page.data)
        self.assertIn("Полную блокировку IP/TCP/TLS".encode(), page.data)

        diagnosis = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page), "action": "mtproto_diagnose",
                "system": "mtg",
            },
            headers=self.headers,
        )
        self.assertEqual(diagnosis.status_code, 200)
        self.assertIn(b"mtg: needs_attention", diagnosis.data)
        self.assertIn(("mtproto.diagnose", {"system": "mtg"}), self.agent.calls)

        applied = self.client.post(
            "/gaer/settings",
            data={
                "csrf_token": self.csrf(page), "action": "mtproto_origin",
                "revision": "a" * 64, "system": "telemt", "origin": "local-site",
            },
            headers=self.headers,
        )
        self.assertEqual(applied.status_code, 200)
        self.assertIn(
            ("mtproto.apply", {
                "revision": "a" * 64, "system": "telemt", "origin": "local-site",
            }),
            self.agent.calls,
        )

    def test_xhttp_mode_route_is_revisioned_and_audit_is_secret_free(self):
        page = self.client.get("/gaer/settings", headers=self.headers)
        response = self.client.post(
            "/gaer/network/protocol/apply",
            data={"csrf_token": self.csrf(page), "revision": "a" * 64, "mode": "stream-up"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        method, params = self.agent.calls[-1]
        self.assertEqual(method, "protocol.apply")
        self.assertEqual(set(params), {"action", "system", "mode", "revision"})
        self.assertEqual(params["system"], "reality-xhttp")
        audit = json.dumps(self.app.extensions["kvn_storage"].list_audit(), ensure_ascii=False)
        self.assertIn("protocol.set-xhttp-mode", audit)
        self.assertIn("reality-xhttp", audit)
        for forbidden in [PASSWORD, "private_key", "root_password", "uuid"]:
            self.assertNotIn(forbidden, audit)

        stale = self.client.post(
            "/gaer/network/protocol/apply",
            data={"csrf_token": self.csrf(page), "revision": "0" * 64, "mode": "packet-up"},
            headers=self.headers,
        )
        self.assertEqual(stale.status_code, 409)


if __name__ == "__main__":
    unittest.main()
