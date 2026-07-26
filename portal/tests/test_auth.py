import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app import create_app
from app.security import SCRYPT_N, SCRYPT_P, SCRYPT_R, hash_password, verify_password
from app.storage import SESSION_IDLE_SECONDS


PASSWORD = "VeryStrongPortalPassword-2026"


class PortalAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = hash_password(PASSWORD)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.users_file = root / "users.json"
        self.users_file.write_text(
            json.dumps(
                {
                    "users": [
                        {
                            "name": "Alice",
                            "enabled": True,
                            "systems": ["hysteria"],
                            "hysteria_password": "HysteriaPassword",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.clock = [1_800_000_000]
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": root / "portal.db",
                "USERS_FILE": self.users_file,
                "PORTAL_PATH": "/gaer",
                "PORTAL_NAME": "Тестовый портал",
                "ADMIN_LOGIN": "admin",
                "ADMIN_PASSWORD_HASH": self.password_hash,
                "PROXY_SECRET": "proxy-secret-value",
                "HYSTERIA_SECRET": "hysteria-secret-value",
                "NOW_PROVIDER": lambda: self.clock[0],
            }
        )
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy-secret-value",
            "X-Real-IP": "2001:db8::1",
            "X-Forwarded-Proto": "https",
        }

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def csrf(response):
        match = re.search(rb'name="csrf_token" value="([^"]*)"', response.data)
        return match.group(1).decode("ascii") if match else ""

    def get_login_csrf(self):
        return self.csrf(self.client.get("/gaer/login", headers=self.headers))

    def post_login(self, login="admin", password=PASSWORD, csrf=None):
        csrf = self.get_login_csrf() if csrf is None else csrf
        return self.client.post(
            "/gaer/login",
            data={"login": login, "password": password, "csrf_token": csrf},
            headers=self.headers,
        )

    def authenticate(self):
        response = self.post_login()
        self.assertEqual(response.status_code, 302)
        return self.client.get("/gaer/", headers=self.headers)

    def test_scrypt_format_and_parameters(self):
        parts = self.password_hash.split("$")
        self.assertEqual(parts[0], "scrypt")
        self.assertGreaterEqual(int(parts[1]), SCRYPT_N)
        self.assertGreaterEqual(int(parts[2]), SCRYPT_R)
        self.assertGreaterEqual(int(parts[3]), SCRYPT_P)
        self.assertNotIn(PASSWORD, self.password_hash)
        self.assertTrue(verify_password(PASSWORD, self.password_hash))
        self.assertFalse(verify_password("wrong-password", self.password_hash))

    def test_successful_login_sets_hardened_scoped_cookie(self):
        response = self.post_login()
        self.assertEqual(response.status_code, 302)
        cookie = response.headers["Set-Cookie"]
        for value in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/gaer/"]:
            self.assertIn(value, cookie)
        dashboard = self.client.get("/gaer/", headers=self.headers)
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Тестовый портал".encode(), dashboard.data)

    def test_session_fixation_replay_and_idle_expiry_are_rejected(self):
        self.client.set_cookie("kvn_portal_session", "attacker-fixed-token", path="/gaer/")
        response = self.post_login()
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("attacker-fixed-token", response.headers["Set-Cookie"])
        self.assertEqual(self.client.get("/gaer/", headers=self.headers).status_code, 200)
        self.clock[0] += SESSION_IDLE_SECONDS + 1
        expired = self.client.get("/gaer/", headers=self.headers)
        self.assertEqual(expired.status_code, 302)
        self.assertTrue(expired.headers["Location"].endswith("/gaer/login"))

    def test_stolen_session_is_bound_to_ip_and_user_agent(self):
        self.assertEqual(self.post_login().status_code, 302)
        session_token = self.client.get_cookie("kvn_portal_session", path="/gaer/").value
        attacker = self.app.test_client()
        attacker.set_cookie("kvn_portal_session", session_token, path="/gaer/")
        other_ip = attacker.get(
            "/gaer/",
            headers={**self.headers, "X-Real-IP": "198.51.100.44"},
        )
        self.assertEqual(other_ip.status_code, 302)
        other_agent = attacker.get(
            "/gaer/",
            headers={**self.headers, "User-Agent": "ReplayClient/1.0"},
        )
        self.assertEqual(other_agent.status_code, 302)
        self.assertEqual(self.client.get("/gaer/", headers=self.headers).status_code, 200)

    def test_invalid_login_and_password_have_same_generic_response(self):
        invalid_login = self.post_login(login="nobody")
        invalid_password = self.post_login(password="WrongPassword-123")
        self.assertEqual(invalid_login.status_code, 401)
        self.assertEqual(invalid_password.status_code, 401)
        message = "Неверный логин или пароль.".encode()
        self.assertIn(message, invalid_login.data)
        self.assertIn(message, invalid_password.data)
        self.assertNotIn(b"nobody", invalid_login.data)

    def test_fifth_failure_blocks_ip_for_twelve_hours_and_survives_restart(self):
        for attempt in range(1, 6):
            response = self.post_login(password=f"WrongPassword-{attempt}")
            self.assertEqual(response.status_code, 429 if attempt == 5 else 401)
        self.assertEqual(response.headers["Retry-After"], "43200")

        restarted = create_app(dict(self.app.config))
        restarted_client = restarted.test_client()
        blocked = restarted_client.get("/gaer/login", headers=self.headers)
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["Retry-After"], "43200")
        with mock.patch("app.blueprints.views.verify_password") as verify:
            blocked_post = restarted_client.post(
                "/gaer/login",
                data={"login": "admin", "password": PASSWORD, "csrf_token": "ignored"},
                headers=self.headers,
            )
        self.assertEqual(blocked_post.status_code, 429)
        verify.assert_not_called()

        other_ip = restarted_client.get(
            "/gaer/login",
            headers={**self.headers, "X-Real-IP": "198.51.100.45"},
        )
        self.assertEqual(other_ip.status_code, 200)

    def test_success_before_block_resets_failure_counter(self):
        for attempt in range(4):
            self.assertEqual(self.post_login(password=f"Wrong-{attempt}-Password").status_code, 401)
        self.assertEqual(self.post_login().status_code, 302)
        self.client.delete_cookie("kvn_portal_session", path="/gaer/")
        self.assertEqual(self.post_login(password="Wrong-Again-Password").status_code, 401)

    def test_login_and_authenticated_mutations_require_csrf(self):
        missing_login = self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": PASSWORD},
            headers=self.headers,
        )
        self.assertEqual(missing_login.status_code, 403)
        dashboard = self.authenticate()
        missing_logout = self.client.post("/gaer/logout", headers=self.headers)
        self.assertEqual(missing_logout.status_code, 403)
        logout = self.client.post(
            "/gaer/logout",
            data={"csrf_token": self.csrf(dashboard)},
            headers=self.headers,
        )
        self.assertEqual(logout.status_code, 302)
        self.assertEqual(self.client.get("/gaer/", headers=self.headers).status_code, 302)

    def test_security_headers_and_proxy_boundary(self):
        response = self.client.get("/gaer/login", headers=self.headers)
        expected = {
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Cache-Control",
            "Strict-Transport-Security",
        }
        for header in expected:
            self.assertIn(header, response.headers)
        spoofed = self.client.get(
            "/gaer/login",
            headers={"X-Real-IP": "198.51.100.1", "X-Forwarded-Proto": "https"},
        )
        self.assertEqual(spoofed.status_code, 404)
        insecure = self.client.get(
            "/gaer/login",
            headers={**self.headers, "X-Forwarded-Proto": "http"},
        )
        self.assertEqual(insecure.status_code, 400)

    def test_storage_cleanup_runs_at_bounded_interval(self):
        storage = self.app.extensions["kvn_storage"]
        with mock.patch.object(storage, "cleanup", wraps=storage.cleanup) as cleanup:
            self.client.get("/gaer/login", headers=self.headers)
            self.client.get("/gaer/login", headers=self.headers)
            self.assertEqual(cleanup.call_count, 1)
            self.clock[0] += self.app.config["STORAGE_CLEANUP_INTERVAL"] - 1
            self.client.get("/gaer/login", headers=self.headers)
            self.assertEqual(cleanup.call_count, 1)
            self.clock[0] += 1
            self.client.get("/gaer/login", headers=self.headers)
            self.assertEqual(cleanup.call_count, 2)

    def test_internal_hysteria_auth_is_not_public(self):
        public = self.client.post(
            "/gaer/internal/hysteria/auth",
            json={"auth": "HysteriaPassword"},
            headers=self.headers,
        )
        self.assertEqual(public.status_code, 404)
        denied = self.client.post("/internal/hysteria/auth", json={"auth": "HysteriaPassword"})
        self.assertEqual(denied.status_code, 403)
        allowed = self.client.post(
            "/internal/hysteria/auth",
            json={"auth": "Alice:HysteriaPassword"},
            headers={"X-KVN-Hysteria-Secret": "hysteria-secret-value"},
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.get_json(), {"ok": True, "id": "Alice"})


if __name__ == "__main__":
    unittest.main()
