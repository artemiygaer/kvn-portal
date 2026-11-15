"""Первый вход, защита сессии и повторный запрос сводки v5."""

import io
import re
import unittest

from v5.portal.app import create_app
from v5.portal.rpc import AgentUnavailable
from v5.core.credentials import hash_admin_password, verify_admin_password
from v5.portal.security import LoginBudget

ORIGIN = "https://127.0.0.1:8443"
PASSWORD = "temporary-v5-fixture-password"


class FixtureStatus:
    calls = 0

    def __init__(self):
        self.tls_issues = []
        self.site_uploads = []
        self.site_resets = 0

    def status(self):
        self.calls += 1
        return {
            "cpu_percent": 5, "uptime_seconds": 120,
            "memory": {"total_bytes": 1048576, "available_bytes": 1048576},
            "disk": {"total_bytes": 1073741824, "free_bytes": 1073741824},
            "network": {"received_bytes": 1024, "sent_bytes": 1024}, "history_enabled": False,
        }

    def tls_status(self):
        return {"busy": False, "names": [{"name": "portal.example", "authority": "portal.example", "slot": "dns-portal.example"}],
                "results": {"dns-portal.example": {"active_expires_at": "2027-01-01T00:00:00+00:00",
                                                   "public": {"status": "dns_failed"}}}}

    def tls_issue(self, name, mode, email):
        self.tls_issues.append((name, mode, email))
        return {"queued": True}

    def site_status(self):
        return {"customized": True}

    def site_publish(self, content):
        self.site_uploads.append(content)

    def site_reset(self):
        self.site_resets += 1


class PortalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.digest = hash_admin_password(PASSWORD)

    def setUp(self):
        self.status = FixtureStatus()
        self.config = {"session_key": "only-for-fixture", "login": "admin", "password_hash": self.digest,
                       "allowed_hosts": ["127.0.0.1:8443"]}
        self.client = create_app(self.config, client=self.status).test_client()

    def login_token(self):
        page = self.client.get("/login", base_url=ORIGIN)
        self.assertEqual(page.status_code, 200)
        return re.search(rb'name="csrf" value="([^"]+)"', page.data).group(1).decode()

    def test_password_format_is_bounded(self):
        self.assertTrue(verify_admin_password(PASSWORD, self.digest))
        self.assertFalse(verify_admin_password(PASSWORD, self.digest.replace("32768", "1048576")))
        self.assertFalse(verify_admin_password("x" * 257, self.digest))

    def test_origin_and_csrf_and_session(self):
        self.assertEqual(self.client.get("/", base_url=ORIGIN).status_code, 303)
        self.assertEqual(self.client.get("/login", base_url="https://bad.example:8443").status_code, 400)
        token = self.login_token()
        credentials = {"login": "admin", "password": PASSWORD, "csrf": token}
        self.assertEqual(self.client.post("/login", base_url=ORIGIN, data=credentials,
                                          headers={"Origin": "https://127.0.0.1"}).status_code, 403)
        self.assertEqual(self.client.post("/login", base_url=ORIGIN, data={**credentials, "csrf": "bad"},
                                          headers={"Origin": ORIGIN}).status_code, 403)
        result = self.client.post("/login", base_url=ORIGIN, data=credentials, headers={"Origin": ORIGIN})
        self.assertEqual(result.status_code, 303)
        cookie = result.headers["Set-Cookie"]
        for part in ("__Host-kvn-v5=", "HttpOnly", "Secure", "SameSite=Strict"):
            self.assertIn(part, cookie)
        for _ in range(2):
            page = self.client.get("/", base_url=ORIGIN)
            self.assertEqual(page.status_code, 200)
            self.assertIn(b'href="/modules"', page.data)
            self.assertIn("Агент доступен".encode(), page.data)
        self.assertEqual(self.status.calls, 1)

    def test_rate_budget_and_agent_failure(self):
        now = [0]
        budget = LoginBudget(clock=lambda: now[0])
        for _ in range(5):
            self.assertTrue(budget.allow("same"))
        self.assertFalse(budget.allow("same"))
        now[0] = 43200
        self.assertTrue(budget.allow("same"))

        class BrokenStatus:
            def status(self):
                raise AgentUnavailable

        # Cookie Flask test client создан для localhost; это разрешённый хост этой проверки.
        app = create_app({**self.config, "allowed_hosts": ["localhost"]}, client=BrokenStatus())
        with app.test_client() as client:
            with client.session_transaction() as session:
                session["admin"] = True
            self.assertIn("Агент недоступен".encode(), client.get("/").data)

    def test_tls_status_and_issue_require_authenticated_exact_origin_and_csrf(self):
        route = "/settings/tls"
        self.assertEqual(self.client.get(route, base_url=ORIGIN).status_code, 303)
        credentials = {"login": "admin", "password": PASSWORD, "csrf": self.login_token()}
        self.client.post("/login", base_url=ORIGIN, data=credentials, headers={"Origin": ORIGIN})
        settings = self.client.get(route, base_url=ORIGIN)
        self.assertIn("DNS не подтвердился".encode(), settings.data)
        self.assertIn(b"2027-01-01T00:00:00+00:00", settings.data)
        csrf = re.search(rb'name="csrf" value="([^"<>]+)"', settings.data)[1].decode()
        request = {"name": "portal.example", "mode": "staging", "email": "ops@example.net", "csrf": csrf}
        self.assertEqual(self.client.post(route, base_url=ORIGIN, data=request,
                                          headers={"Origin": "https://127.0.0.1"}).status_code, 403)
        self.assertEqual(self.client.post(route, base_url=ORIGIN, data={**request, "csrf": "bad"},
                                          headers={"Origin": ORIGIN}).status_code, 403)
        self.assertEqual(self.status.tls_issues, [])
        response = self.client.post(route, base_url=ORIGIN, data=request, headers={"Origin": ORIGIN})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.status.tls_issues, [("portal.example", "staging", "ops@example.net")])
        self.assertEqual(self.client.post(route, base_url=ORIGIN, data={**request, 'email': ''},
                                          headers={'Origin': ORIGIN}).status_code, 303)
        self.assertEqual(self.status.tls_issues[-1], ('portal.example', 'staging', ''))
        self.assertIn('необязательно'.encode(), settings.data)

    def test_site_preview_is_sandboxed_and_publish_and_reset_are_guarded(self):
        settings = "/settings/site"
        self.assertEqual(self.client.get(settings, base_url=ORIGIN).status_code, 303)
        credentials = {"login": "admin", "password": PASSWORD, "csrf": self.login_token()}
        self.client.post("/login", base_url=ORIGIN, data=credentials, headers={"Origin": ORIGIN})
        page = self.client.get(settings, base_url=ORIGIN)
        csrf = re.search(rb'name="csrf" value="([^"<>]+)"', page.data)[1].decode()
        html = b"<main>" + b"x" * (60 * 1024) + b"</main>"

        def post(action, source, origin=ORIGIN):
            return self.client.post(settings + "/" + action, base_url=ORIGIN, headers={"Origin": origin},
                                    data={"csrf": csrf, "html": (io.BytesIO(source), "index.html")})

        result = post("preview", html)
        self.assertEqual(result.status_code, 200)
        self.assertIn("sandbox", result.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", result.headers["Content-Security-Policy"])
        self.assertIn(html, result.data)
        self.assertEqual(self.status.site_uploads, [])
        self.assertEqual(post("publish", html, "https://127.0.0.1").status_code, 403)
        self.assertEqual(post("publish", b"<script>bad()</script>").status_code, 303)
        self.assertEqual(post("publish", b"x" * (140 * 1024)).status_code, 413)
        self.assertEqual(self.status.site_uploads, [])
        self.assertEqual(post("publish", html).status_code, 303)
        self.assertEqual(self.status.site_uploads, [html])
        self.client.post(settings + "/reset", base_url=ORIGIN, data={"csrf": csrf}, headers={"Origin": ORIGIN})
        self.assertEqual(self.status.site_resets, 0)
        self.client.post(settings + "/reset", base_url=ORIGIN, data={"csrf": csrf, "confirm": "yes"},
                         headers={"Origin": ORIGIN})
        self.assertEqual(self.status.site_resets, 1)
