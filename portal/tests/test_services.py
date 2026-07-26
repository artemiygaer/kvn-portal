import json
import re
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from app import create_app
from app.security import hash_password
from app.service_catalog import (
    MANAGED_SERVICE_ORDER,
    SERVICE_CATALOG,
    SYSTEM_ORDER,
)


PASSWORD = "ServicePortalPassword-2026"
FORBIDDEN = "password=NeverStoreThis token=NeverStoreThis"


class FakeServiceAgent:
    def __init__(self):
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, dict(params)))
        if method == "service.status":
            return {"service": params["service"], "active": True, "enabled": True}
        if method == "service.action":
            return {
                "service": params["service"], "action": params["action"], "ok": True,
                "before": {"active": True}, "after": {"active": True},
                "health": {"ok": True, "expected_active": True},
                "duration_ms": 12, "correlation_id": "correlation-123",
                "warning": "", "command": {"stderr": FORBIDDEN}, "fallback": None,
            }
        raise AssertionError(method)


class PortalServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = hash_password(PASSWORD)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "portal.db"
        users = root / "users.json"
        users.write_text(json.dumps({"users": []}), encoding="utf-8")
        self.agent = FakeServiceAgent()
        self.app = create_app({
            "TESTING": True, "DATABASE": self.db, "USERS_FILE": users,
            "PORTAL_PATH": "/gaer", "ADMIN_LOGIN": "admin",
            "ADMIN_PASSWORD_HASH": self.password_hash, "PROXY_SECRET": "proxy",
            "HYSTERIA_SECRET": "hysteria", "AGENT_CLIENT": self.agent,
            "NOW_PROVIDER": lambda: 1_800_000_000,
        })
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy", "X-Real-IP": "198.51.100.9",
            "X-Forwarded-Proto": "https",
        }
        page = self.client.get("/gaer/login", headers=self.headers)
        csrf = self.csrf(page)
        self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": PASSWORD, "csrf_token": csrf},
            headers=self.headers,
        )

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def csrf(response):
        return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()

    def test_status_page_and_restart_confirmation_audit(self):
        page = self.client.get("/gaer/services", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"xray", page.data)
        self.assertIn(b'value="apply"', page.data)
        text = page.data.decode("utf-8")
        for marker in ["data-service-filter", "data-service-card", "data-service-empty", "Host-служба", "Контейнер"]:
            self.assertIn(marker, text)
        for marker in ["data-inline-log-toggle", "data-inline-log-panel", "data-inline-log-endpoint", "data-inline-log-refresh", "Полный журнал"]:
            self.assertIn(marker, text)
        self.assertFalse(any(method == "logs.tail" for method, _params in self.agent.calls))
        match = re.search(
            rb'action="/gaer/services/xray/action".*?name="action" value="restart".*?name="confirmation_token" value="([^"]+)"',
            page.data,
            re.DOTALL,
        )
        response = self.client.post(
            "/gaer/services/xray/action",
            data={
                "csrf_token": self.csrf(page), "action": "restart",
                "confirmation_token": match.group(1).decode(),
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"correlation-123", response.data)
        with closing(sqlite3.connect(self.db)) as db:
            detail = db.execute("SELECT detail FROM audit_events WHERE action='service.action'").fetchone()[0]
        self.assertIn("correlation-123", detail)
        self.assertNotIn("NeverStoreThis", detail)
        self.assertNotIn("stderr", detail)

    def test_wireguard_apply_button_calls_service_action_with_confirmation(self):
        page = self.client.get("/gaer/services", headers=self.headers)
        match = re.search(
            rb'action="/gaer/services/wireguard/action".*?name="action" value="apply".*?name="confirmation_token" value="([^"]+)"',
            page.data,
            re.DOTALL,
        )
        self.assertIsNotNone(match)

        response = self.client.post(
            "/gaer/services/wireguard/action",
            data={
                "csrf_token": self.csrf(page), "action": "apply",
                "confirmation_token": match.group(1).decode(),
            },
            headers=self.headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"correlation-123", response.data)
        self.assertIn(("service.action", {"service": "wireguard", "action": "apply", "request_id": self.agent.calls[-1][1]["request_id"]}), self.agent.calls)

    def test_restart_without_confirmation_is_rejected_before_agent(self):
        page = self.client.get("/gaer/services", headers=self.headers)
        before = len(self.agent.calls)
        response = self.client.post(
            "/gaer/services/xray/action",
            data={"csrf_token": self.csrf(page), "action": "restart"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.agent.calls), before)

    def test_catalog_help_covers_service_cards_and_project_reference(self):
        services = self.client.get("/gaer/services", headers=self.headers)
        self.assertEqual(services.status_code, 200)
        text = services.data.decode("utf-8")
        for key in MANAGED_SERVICE_ORDER:
            self.assertIn(f'data-service-guide="{key}"', text)
        for marker in [
            "Порты, клиенты и применение",
            "Быстрая диагностика",
            "AmneziaWG app",
            "51821/udp",
        ]:
            self.assertIn(marker, text)

        project = self.client.get("/gaer/project", headers=self.headers)
        self.assertEqual(project.status_code, 200)
        project_text = project.data.decode("utf-8")
        for key in (*SYSTEM_ORDER, "portal", "nginx", "agent"):
            self.assertIn(f'data-catalog-entry="{key}"', project_text)
        self.assertEqual(
            project_text.count('data-catalog-entry="'),
            len(SERVICE_CATALOG),
        )
        for forbidden in [FORBIDDEN, "BEGIN PRIVATE KEY", "password_hash"]:
            self.assertNotIn(forbidden, project_text)


if __name__ == "__main__":
    unittest.main()
