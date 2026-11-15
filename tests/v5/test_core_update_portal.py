"""Доступ, CSRF и двухэтапное обновление ядра через панель."""

import io
from unittest import TestCase
from unittest.mock import Mock

from v5.portal.app import create_app
from v5.portal.rpc import AgentRejected, AgentUnavailable

ORIGIN = "https://localhost:8443"


class CoreUpdatePortalTests(TestCase):
    def setUp(self):
        self.client = Mock()
        self.client.status.return_value = {"current": "5.0.0", "records": []}
        self.app = create_app({"session_key": "fixture", "allowed_hosts": ["localhost:8443"]},
                              client=Mock(), core_update_client=self.client)
        self.web = self.app.test_client()

    def admin(self):
        with self.web.session_transaction(base_url=ORIGIN) as state:
            state.update(admin=True, csrf="fixture-csrf")

    def post(self, action, data):
        return self.web.post("/maintenance/update/" + action, data=data, base_url=ORIGIN,
                             headers={"Origin": ORIGIN})

    def test_login_status_unavailable_and_no_server_paths(self):
        self.assertEqual(self.web.get("/maintenance/update", base_url=ORIGIN).status_code, 303)
        self.client.status.assert_not_called()
        self.admin()
        page = self.web.get("/maintenance/update", base_url=ORIGIN)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Загрузить и проверить".encode(), page.data)
        self.assertIn(b"core-update.js", page.data)
        self.assertIn("script-src 'self'", page.headers["Content-Security-Policy"])
        self.client.status.side_effect = AgentUnavailable()
        self.assertIn("Служба обновления недоступна".encode(),
                      self.web.get("/maintenance/update", base_url=ORIGIN).data)

    def test_upload_and_github_prepare_do_not_start_update(self):
        self.admin()
        response = self.post("upload", {"csrf": "fixture-csrf", "bundle": (io.BytesIO(b"fixture"), "update.tar")})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.client.upload.call_args.args[1], 7)
        self.assertEqual(self.post("github", {"csrf": "fixture-csrf", "tag": "v5.0.1"}).status_code, 303)
        self.client.github.assert_called_once_with("v5.0.1")
        self.client.start.assert_not_called()

    def test_start_needs_csrf_and_confirmation(self):
        self.admin()
        ticket = "a" * 64
        self.assertEqual(self.post("start", {"csrf": "wrong", "confirm": "yes", "ticket": ticket}).status_code, 403)
        self.assertEqual(self.post("start", {"csrf": "fixture-csrf", "ticket": ticket}).status_code, 400)
        self.client.start.assert_not_called()
        self.assertEqual(self.post("start", {"csrf": "fixture-csrf", "confirm": "yes", "ticket": ticket}).status_code, 303)
        self.client.start.assert_called_once_with(ticket)

    def test_untrusted_update_gets_safe_message(self):
        self.admin()
        self.client.github.side_effect = AgentRejected("invalid_package_signature")
        self.assertEqual(self.post("github", {"csrf": "fixture-csrf", "tag": "v5.0.1"}).status_code, 303)
        page = self.web.get("/maintenance/update", base_url=ORIGIN)
        self.assertIn("Подпись обновления не совпадает".encode(), page.data)
        self.client.start.assert_not_called()
