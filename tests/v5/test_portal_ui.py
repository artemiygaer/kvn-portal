"""Контракт доступной навигации и пустого состояния ядра v5."""

import gzip
from pathlib import Path
import re
from unittest import TestCase
from unittest.mock import Mock

from v5.portal.app import create_app
from v5.portal.rpc import AgentUnavailable

ORIGIN = "https://localhost:8443"


class PortalUITests(TestCase):
    def setUp(self):
        self.backend = Mock()
        self.backend.status.return_value = {"cpu_percent": None, "memory": {"available_bytes": 32 * 1024**2},
                                            "disk": {"free_bytes": 64 * 1024**3}, "uptime_seconds": 120,
                                            "network": {"received_bytes": 0, "sent_bytes": 0}}
        self.packages = Mock()
        self.packages.status.return_value = {"installed": []}
        self.lifecycle = Mock()
        self.lifecycle.settings_snapshot.side_effect = lambda modules: {'settings': {
            module: ([] if module == 'xray' else None) for module in modules}, 'errors': []}
        self.app = create_app({"session_key": "fixture-only", "allowed_hosts": ["localhost:8443"]},
                              client=self.backend, package_client=self.packages, lifecycle_client=self.lifecycle)
        self.admin = self.app.test_client()
        with self.admin.session_transaction(base_url=ORIGIN) as session:
            session.update(admin=True, csrf="fixture-session")

    def test_empty_dashboard_has_action_and_no_eager_modules(self):
        page = self.admin.get("/", base_url=ORIGIN)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Модули не установлены".encode(), page.data)
        self.assertIn("Агент доступен".encode(), page.data)
        self.assertIn(b"0 " + "из".encode() + b" 6", page.data)
        self.assertIn(b'href="/modules#module-catalog"', page.data)
        self.assertIn(b'href="/modules#module-upload"', page.data)
        self.assertIn(b'href="#main"', page.data)
        self.assertEqual(page.data.count(b'aria-current="page"'), 1)
        self.assertNotIn(b"<script", page.data)
        self.assertNotIn(b"xterm", page.data)
        css = self.admin.get("/static/portal.css", base_url=ORIGIN)
        try:
            self.assertEqual(css.status_code, 200)
            self.assertLess(len(gzip.compress(page.data)) + len(gzip.compress(css.data)), 250 * 1024)
        finally:
            css.close()
        self.packages.status.assert_called_once_with()

    def test_failed_inventory_is_not_reported_as_empty(self):
        self.packages.status.side_effect = AgentUnavailable("fixture")
        page = self.admin.get("/", base_url=ORIGIN).data
        self.assertIn("Служба пакетов недоступна".encode(), page)
        self.assertNotIn("Модули не установлены".encode(), page)

    def test_navigation_is_authenticated_and_disabled_module_is_neutral(self):
        guest = self.app.test_client()
        self.assertEqual(guest.get("/", base_url=ORIGIN).status_code, 303)
        self.assertNotIn(b"<nav", guest.get("/login", base_url=ORIGIN).data)
        self.packages.status.assert_not_called()
        self.packages.status.return_value = {"installed": [{"module": "wireguard", "version": "1.0.0", "enabled": False}]}
        page = self.admin.get("/modules", base_url=ORIGIN).data
        self.assertIn(b'id="module-catalog"', page)
        self.assertIn(b'id="module-upload"', page)
        self.assertIn(b'href="/modules" aria-current="page"', page)
        self.assertIn("Установлен, выключен".encode(), page)
        self.assertNotIn(b'badge-ok', page)

    def test_awg_diagnostics_distinguish_legacy_from_fresh_setup(self):
        self.packages.status.return_value = {"installed": [{"module": "amneziawg", "version": "1.0.0", "enabled": False}]}
        self.assertIn("Новые настройки используют AWG 3.1".encode(),
                      self.admin.get("/modules", base_url=ORIGIN).data)
        host = {"kernel": "6.12.0-fixture", "headers": True, "module_available": True,
                "module_version": "1.0.0", "tools_version": "3.1.20260812", "issue": None}
        for profiles in (["legacy"], ["legacy", "3.1"]):
            with self.subTest(profiles=profiles):
                self.lifecycle.diagnostics.return_value = {"module": "amneziawg", "host": {**host, "profiles": profiles}}
                page = self.admin.post("/modules/diagnostics", data={"csrf": "fixture-session", "module": "amneziawg"},
                                       base_url=ORIGIN, headers={"Origin": ORIGIN})
                self.assertEqual(page.status_code, 200)
                self.assertEqual("AWG 3.1 недоступен".encode() in page.data, "3.1" not in profiles)

    def test_initial_tunnel_form_only_for_disabled_tunnels(self):
        self.packages.status.return_value = {'installed': [
            {'module': 'wireguard', 'version': '1.0.0', 'enabled': False},
            {'module': 'amneziawg', 'version': '1.0.0', 'enabled': True},
            {'module': 'xray', 'version': '1.0.0', 'enabled': False},
        ]}
        page = self.admin.get('/modules', base_url=ORIGIN).data
        self.assertEqual(page.count(b'action="/modules/initialize"'), 1)
        self.assertIn('выхода в интернет'.encode(), page)
        self.assertIn('при отсутствии настроек'.encode(), page)

    def test_provision_requires_confirmation_and_starts_only_selected_module(self):
        updates = Mock()
        updates.provision_status.return_value = {'job': None}
        app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost:8443']},
                         client=self.backend, package_client=self.packages, lifecycle_client=self.lifecycle,
                         core_update_client=updates)
        admin = app.test_client()
        with admin.session_transaction(base_url=ORIGIN) as session:
            session.update(admin=True, csrf='fixture-session')
        self.packages.status.return_value = {'installed': [
            {'module': 'wireguard', 'version': '1.0.0', 'enabled': False},
            {'module': 'amneziawg', 'version': '1.0.0', 'enabled': False},
        ]}
        page = admin.get('/modules', base_url=ORIGIN)
        self.assertEqual(page.data.count(b'action="/modules/provision"'), 2)
        params = {'csrf': 'fixture-session', 'module': 'wireguard'}
        admin.post('/modules/provision', data=params, base_url=ORIGIN, headers={'Origin': ORIGIN})
        updates.provision_start.assert_not_called()
        admin.post('/modules/provision', data={**params, 'confirm': 'yes'},
                   base_url=ORIGIN, headers={'Origin': ORIGIN})
        updates.provision_start.assert_called_once_with('wireguard')

    def test_text_and_focus_palette_in_both_themes(self):
        css = (Path(__file__).resolve().parents[2] / "v5/portal/static/portal.css").read_text(encoding="utf-8")
        roots = re.findall(r":root\s*\{([^}]+)\}", css)
        self.assertEqual(len(roots), 2)

        def luminance(value):
            if len(value) == 3:
                value = "".join(item * 2 for item in value)
            channels = [int(value[i:i + 2], 16) / 255 for i in range(0, 6, 2)]
            linear = [item / 12.92 if item <= 0.04045 else ((item + 0.055) / 1.055) ** 2.4 for item in channels]
            return sum(item * weight for item, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

        for index, root in enumerate(roots):
            colors = dict(re.findall(r"--([\w-]+):\s*#([0-9a-f]+);", root))
            for foreground, background, minimum in (("ink", "bg", 4.5), ("ink", "panel", 4.5),
                    ("muted", "bg", 4.5), ("muted", "panel", 4.5), ("accent", "active", 4.5),
                    ("accent", "panel", 4.5), ("button-ink", "accent", 4.5), ("good", "good-bg", 4.5),
                    ("warn", "warn-bg", 4.5), ("focus", "panel", 3), ("focus", "bg", 3)):
                with self.subTest(theme=index, foreground=foreground, background=background):
                    low, high = sorted(map(luminance, (colors[foreground], colors[background])))
                    self.assertGreaterEqual((high + 0.05) / (low + 0.05), minimum)

    def test_network_preview_is_guarded_and_progress_script_is_scoped(self):
        self.lifecycle.plan.return_value = {"module": "wireguard", "sni": [],
                                            "ports": [{"protocol": "udp", "port": 51821, "ip": "::"}]}
        path = "/modules/plan"
        params = {"csrf": "fixture-session", "module": "wireguard"}
        self.assertEqual(self.admin.post(path, data=params, base_url=ORIGIN).status_code, 403)
        self.assertEqual(self.admin.post(path, data=params, base_url=ORIGIN, headers={"Origin": "null"}).status_code, 403)
        self.assertEqual(self.admin.post(path, data=params, base_url=ORIGIN,
                                         headers={"Origin": "https://foreign.invalid"}).status_code, 403)
        self.assertEqual(self.admin.post(path, data={**params, "csrf": "wrong"}, base_url=ORIGIN,
                                         headers={"Origin": ORIGIN}).status_code, 403)
        self.lifecycle.plan.assert_not_called()
        page = self.admin.post(path, data=params, base_url=ORIGIN, headers={"Origin": ORIGIN})
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"UDP/51821", page.data)
        self.assertIn("Состояние не изменено".encode(), page.data)
        self.assertIn(b"module-progress.js", page.data)
        self.assertIn(b"<progress", page.data)
        self.assertIn("script-src 'self'", page.headers["Content-Security-Policy"])
        self.lifecycle.plan.assert_called_once_with("wireguard")
        self.lifecycle.set_enabled.assert_not_called()
        self.assertNotIn("script-src", self.admin.get("/", base_url=ORIGIN).headers["Content-Security-Policy"])

    def test_forms_preserve_origin_and_subscription_keeps_no_referrer(self):
        for path in ("/login", "/modules"):
            self.assertEqual(self.admin.get(path, base_url=ORIGIN).headers["Referrer-Policy"], "same-origin")
        self.assertEqual(self.admin.get("/sub/fixture-invalid", base_url=ORIGIN).headers["Referrer-Policy"], "no-referrer")
