"""Контракт маршрутов после разделения application factory на Blueprints."""

import json
import tempfile
import unittest
from pathlib import Path

from app import create_app


EXPECTED = {
    "login": ("/gaer/login", {"GET", "POST"}),
    "logout": ("/gaer/logout", {"POST"}),
    "dashboard": ("/gaer/", {"GET"}),
    "network_view": ("/gaer/network", {"GET"}),
    "network_json": ("/gaer/network.json", {"GET"}),
    "network_protocol_apply": ("/gaer/network/protocol/apply", {"POST"}),
    "network_sni_apply": ("/gaer/network/sni/apply", {"POST"}),
    "dashboard_json": ("/gaer/dashboard.json", {"GET"}),
    "metrics_history_json": ("/gaer/metrics/history.json", {"GET"}),
    "project_release_check": ("/gaer/settings/update/github/check", {"POST"}),
    "project_release_prepare": ("/gaer/settings/update/github/prepare", {"POST"}),
    "project_update_prepare": ("/gaer/settings/update/prepare", {"POST"}),
    "project_update_start": ("/gaer/settings/update/start", {"POST"}),
    "project_update_discard": ("/gaer/settings/update/discard", {"POST"}),
    "terminal_shell_open": ("/gaer/terminal/shell/open", {"POST"}),
    "terminal_shell_read": ("/gaer/terminal/shell/read", {"POST"}),
    "terminal_shell_write": ("/gaer/terminal/shell/write", {"POST"}),
    "terminal_shell_resize": ("/gaer/terminal/shell/resize", {"POST"}),
    "terminal_shell_close": ("/gaer/terminal/shell/close", {"POST"}),
    "root_shell_view": ("/gaer/shell", {"GET"}),
    "users_list": ("/gaer/users", {"GET"}),
    "services_list": ("/gaer/services", {"GET"}),
    "service_action": ("/gaer/services/<service>/action", {"POST"}),
    "logs_view": ("/gaer/logs", {"GET"}),
    "logs_json": ("/gaer/logs.json", {"GET"}),
    "terminal_view": ("/gaer/terminal", {"GET", "POST"}),
    "certificates_view": ("/gaer/certificates", {"GET"}),
    "certificate_action": ("/gaer/certificates/action", {"POST"}),
    "health_view": ("/gaer/health", {"GET"}),
    "audit_view": ("/gaer/audit", {"GET"}),
    "audit_export": ("/gaer/audit/export.csv", {"GET"}),
    "backups_view": ("/gaer/backups", {"GET", "POST"}),
    "backup_download": ("/gaer/backups/files/<filename>", {"GET"}),
    "project_info": ("/gaer/project", {"GET"}),
    "user_create": ("/gaer/users/new", {"GET", "POST"}),
    "user_detail": ("/gaer/users/<name>", {"GET"}),
    "user_activity_json": ("/gaer/users/<name>/activity.json", {"GET"}),
    "user_edit": ("/gaer/users/<name>/edit", {"GET", "POST"}),
    "user_action": ("/gaer/users/<name>/action", {"POST"}),
    "user_toggle": ("/gaer/users/<name>/toggle", {"POST"}),
    "reconcile_state": ("/gaer/reconcile", {"POST"}),
    "settings_view": ("/gaer/settings", {"GET", "POST"}),
    "user_export_zip": ("/gaer/users/<name>/export.zip", {"GET"}),
    "user_export_text": ("/gaer/users/<name>/export.txt", {"GET"}),
    "user_download": ("/gaer/users/<name>/files/<filename>", {"GET"}),
    "user_inline_file": ("/gaer/users/<name>/files/<filename>/inline", {"GET"}),
    "user_file_preview": ("/gaer/users/<name>/files/<filename>/view", {"GET"}),
    "hysteria_auth": ("/internal/hysteria/auth", {"POST"}),
    "internal_health": ("/internal/health", {"GET"}),
}


class PortalRouteContractTests(unittest.TestCase):
    def test_paths_methods_endpoints_and_blueprints_are_compatible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            users = root / "users.json"
            users.write_text(json.dumps({"users": []}), encoding="utf-8")
            app = create_app({
                "TESTING": True,
                "DATABASE": root / "portal.db",
                "USERS_FILE": users,
                "PORTAL_PATH": "/gaer",
                "PROXY_SECRET": "fixture",
            })

        actual = {}
        for rule in app.url_map.iter_rules():
            if rule.endpoint == "static":
                continue
            actual[rule.endpoint] = (
                rule.rule,
                set(rule.methods) - {"HEAD", "OPTIONS"},
            )
        self.assertEqual(actual, EXPECTED)
        self.assertEqual(
            set(app.blueprints),
            {"auth", "users", "services", "diagnostics", "settings"},
        )

    def test_blueprints_do_not_execute_host_commands_directly(self):
        blueprint_dir = Path(__file__).resolve().parents[1] / "app/blueprints"
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in blueprint_dir.glob("*.py")
        )
        for forbidden in (
            "subprocess.",
            "os.system(",
            "docker.sock",
            "DockerClient(",
            "Popen(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
