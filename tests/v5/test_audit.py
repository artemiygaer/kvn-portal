"""Границы чтения журнала, аудит операций и доступ из панели."""

import json
from subprocess import TimeoutExpired
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core import audit
from v5.core.agent import AgentApplication
from v5.core.contracts import CORE_API_VERSION
from v5.portal.app import create_app
from v5.portal.log_routes import OPERATION_LABELS, SOURCE_LABELS
from v5.portal.rpc import AgentUnavailable

ORIGIN = "https://localhost:8443"
STAMP = "1780000000000000"


def line(**fields):
    return json.dumps({"__REALTIME_TIMESTAMP": STAMP, "PRIORITY": "6", **fields}).encode() + b"\n"


class AuditTests(TestCase):
    def test_audit_records_only_known_operation_result_and_module(self):
        with patch.object(audit.syslog, "openlog"), patch.object(audit.syslog, "syslog") as sink:
            audit.outcome({"method": "migration.preview", "params": {"phrase": "fixture-secret"}},
                          {"ok": False, "error": "fixture-secret"})
            audit.outcome({"method": "package.install", "params": {"ticket": "fixture-token"}},
                          {"ok": True, "result": {"module": "wireguard", "token": "fixture-token"}})
            audit.outcome({"method": "users.subscription", "params": {"token": "fixture-token"}}, {"ok": True})
            audit.outcome({"method": "lifecycle.enable", "params": {"module": ["fixture-secret"]}}, {"ok": False})
        self.assertEqual([entry.args[1] for entry in sink.call_args_list],
                         ["migration.preview failed -", "package.install ok wireguard", "lifecycle.enable failed -"])

    def test_journal_projects_allowlisted_fields_with_fixed_query_and_limits(self):
        runner = Mock(return_value=SimpleNamespace(stdout=(
            line(MESSAGE="fixture-secret") + line(MESSAGE="package.install ok wireguard", extra="fixture-token")
            + line(MESSAGE="users.grant failed -") + line(MESSAGE="lifecycle.enable ok attacker")
            + line(MESSAGE=[255, 255]) + b"{not-json}\n")))
        rows = audit.recent("operations", run=runner)
        self.assertEqual([(r["method"], r["status"], r["module"]) for r in rows],
                         [("package.install", "ok", "wireguard"), ("users.grant", "failed", None)])
        argv = runner.call_args.args[0]
        self.assertIn("_UID=0", argv)
        self.assertIn("_TRANSPORT=syslog", argv)
        self.assertIn("--lines=40", argv)
        self.assertIn("--since=-24h", argv)
        self.assertEqual(runner.call_args.kwargs["timeout"], 1.4)
        self.assertNotIn("fixture", json.dumps(rows))
        runner.return_value.stdout = line(MESSAGE="private fixture", PRIORITY="3") * 50
        rows = audit.recent("xray", run=runner)
        self.assertEqual(len(rows), 40)
        self.assertTrue(all(set(row) == {"time", "priority"} and row["priority"] == 3 for row in rows))
        argv = runner.call_args.args[0]
        self.assertIn("_SYSTEMD_UNIT=kvn-v5-module-xray.service", argv)
        self.assertNotIn("MESSAGE", " ".join(argv))
        runner.return_value.stdout = b"x" * (audit.MAX_OUTPUT + 1)
        with self.assertRaises(ValueError):
            audit.recent("xray", run=runner)
        runner.reset_mock()
        with self.assertRaises(ValueError):
            audit.recent("--file=/etc/shadow", run=runner)
        runner.assert_not_called()

    def test_agent_journal_strict_schema_peer_and_timeout(self):
        backend = Mock(return_value=[])
        app = AgentApplication(123, journal=backend)
        request = {"version": CORE_API_VERSION, "method": "journal.recent", "params": {"source": "gateway"}}
        self.assertEqual(app.dispatch(124, request)["error"], "forbidden")
        for params in ({}, {"source": "ssh"}, {"source": ["gateway"]}, {"source": "gateway", "limit": 5000}):
            self.assertEqual(app.dispatch(123, {**request, "params": params})["error"], "invalid_request")
        self.assertEqual(app.dispatch(123, request, body=b"x")["error"], "invalid_request")
        backend.assert_not_called()
        self.assertEqual(app.dispatch(123, request), {"ok": True, "result": {"entries": []}})
        backend.assert_called_once_with("gateway")
        backend.side_effect = TimeoutExpired("fixture", 1)
        self.assertEqual(app.dispatch(123, request)["error"], "journal_unavailable")

    def test_logs_only_load_for_authorized_and_selected_source(self):
        backend = Mock()
        backend.status.return_value = {}
        backend.package_status.return_value = {"installed": []}
        backend.journal_recent.return_value = {"entries": [{"time": "2026-11-11T12:00:00+00:00",
                                                             "priority": 3, "MESSAGE": "fixture-secret"}]}
        app = create_app({"session_key": "fixture-only", "allowed_hosts": ["localhost:8443"]}, client=backend)
        guest = app.test_client()
        self.assertEqual(guest.get("/logs", base_url=ORIGIN).status_code, 303)
        admin = app.test_client()
        with admin.session_transaction(base_url=ORIGIN) as session:
            session["admin"] = True
        self.assertEqual(admin.get("/", base_url=ORIGIN).status_code, 200)
        for query in ("source=ssh", "source=xray&source=gateway", "source=xray&limit=10"):
            self.assertEqual(admin.get("/logs?" + query, base_url=ORIGIN).status_code, 400)
        backend.journal_recent.assert_not_called()
        response = admin.get("/logs?source=xray", base_url=ORIGIN)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Ошибка".encode(), response.data)
        self.assertNotIn(b"fixture-secret", response.data)
        self.assertNotIn(b"<script", response.data)
        backend.journal_recent.assert_called_once_with("xray")
        backend.journal_recent.side_effect = AgentUnavailable()
        response = admin.get("/logs", base_url=ORIGIN)
        self.assertEqual(response.status_code, 503)
        self.assertIn("Журнал недоступен".encode(), response.data)
        self.assertEqual(set(SOURCE_LABELS), set(audit.SOURCES))
        self.assertEqual(set(OPERATION_LABELS), audit.OPERATIONS)
