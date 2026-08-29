"""Архитектурные контракты модульного portal control."""

import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path

from portal.control import ControlError, KvnControl
from portal.control.diagnostics import DiagnosticsService
from portal.control.exports import ExportsService
from portal.control.protocols import ProtocolsService
from portal.control.services import ServicesService
from portal.control.shared import ControlDependencies
from portal.control.updates import UpdatesService
from portal.control.users import UsersService

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PUBLIC_SHA = "19dec69aaafaec8d70c940a3806086cdee5caa8d86403522d3692177d3475be2"

class ControlFacadeTests(unittest.TestCase):
    def test_public_api_inventory_matches_v3(self):
        public = sorted(name for name, value in inspect.getmembers(KvnControl, inspect.isfunction) if not name.startswith("_"))
        digest = hashlib.sha256(json.dumps(public, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(len(public), 31)
        self.assertEqual(digest, EXPECTED_PUBLIC_SHA)

    def test_compatibility_facade_is_under_300_lines(self):
        source = (ROOT / "portal/control.py").read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 300)
        self.assertNotIn("class KvnControl", source)

class ExplicitServiceDependencyTests(unittest.TestCase):
    class FakeControl:
        def __init__(self):
            self.calls = []
        def list_users(self): self.calls.append("list"); return {"revision": "r", "users": []}
        def get_user(self, name): self.calls.append(("get", name)); return {"name": name}
        def apply_user(self, params): self.calls.append(("apply", params)); return {"revision": "next"}
        def apply_protocol(self, params): return {"revision": "protocol"}
        def apply_sni_route(self, params): return {"revision": "sni"}
        def apply_mtproto(self, params): return {"revision": "mtproto"}
        def apply_amneziawg(self, params): return {"revision": "awg"}
        def service_preferences(self): return {"xray": True}
        def set_service_enabled(self, service, enabled): return {service: enabled}
        def apply_host_service(self, service): return {"service": service}
        def reconcile_state(self): return {"outcome": "applied"}
        def client_export_settings(self): return {"address_mode": "server"}
        def update_client_export(self, params): return params
        def user_export(self, name, address_mode): return {"name": name, "mode": address_mode}
        def network_topology(self): return {"protocols": []}
        def domain_advice(self, params): return {"status": "ok"}
        def sni_diagnose(self, params): return {"status": "ok"}

    def setUp(self):
        self.fake = self.FakeControl()
        self.deps = ControlDependencies.create(Path.cwd(), self.fake)

    def test_bounded_services_receive_dependencies_explicitly(self):
        self.assertEqual(UsersService(self.deps).list()["users"], [])
        self.assertEqual(ProtocolsService(self.deps).apply({})["revision"], "protocol")
        self.assertTrue(ServicesService(self.deps).preferences()["xray"])
        self.assertEqual(ExportsService(self.deps).user_bundle("alice", "server")["name"], "alice")
        self.assertEqual(DiagnosticsService(self.deps).topology(), {"protocols": []})
        update = UpdatesService(lambda: {"status": "ready"}, lambda value: value)
        self.assertEqual(update.status()["status"], "ready")

    def test_revision_failure_does_not_mutate_service_state_or_echo_secret(self):
        secret = "NEVER_ECHO_CONTROL_SECRET"
        before = list(self.fake.calls)
        def reject(_params):
            raise ControlError("revision_conflict", "Состояние изменилось.")
        self.fake.apply_user = reject
        with self.assertRaises(ControlError) as caught:
            UsersService(self.deps).apply({"revision": "stale", "password": secret})
        self.assertEqual(self.fake.calls, before)
        self.assertNotIn(secret, str(caught.exception))

if __name__ == "__main__":
    unittest.main()
