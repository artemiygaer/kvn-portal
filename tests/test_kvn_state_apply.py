import json
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from tools import kvnctl
from tools.kvnlib.apply import (
    ApplyAction,
    SERVICE_CAPABILITIES,
    build_change_set,
    merge_service_change,
)
from tools.kvnlib.state import (
    JsonStateStore,
    StateRevisionConflict,
    atomic_write_json,
    atomic_write_text,
    state_revision,
)
from tools.kvnlib.services import effective_service_plan


def awg_state_with_user(enabled: bool = True) -> dict:
    return {
        "server": "203.0.113.10",
        "users": [
            {
                "name": "Alice",
                "uuid": "18f0bddd-8871-4ba5-98c3-5aefb29732e0",
                "hysteria_password": "StrongPass123",
                "telemt_secret": "ebe46ad6c9458f8c5a57922f8d28fe38",
                "enabled": enabled,
                "description": "",
                "systems": ["amneziawg"],
                "sni_overrides": {},
            }
        ],
    }


def wg_state_with_user(enabled: bool = True) -> dict:
    return {
        "server": "203.0.113.10",
        "users": [
            {
                "name": "Alice",
                "uuid": "18f0bddd-8871-4ba5-98c3-5aefb29732e0",
                "hysteria_password": "StrongPass123",
                "telemt_secret": "ebe46ad6c9458f8c5a57922f8d28fe38",
                "enabled": enabled,
                "description": "",
                "systems": ["wireguard"],
                "sni_overrides": {},
            }
        ],
    }


class JsonStateStoreTests(unittest.TestCase):
    def make_store(self, root: Path) -> JsonStateStore:
        path = root / "users.json"
        atomic_write_json(path, {"users": [], "counter": 0})
        return JsonStateStore(path, root / ".kvnctl.lock", timeout=3)

    def test_parallel_writers_do_not_lose_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))

            def add_user(name):
                def mutate(state):
                    current = state["counter"]
                    time.sleep(0.05)
                    state["counter"] = current + 1
                    state["users"].append({"name": name})

                return store.update(mutate)

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(add_user, ["Alice", "Bob"]))

            state = store.load()
            self.assertEqual(state["counter"], 2)
            self.assertEqual(sorted(user["name"] for user in state["users"]), ["Alice", "Bob"])
            self.assertTrue(all(result.changed for result in results))
            json.loads(store.path.read_text(encoding="utf-8"))

    def test_failure_before_replace_preserves_old_state_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = self.make_store(root)
            old_bytes = store.path.read_bytes()

            def fail(_temp_path):
                raise RuntimeError("инъекция сбоя")

            with self.assertRaisesRegex(RuntimeError, "инъекция сбоя"):
                store.update(lambda state: state.update(counter=1), before_replace=fail)

            self.assertEqual(store.path.read_bytes(), old_bytes)
            self.assertEqual(list(root.glob(".users.json.*.tmp")), [])
            self.assertEqual(store.load()["counter"], 0)

    def test_semantic_noop_does_not_replace_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            before = store.path.stat().st_mtime_ns
            result = store.update(lambda state: None)
            self.assertFalse(result.changed)
            self.assertEqual(store.path.stat().st_mtime_ns, before)

    def test_stale_revision_does_not_change_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = self.make_store(Path(tmp))
            stale = state_revision(store.load())
            store.update(lambda state: state.update(counter=1))
            before = store.path.read_bytes()
            with self.assertRaises(StateRevisionConflict):
                store.update(lambda state: state.update(counter=2), expected_revision=stale)
            self.assertEqual(store.path.read_bytes(), before)

    def test_atomic_text_failure_preserves_old_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / ".env"
            path.write_text("old\n", encoding="utf-8")

            def fail(_temp_path):
                raise RuntimeError("инъекция сбоя")

            with self.assertRaisesRegex(RuntimeError, "инъекция сбоя"):
                atomic_write_text(path, "new\n", before_replace=fail)
            self.assertEqual(path.read_text(encoding="utf-8"), "old\n")
            self.assertEqual(list(root.glob("..env.*.tmp")), [])


class EffectiveServicePlanTests(unittest.TestCase):
    def test_legacy_state_keeps_non_portal_services_enabled(self):
        plan = effective_service_plan({"users": [], "portal": {"enabled": False}})
        self.assertEqual(
            plan.enabled_docker,
            ("nginx", "xray", "hysteria", "telemt", "mtg", "ocserv"),
        )
        self.assertEqual(plan.enabled_host, ("amneziawg", "wireguard"))
        self.assertFalse(plan.enabled("portal"))
        self.assertFalse(plan.enabled("agent"))

    def test_explicit_disable_and_ip_portal_profile_are_deterministic(self):
        state = {
            "users": [],
            "services": {
                "xray": {"enabled": False},
                "wireguard": {"enabled": False},
            },
            "portal": {"enabled": True, "domain": "203.0.113.10", "port": 8443},
        }
        before = json.dumps(state, sort_keys=True)
        first = effective_service_plan(state)
        second = effective_service_plan(state)
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(state, sort_keys=True), before)
        self.assertNotIn("xray", first.enabled_docker)
        self.assertEqual(first.disabled_host, ("wireguard",))
        self.assertIn("portal-gateway", first.enabled_docker)
        self.assertEqual(first.compose_profiles, ("portal", "portal-custom"))
        self.assertTrue(first.enabled("agent"))


class ApplyPlanTests(unittest.TestCase):
    def test_noop_plan_has_no_actions_or_subprocess(self):
        plan = build_change_set({"xray/config.json": "same"}, {"xray/config.json": "same"})
        self.assertFalse(plan)
        self.assertEqual(plan.services, {})
        with mock.patch("tools.kvnctl.subprocess.run") as run:
            kvnctl.restart_services(plan)
        run.assert_not_called()

    def test_disabled_services_are_not_resurrected_by_apply(self):
        state = {
            "users": [],
            "services": {
                "xray": {"enabled": False},
                "amneziawg": {"enabled": False},
            },
        }
        plan = build_change_set(
            {"xray/config.json": "old", "amneziawg/awg0.conf": "old"},
            {"xray/config.json": "new", "amneziawg/awg0.conf": "new"},
        )
        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._sync_amneziawg") as awg_sync,
            mock.patch("tools.kvnctl._restart_docker_services", return_value=True) as restart,
        ):
            report = kvnctl.restart_services(plan, before_state=state, after_state=state)
        awg_sync.assert_not_called()
        restart.assert_called_once_with([])
        self.assertEqual(report["skipped_disabled"], ["amneziawg", "xray"])

    def test_plan_lists_paths_services_actions_and_reasons(self):
        before = {
            "nginx/nginx.conf": "old",
            "xray/config.json": "old",
            "clients/Alice/links.txt": "old",
        }
        after = {
            "nginx/nginx.conf": "new",
            "xray/config.json": "new",
            "clients/Alice/links.txt": "new",
        }
        plan = build_change_set(before, after)
        data = plan.to_dict()
        self.assertEqual(data["services"]["nginx"]["action"], "reload")
        self.assertEqual(data["services"]["nginx"]["reason"], "nginx-config")
        self.assertEqual(data["services"]["xray"]["action"], "restart")
        self.assertIn("clients/Alice/links.txt", data["changed_paths"])

    def test_action_priority_is_restart_reload_hot_noop(self):
        plan = build_change_set(
            {
                "ocserv/users.txt": "a",
                "ocserv/ocserv.conf": "a",
                "ocserv/ocserv.env": "a",
            },
            {
                "ocserv/users.txt": "b",
                "ocserv/ocserv.conf": "b",
                "ocserv/ocserv.env": "b",
            },
        )
        self.assertEqual(plan.services["ocserv"].action, ApplyAction.RESTART)
        self.assertEqual(len(plan.services["ocserv"].paths), 3)

    def test_unknown_capability_fails_safe_to_restart(self):
        services = {}
        merge_service_change(
            services,
            "unknown-service",
            ApplyAction.HOT_UPDATE,
            "requested-hot-update",
            "unknown/config",
        )
        self.assertEqual(services["unknown-service"].action, ApplyAction.RESTART)
        self.assertEqual(services["unknown-service"].reason, "unknown-capability")

    def test_capability_matrix_covers_all_managed_services(self):
        expected = {"nginx", "xray", "hysteria", "telemt", "mtg", "ocserv", "amneziawg", "wireguard"}
        self.assertEqual(set(SERVICE_CAPABILITIES), expected)
        for capability in SERVICE_CAPABILITIES.values():
            self.assertTrue(capability["version"])
            self.assertTrue(capability["evidence"])
            self.assertEqual(capability["fallback"], "restart")

    def test_capability_versions_match_pinned_compose_images(self):
        compose = (Path(__file__).resolve().parents[1] / "docker-compose.yml").read_text(encoding="utf-8")
        for service in ("nginx", "xray", "hysteria", "telemt", "mtg"):
            with self.subTest(service=service):
                self.assertIn(f"image: {SERVICE_CAPABILITIES[service]['version']}", compose)
        self.assertNotIn(":latest", compose)
        self.assertNotIn(":latest", json.dumps(SERVICE_CAPABILITIES, sort_keys=True))

    def test_xray_user_delta_uses_hot_api_without_restart(self):
        plan = build_change_set({"xray/config.json": "old"}, {"xray/config.json": "new"})
        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._hot_update_xray_users", return_value=True) as hot,
            mock.patch("tools.kvnctl._restart_docker_services") as restart,
        ):
            report = kvnctl.restart_services(
                plan,
                before_state={"users": []},
                after_state={"users": []},
            )
        hot.assert_called_once()
        restart.assert_called_once_with([])
        self.assertEqual(report["hot_updated"], ["xray"])
        self.assertEqual(report["restarted"], [])

    def test_xray_hot_failure_restarts_only_xray_once(self):
        plan = build_change_set({"xray/config.json": "old"}, {"xray/config.json": "new"})
        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._hot_update_xray_users", return_value=False),
            mock.patch("tools.kvnctl._restart_docker_services", return_value=True) as restart,
        ):
            report = kvnctl.restart_services(
                plan,
                before_state={"users": []},
                after_state={"users": []},
            )
        restart.assert_called_once_with(["xray"])
        self.assertEqual(report["restarted"], ["xray"])
        self.assertEqual(report["outcome"], "fallback")
        self.assertEqual(len(report["fallbacks"]), 1)
        self.assertEqual(report["warnings"], [])

    def test_failed_restart_requires_reconcile(self):
        plan = build_change_set({"xray/config.json": "old"}, {"xray/config.json": "new"})
        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._hot_update_xray_users", return_value=False),
            mock.patch("tools.kvnctl._restart_docker_services", return_value=False),
        ):
            report = kvnctl.restart_services(
                plan,
                before_state={"users": []},
                after_state={"users": []},
            )
        self.assertEqual(report["outcome"], "failed")
        self.assertEqual(report["failed"], ["xray"])
        self.assertTrue(report["reconcile_required"])

    def test_telemt_ocserv_awg_and_wg_user_changes_do_not_restart(self):
        cases = [
            ("telemt/config.toml", {}),
            ("ocserv/users.txt", {"tools.kvnctl._hot_update_ocserv_users": True}),
            ("amneziawg/awg0.conf", {"tools.kvnctl._sync_amneziawg": {
                "ok": True, "mode": "syncconf", "fallback": "", "reason": "ok",
            }}),
            ("wireguard/wg0.conf", {"tools.kvnctl._sync_wireguard": {
                "ok": True, "mode": "syncconf", "fallback": "", "reason": "ok",
            }}),
        ]
        for path, helpers in cases:
            with self.subTest(path=path):
                plan = build_change_set({path: "old"}, {path: "new"})
                patches = [
                    mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
                    mock.patch("tools.kvnctl._restart_docker_services", return_value=True),
                ]
                patches.extend(mock.patch(name, return_value=value) for name, value in helpers.items())
                active = [item.start() for item in patches]
                try:
                    report = kvnctl.restart_services(plan)
                finally:
                    for item in reversed(patches):
                        item.stop()
                self.assertEqual(report["restarted"], [])
                active[1].assert_called_once_with([])

    def test_amneziawg_sync_modes_and_failure_are_reported(self):
        plan = build_change_set({"amneziawg/awg0.conf": "old"}, {"amneziawg/awg0.conf": "new"})
        cases = [
            ({"ok": True, "mode": "syncconf", "fallback": "", "reason": "ok"}, "applied", ["amneziawg"], []),
            ({"ok": True, "mode": "restart", "fallback": "", "reason": "ok"}, "applied", [], ["amneziawg"]),
            ({"ok": True, "mode": "restart", "fallback": "syncconf_failed", "reason": "ok"}, "fallback", [], ["amneziawg"]),
            ({"ok": False, "mode": "failed", "fallback": "", "reason": "runtime_peer_mismatch"}, "failed", [], []),
        ]
        for sync, outcome, hot, restarted in cases:
            with self.subTest(sync=sync):
                with (
                    mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
                    mock.patch("tools.kvnctl._sync_amneziawg", return_value=sync),
                    mock.patch("tools.kvnctl._restart_docker_services", return_value=True),
                ):
                    report = kvnctl.restart_services(plan, after_state={"users": []})
                self.assertEqual(report["outcome"], outcome)
                self.assertEqual(report["hot_updated"], hot)
                self.assertEqual(report["restarted"], restarted)
                self.assertEqual(report["reconcile_required"], outcome == "failed")

    def test_host_sync_reports_forwarding_policy_failure(self):
        cases = [
            (kvnctl._sync_amneziawg, "KVN_AWG_ERROR=ipv4_forwarding_disabled"),
            (kvnctl._sync_wireguard, "KVN_WG_ERROR=ipv4_forwarding_disabled"),
        ]
        for helper, marker in cases:
            with (
                self.subTest(helper=helper.__name__),
                mock.patch("tools.kvnctl.shutil.which", return_value="/usr/bin/tool"),
                mock.patch.object(kvnctl.os, "geteuid", return_value=0, create=True),
                mock.patch(
                    "tools.kvnctl.subprocess.run",
                    return_value=mock.Mock(returncode=1, stdout="", stderr=marker + "\n"),
                ),
            ):
                result = helper({"users": []})
            self.assertFalse(result["ok"])
            self.assertEqual(result["reason"], "ipv4_forwarding_disabled")

    def test_amneziawg_semantic_delta_is_applied_even_for_client_only_plan(self):
        before_state = {"server": "203.0.113.10", "users": []}
        after_state = awg_state_with_user()
        kvnctl.prepare_state(after_state)
        plan = kvnctl.ChangeSet(changed_paths=("clients/Alice/amneziawg.conf",), services={})
        sync = {
            "ok": True,
            "mode": "syncconf",
            "fallback": "",
            "reason": "ok",
            "verified": True,
            "verification": {"expected_peers": 1, "runtime_peers": 1},
        }

        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._sync_amneziawg", return_value=sync) as awg_sync,
            mock.patch("tools.kvnctl._restart_docker_services") as restart,
        ):
            report = kvnctl.restart_services(
                plan,
                before_state=before_state,
                after_state=after_state,
            )

        awg_sync.assert_called_once()
        restart.assert_not_called()
        self.assertEqual(report["hot_updated"], ["amneziawg"])
        self.assertEqual(report["details"]["amneziawg"]["expected_peers"], 1)
        self.assertEqual(report["details"]["amneziawg"]["runtime_peers"], 1)

    def test_wireguard_semantic_delta_is_applied_even_for_client_only_plan(self):
        before_state = {"server": "203.0.113.10", "users": []}
        after_state = wg_state_with_user()
        kvnctl.prepare_state(after_state)
        plan = kvnctl.ChangeSet(changed_paths=("clients/Alice/wireguard.conf",), services={})
        sync = {
            "ok": True,
            "mode": "syncconf",
            "fallback": "",
            "reason": "ok",
            "verified": True,
            "verification": {"expected_peers": 1, "runtime_peers": 1},
        }

        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._sync_wireguard", return_value=sync) as wg_sync,
            mock.patch("tools.kvnctl._restart_docker_services") as restart,
        ):
            report = kvnctl.restart_services(
                plan,
                before_state=before_state,
                after_state=after_state,
            )

        wg_sync.assert_called_once()
        restart.assert_not_called()
        self.assertEqual(report["hot_updated"], ["wireguard"])
        self.assertEqual(report["details"]["wireguard"]["expected_peers"], 1)
        self.assertEqual(report["details"]["wireguard"]["runtime_peers"], 1)

    def test_forced_host_sync_applies_awg_and_wg_even_without_render_delta(self):
        sync = {
            "ok": True,
            "mode": "syncconf",
            "fallback": "",
            "reason": "ok",
            "verified": True,
            "verification": {"expected_peers": 1, "runtime_peers": 1},
        }
        with (
            mock.patch("tools.kvnctl.shutil.which", return_value="docker"),
            mock.patch("tools.kvnctl._sync_amneziawg", return_value=sync) as awg_sync,
            mock.patch("tools.kvnctl._sync_wireguard", return_value=sync) as wg_sync,
            mock.patch("tools.kvnctl._restart_docker_services") as restart,
        ):
            report = kvnctl.restart_services(
                kvnctl.ChangeSet(),
                after_state={"users": []},
                force_host_sync_services={"amneziawg", "wireguard"},
            )

        awg_sync.assert_called_once()
        wg_sync.assert_called_once()
        restart.assert_not_called()
        self.assertEqual(report["hot_updated"], ["amneziawg", "wireguard"])

    def test_hysteria_portal_auth_removes_user_file_churn(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "config.yaml"
            state = {
                "portal": {"enabled": True, "hysteria_secret": "secret value"},
                "users": [{
                    "name": "Alice", "enabled": True,
                    "systems": ["hysteria"], "hysteria_password": "private",
                }],
            }
            with mock.patch.object(kvnctl, "HY2_CONFIG", output):
                kvnctl.render_hysteria(state)
            text = output.read_text(encoding="utf-8")
            self.assertIn("type: http", text)
            self.assertIn("token=secret%20value", text)
            self.assertIn("trafficStats:", text)
            self.assertIn("listen: 127.0.0.1:9090", text)
            self.assertNotIn("private", text)


if __name__ == "__main__":
    unittest.main()
