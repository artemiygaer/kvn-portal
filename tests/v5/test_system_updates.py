"""Проверки APT-плана, границы панели и одноразового включения Shell."""

from contextlib import nullcontext
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from tests.v5.test_console_agent import SID
from v5.core.console import upgrade
from v5.core.maintenance import system_updates as updates
from v5.core.maintenance import release_poll
from v5.core.maintenance.portal_store import UpdateStoreError
from v5.portal.app import create_app

ORIGIN = "https://localhost:8443"
VALID = "Inst linux-image-6.1.0-99-amd64 (1:6.1.456-1 Debian-Security:12/oldstable-security [amd64])\n"


class SystemUpdatesTests(TestCase):
    def test_periodic_github_status_only_offers_fresh_newer_release(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "release.json"
            source = Mock()
            source.latest.return_value = "v5.0.10"
            release_poll.refresh(path, source=source, clock=lambda: 100)
            source.latest.assert_called_once_with()
            source.prepare.assert_not_called()
            self.assertEqual(release_poll.snapshot("5.0.9", path, clock=lambda: 120)["status"], "available")
            self.assertEqual(release_poll.snapshot("5.0.11", path, clock=lambda: 120)["status"], "current")
            self.assertEqual(release_poll.snapshot("5.0.9", path, clock=lambda: 100000)["status"], "unknown")

    def test_reject_removal_and_unrecognised_plan(self):
        self.assertEqual(updates.parse_plan(VALID), (("linux-image-6.1.0-99-amd64", "1:6.1.456-1"),))
        for plan in ("Remv nginx [1.0]", "Inst broken", "Conf incomplete configured"):
            with self.subTest(plan=plan), self.assertRaises(UpdateStoreError):
                updates.parse_plan(plan)

    def test_install_uses_approved_plan_no_auto_reboot(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            output = [VALID]
            commands = []

            def apt(command, stage, *, capture=False, timeout=None):
                commands.append(command)
                return output[0] if capture else ""

            with patch.object(updates, "parse_os_release"), patch.object(updates, "apt_stage", return_value=nullcontext(Path("/tmp"))), \
                    patch.object(updates, "apt_base", return_value=("apt-get",)), patch.object(updates, "boot_id", return_value="boot-test"), \
                    patch.object(updates, "REBOOT_REQUIRED", Path(directory) / "absent"):
                updates.perform("check", path=state, apt=apt, clock=lambda: 10)
                first = updates.read_state(state)
                self.assertEqual(first["total"], 1)
                output[0] = VALID.replace("-99-", "-100-")
                updates.perform("install", first["plan"], path=state, apt=apt, clock=lambda: 20)
                self.assertEqual(updates.read_state(state)["phase"], "plan_changed")
                self.assertFalse(any("-y" in command for command in commands))
                updates.perform("check", path=state, apt=apt, clock=lambda: 30)
                second = updates.read_state(state)
                updates.perform("install", second["plan"], path=state, apt=apt, clock=lambda: 40)
                final = updates.status(state, clock=lambda: 41)
                self.assertEqual(final["phase"], "done")
                self.assertTrue(final["needs_reboot"])
                self.assertIn("--no-remove", commands[-1])
                self.assertIn("-y", commands[-1])
                self.assertFalse(any("reboot" in argv for argv in commands))
            with patch.object(updates, "boot_id", return_value="next-boot"), patch.object(updates, "REBOOT_REQUIRED", Path(directory) / "absent"):
                self.assertFalse(updates.status(state, clock=lambda: 42)["needs_reboot"])

    def test_reboot_requires_confirmation_and_current_boot_marker(self):
        run = Mock()
        with patch.object(updates, "status", return_value={"needs_reboot": False}):
            for args in ({}, {"confirm": "yes"}):
                with self.assertRaises(UpdateStoreError):
                    updates.launch("reboot", args, run=run)
        run.assert_not_called()

    def test_dashboard_and_post_guards(self):
        client = Mock()
        client.system_status.return_value = {"phase": "ready", "total": 2, "stale": False, "needs_reboot": False,
                                             "portal_release": {"status": "available", "tag": "v5.0.10"}}
        backend = Mock()
        backend.package_status.return_value = {"installed": []}
        backend.status.return_value = None
        app = create_app({"session_key": "test", "allowed_hosts": ["localhost:8443"]}, client=backend,
                         core_update_client=client)
        browser = app.test_client()
        root = "/maintenance/system"
        self.assertEqual(browser.get(root, base_url=ORIGIN).status_code, 303)
        with browser.session_transaction(base_url=ORIGIN) as values:
            values.update(admin=True, console_sid=SID, csrf="fixture")
        page = browser.get("/", base_url=ORIGIN).data
        self.assertIn("Доступно обновлений: 2".encode(), page)
        self.assertIn("Доступен портал v5.0.10".encode(), page)
        self.assertEqual(browser.post(root + "/check", base_url=ORIGIN, data={"csrf": "fixture"}).status_code, 403)
        headers = {"Origin": ORIGIN}
        self.assertEqual(browser.post(root + "/reboot", base_url=ORIGIN, headers=headers,
                                      data={"csrf": "fixture"}).status_code, 400)
        client.system_action.assert_not_called()
        self.assertEqual(browser.post(root + "/check", base_url=ORIGIN, headers=headers,
                                      data={"csrf": "fixture"}).status_code, 303)
        client.system_action.assert_called_once_with("check")

    def test_console_migration_only_for_upgraded_v508_and_not_clean_install(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            live = root / "live"
            live.mkdir()
            (live / "core-version").write_text("5.0.9\n")
            transactions = root / "transactions"
            runner = Mock()
            upgrade.schedule(live=live, transactions=transactions, run=runner)
            runner.assert_not_called()
            old = transactions / "pending/tree"
            old.mkdir(parents=True)
            (old / "core-version").write_text("5.0.8\n")
            upgrade.schedule(live=live, transactions=transactions, run=runner)
            self.assertIn(f"--unit={upgrade.UNIT}", runner.call_args.args[0])
            old.parent.rename(transactions / "previous")
            self.assertNotIn(upgrade.WEB_SOCKET_UNIT, runner.call_args.args[0])
            with patch.object(upgrade.importlib.util, "find_spec", return_value=True):
                upgrade.activate(live=live, transactions=transactions, run=runner)
            self.assertEqual(runner.call_args.args[0], (upgrade.SYSTEMCTL, "start", upgrade.WEB_SOCKET_UNIT))

    def test_manual_console_actions_are_allowlisted_and_require_confirmation(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            runner = Mock()
            for action, confirmation in (("reboot", "yes"), ("enable", "no")):
                with self.assertRaises(ValueError):
                    upgrade.control(action, confirmation, live=root, transactions=root, run=runner)
            runner.assert_not_called()
            upgrade.control("disable", "yes", live=root, transactions=root, run=runner)
            self.assertIn(f"--unit={upgrade.UNIT}", runner.call_args.args[0])
            self.assertEqual(runner.call_args.args[0][-1], "disable")

    def test_console_toggle_requires_web_csrf_reauth_and_explicit_confirmation(self):
        from v5.core.credentials import hash_admin_password

        client, terminal = Mock(), Mock()
        terminal.available.return_value = False
        password = "local-console-fixture-password"
        app = create_app({"session_key": "test", "allowed_hosts": ["localhost:8443"],
                          "admin_login": "admin", "password_hash": hash_admin_password(password)}, client=Mock(),
                         core_update_client=client, console_client=terminal)
        browser = app.test_client()
        with browser.session_transaction(base_url=ORIGIN) as values:
            values.update(admin=True, console_sid=SID, csrf="fixture")
        route = "/maintenance/console/control"
        data = {"csrf": "fixture", "action": "enable", "admin_password": password}
        headers = {"Origin": ORIGIN}
        self.assertEqual(browser.post(route, base_url=ORIGIN, data={**data, "confirm": "yes"}).status_code, 403)
        self.assertEqual(browser.post(route, base_url=ORIGIN, headers=headers, data=data).status_code, 400)
        self.assertEqual(browser.post(route, base_url=ORIGIN, headers=headers,
                                      data={**data, "confirm": "yes", "admin_password": "wrong"}).status_code, 303)
        client.shell_control.assert_not_called()
        self.assertEqual(browser.post(route, base_url=ORIGIN, headers=headers,
                                      data={**data, "confirm": "yes"}).status_code, 303)
        client.shell_control.assert_called_once_with("enable")
