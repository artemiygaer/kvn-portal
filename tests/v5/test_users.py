"""Проверки общей модели прав без запуска модулей и сети."""

import unittest
import base64
from contextlib import nullcontext
import os
from pathlib import Path
import re
import socket
from tempfile import TemporaryDirectory
from threading import Event, Thread
from types import SimpleNamespace
from unittest.mock import patch

from v5.core.contracts import UserGrant
from v5.core.lifecycle.rpc import Application
from v5.core.users.model import GrantState, ModuleState, SubscriptionToken, User
from v5.core.users.store import UserStore
from v5.core.users.controller import UserApplyError, UserController
from v5.core.users.subscription import SubscriptionService
from v5.core.users.journal import MAX_SNAPSHOT, PendingUserApply, UserApplyJournal
from v5.core.users.transaction import TransactionError, UserTransaction
from v5.core.users.settings_backend import SettingsBackend
from v5.core.users.settings_module import SettingsUserModule
from v5.core.users.recovery import UserRecovery
from v5.core.users.rpc import UsersApplication
from v5.modules.xray.config import Settings as XraySettings
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles
from v5.modules.xray.users import set_user as set_xray_user, subscription_uris as xray_user_uris
from v5.modules.xray.clients import client_profiles as xray_profiles
from v5.modules.hysteria.config import Account as HysteriaAccount, Settings as HysteriaSettings, identity, render_server
from v5.modules.hysteria.users import set_user as set_hysteria_user, subscription_uris as hysteria_user_uris
from v5.modules.hysteria.idle import idle_secret
from v5.modules.hysteria.clients import client_profile as hysteria_profile
from v5.portal.app import create_app
from v5.portal.rpc import UsersClient

GENERATION = "a" * 64


class UserModelTests(unittest.TestCase):
    def setUp(self):
        self.user = User("alice", "alice")

    def test_missing_disabled_pending_error_and_active(self):
        grant = UserGrant("alice", "xray", True)
        for state, module, expected in (
            (GrantState(grant, False), ModuleState("xray", False, False), "awaiting_install"),
            (GrantState(grant, False, True), ModuleState("xray", False, False), "awaiting_install"),
            (GrantState(grant, True), ModuleState("xray", True, False), "disabled"),
            (GrantState(grant, False, True), ModuleState("xray", True, False), "disabled"),
            (GrantState(grant, False), ModuleState("xray", True, True), "pending"),
            (GrantState(grant, True, True), ModuleState("xray", True, True), "error"),
            (GrantState(grant, True, generation=GENERATION), ModuleState("xray", True, True, GENERATION), "active"),
            (GrantState(grant, True, generation=GENERATION), ModuleState("xray", True, True, "b" * 64), "pending"),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(state.status(self.user, module), expected)
                self.assertEqual(state.can_export(self.user, module), expected == "active")

    def test_revocation_and_user_mismatch_fail_closed(self):
        module = ModuleState("hysteria", True, True)
        state = GrantState(UserGrant("alice", "hysteria", False), True)
        self.assertEqual(state.status(self.user, module), "revoking")
        self.assertFalse(state.can_export(self.user, module))
        with self.assertRaises(ValueError):
            state.can_export(User("bob", "bob"), module)
        with self.assertRaises(ValueError):
            ModuleState("hysteria", False, True)

    def test_random_tokens_are_private_and_checked_by_digest(self):
        first, second = SubscriptionToken.create(), SubscriptionToken.create()
        self.assertTrue(first.matches(first.digest()))
        self.assertFalse(second.matches(first.digest()))
        self.assertFalse(first.matches(b""))
        self.assertNotIn(first.value, repr(first))
        with self.assertRaises(ValueError):
            SubscriptionToken("short")

    def test_legacy_display_name_does_not_become_identifier(self):
        user = User("alice_01", "Alice.Office")
        self.assertEqual(user.name, "Alice.Office")
        with self.assertRaises(ValueError):
            User("alice/01", "alice")
        with self.assertRaises(ValueError):
            User("alice", "..")

    def test_module_user_changes_preserve_independent_secrets(self):
        xray = XraySettings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, "portal.example"),)))
        hysteria = HysteriaSettings(identity("portal.example"), (HysteriaAccount.create("bob"),))
        xray = set_xray_user(xray, "alice", True)
        hysteria = set_hysteria_user(hysteria, "alice", True)
        xray_id = xray.accounts[0].id
        secret = next(item.password for item in hysteria.accounts if item.name == "alice")
        bob = next(item for item in hysteria.accounts if item.name == "bob")
        xray = set_xray_user(xray, "alice", False)
        hysteria = set_hysteria_user(hysteria, "alice", False)
        self.assertEqual(xray.accounts[0].grants, ())
        self.assertFalse(next(item for item in hysteria.accounts if item.name == "alice").enabled)
        self.assertEqual(next(item for item in hysteria.accounts if item.name == "bob"), bob)
        xray = set_xray_user(xray, "alice", True)
        hysteria = set_hysteria_user(hysteria, "alice", True)
        self.assertEqual(xray.accounts[0].id, xray_id)
        self.assertEqual(next(item.password for item in hysteria.accounts if item.name == "alice"), secret)


class UserStoreTests(unittest.TestCase):
    def test_two_modules_revisions_and_failed_apply(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            user = User("alice", "Alice.Office")
            store.create(user)
            with self.assertRaises(ValueError):
                store.create(user)
            self.assertEqual(store.list_users(), ({"id": "alice", "name": "Alice.Office", "enabled": True,
                                                   "revision": 1},))
            with self.assertRaises(ValueError):
                store.list_users(limit=101)
            first = UserGrant("alice", "xray", True)
            second = UserGrant("alice", "hysteria", True)
            revision = store.set_grant(first, revision=1)
            revision = store.confirm_grant(first, revision=revision, generation=GENERATION)
            revision = store.set_grant(second, revision=revision)
            revision = store.confirm_grant(second, revision=revision, error=True)
            saved, actual, grants = store.get("alice")
            self.assertEqual((saved, actual), (user, revision))
            by_module = {item.grant.module_id: item for item in grants}
            self.assertEqual(by_module["xray"].status(user, ModuleState("xray", True, True, GENERATION)), "active")
            self.assertEqual(by_module["hysteria"].status(user, ModuleState("hysteria", True, True)), "error")
            with self.assertRaises(ValueError):
                store.confirm_grant(first, revision=1, generation=GENERATION)
            revoke = UserGrant("alice", "xray", False)
            revision = store.set_grant(revoke, revision=revision)
            self.assertEqual(store.get("alice")[2][1].status(user, ModuleState("xray", True, True)), "revoking")
            store.confirm_grant(revoke, revision=revision)
            self.assertEqual(store.get("alice")[2][1].status(user, ModuleState("xray", True, True)), "revoked")

    def test_token_rotation_and_file_permissions(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            first = store.rotate_token("alice", revision=1)
            self.assertEqual(store.subscription_owner(first), "alice")
            second = store.rotate_token("alice", revision=2)
            self.assertIsNone(store.subscription_owner(first))
            self.assertEqual(store.subscription_owner(second), "alice")
            self.assertEqual(store.database.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(second.value.encode(), store.database.read_bytes())
            store.revoke_token("alice", revision=3)
            self.assertIsNone(store.subscription_owner(second))

    def test_insecure_store_rejected(self):
        with TemporaryDirectory() as folder:
            root = Path(folder) / "users"
            root.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                UserStore(root)

    def test_module_epoch_invalidation_is_persistent_and_scoped(self):
        with TemporaryDirectory() as folder:
            root = Path(folder) / "users"
            store = UserStore(root)
            first = store.confirm_module("xray")
            other = store.confirm_module("hysteria")
            self.assertNotEqual(first, other)
            with self.assertRaises(ValueError):
                store.confirm_module("xray")
            store.invalidate_module("xray")
            reopened = UserStore(root)
            self.assertIsNone(reopened.module_generation("xray"))
            self.assertEqual(reopened.module_generation("hysteria"), other)
            self.assertNotEqual(reopened.confirm_module("xray"), first)
            with self.assertRaises(ValueError):
                reopened.confirm_module("ocserv")


class UserJournalTests(unittest.TestCase):
    def test_snapshot_is_private_immutable_and_detects_corruption(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "user.pending"
            journal = UserApplyJournal(path)
            pending = PendingUserApply(UserGrant("alice", "xray", True), 2, b"fixture-private-data")
            self.assertIsNone(journal.read())
            journal.write(pending)
            self.assertEqual(journal.read(), pending)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("fixture-private-data", repr(pending))
            with self.assertRaises(FileExistsError):
                journal.write(pending)
            raw = path.read_bytes().replace(b'"sha256":"', b'"sha256":"0', 1)
            path.write_bytes(raw)
            with self.assertRaises(ValueError):
                journal.read()
            journal.clear()
            self.assertIsNone(journal.read())

    def test_settings_backend_rolls_back_xray_and_hysteria(self):
        class Adapter:
            def __init__(self, module, root, settings):
                self.module, self.root, self.kind = module, root, type(settings)
                self.live, self.fail_start = True, False
                settings.save(root / "settings.json")

            def settings(self):
                return self.kind.load(self.root / "settings.json")

            def running(self):
                return self.live

            def stop(self):
                self.live = False

            def start(self):
                if self.fail_start:
                    self.fail_start = False
                    raise RuntimeError("учебный отказ")
                self.live = True

            def verify(self):
                if not self.live:
                    raise RuntimeError("служба недоступна")

        initial = (
            ("xray", XraySettings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, "portal.example"),))),
             set_xray_user, lambda value: None),
            ("hysteria", HysteriaSettings(identity("portal.example"), (HysteriaAccount.create("bob"),)),
             set_hysteria_user, render_server),
        )
        for name, settings, transform, validator in initial:
            with self.subTest(module=name), TemporaryDirectory() as folder:
                root = Path(folder)
                adapter = Adapter(name, root, settings)
                if name == "hysteria":
                    validator = lambda value: render_server(value, idle_secret=idle_secret(root, create=True))
                backend = SettingsBackend(name, adapter, transform, validator)
                journal = UserApplyJournal(root / "pending")
                transaction = UserTransaction(journal, backend)
                grant = UserGrant("alice", name, True)
                adapter.fail_start = True
                with self.assertRaisesRegex(TransactionError, "user_apply_rolled_back"):
                    transaction.apply(grant, revision=1)
                self.assertEqual(adapter.settings(), settings)
                self.assertTrue(adapter.running())
                self.assertIsNone(journal.read())
                transaction.apply(grant, revision=2)
                self.assertNotEqual(adapter.settings(), settings)
                self.assertTrue(adapter.running())
                baseline = backend.snapshot()
                journal.write(PendingUserApply(grant, 3, baseline))
                self.assertTrue(transaction.recover_offline())
                self.assertEqual(backend.snapshot(), baseline)
                self.assertFalse(adapter.running())
                self.assertIsNone(journal.read())

                if name == "hysteria":
                    adapter.start()
                    transaction.apply(UserGrant("bob", name, False), revision=4)
                    transaction.apply(UserGrant("alice", name, False), revision=5)
                    self.assertTrue(adapter.running())
                    self.assertFalse(next(item for item in adapter.settings().accounts if item.name == "alice").enabled)
                    self.assertEqual(set(render_server(adapter.settings(), idle_secret=idle_secret(root))
                                         ["auth"]["userpass"]), {"_kvn_no_user"})
    def test_rejects_oversized_snapshot_and_symlink(self):
        with self.assertRaises(ValueError):
            PendingUserApply(UserGrant("alice", "xray", True), 1, b"x" * (MAX_SNAPSHOT + 1))
        with TemporaryDirectory() as folder:
            path = Path(folder) / "pending"
            target = Path(folder) / "target"
            target.write_bytes(b"fixture")
            path.symlink_to(target)
            with self.assertRaises(OSError):
                UserApplyJournal(path).read()

    def test_apply_failure_rolls_back_and_recovery_is_retryable(self):
        class Backend:
            module = "xray"
            value = b"before"
            fail_apply = True
            fail_restore = False

            def snapshot(self):
                return self.value

            def apply_user(self, grant):
                self.value = b"after"
                if self.fail_apply:
                    raise ValueError("приватные сведения backend")

            def verify_user(self, grant):
                assert self.value == b"after"

            def restore(self, value):
                if self.fail_restore:
                    raise ValueError("приватные сведения backend")
                self.value = value

            def verify_snapshot(self, value):
                assert self.value == value

        with TemporaryDirectory() as folder:
            journal = UserApplyJournal(Path(folder) / "pending")
            backend = Backend()
            transaction = UserTransaction(journal, backend)
            grant = UserGrant("alice", "xray", True)
            with self.assertRaisesRegex(TransactionError, "user_apply_rolled_back") as error:
                transaction.apply(grant, revision=1)
            self.assertNotIn("приватные", str(error.exception))
            self.assertEqual(backend.value, b"before")
            self.assertIsNone(journal.read())
            backend.fail_restore = True
            with self.assertRaisesRegex(TransactionError, "user_rollback_unconfirmed"):
                transaction.apply(grant, revision=2)
            self.assertIsNotNone(journal.read())
            with self.assertRaisesRegex(TransactionError, "user_recovery_required"):
                transaction.apply(grant, revision=2)
            backend.fail_restore = False
            self.assertTrue(transaction.recover())
            self.assertEqual(backend.value, b"before")
            backend.fail_apply = False
            transaction.apply(grant, revision=3)
            self.assertEqual(backend.value, b"after")
            self.assertIsNone(journal.read())


class FakeModule:
    def __init__(self, module, *, enabled=True, fail=False):
        self.current = ModuleState(module, True, enabled, GENERATION if enabled else None)
        self.fail = fail
        self.applied = []

    def guard(self):
        return nullcontext()

    def state(self):
        return self.current

    def apply_user(self, user, enabled):
        if self.fail:
            raise RuntimeError("секрет не должен попадать в сообщение")
        self.applied.append((user.id, enabled))

    def subscription_uris(self, user):
        scheme = "vless" if self.current.module == "xray" else "hysteria2"
        return (f"{scheme}://fixture@vpn.example:443#{user.id}",)


class UserControllerTests(unittest.TestCase):
    def test_unhealthy_module_keeps_revocation_intent(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            user = User("alice", "alice")
            store.create(user)
            module = FakeModule("xray")
            controller = UserController(store, {"xray": module})
            rev = controller.change(UserGrant(user.id, "xray", True), revision=1)
            with patch.object(module, "state", side_effect=RuntimeError("закрытая диагностика")):
                with self.assertRaisesRegex(UserApplyError, "user_apply_failed"):
                    controller.change(UserGrant(user.id, "xray", False), revision=rev)
            access = store.get(user.id)[2][0]
            self.assertFalse(access.grant.enabled)
            self.assertTrue(access.error)
            self.assertFalse(access.can_export(user, module.state()))

    def test_concurrent_token_rotation_cannot_keep_stale_confirmation(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            user = User("alice", "alice")
            store.create(user)
            module = FakeModule("xray")
            controller = UserController(store, {"xray": module})
            grant = UserGrant(user.id, "xray", True)
            revision = controller.change(grant, revision=1)

            def fail_during_rotation(*_):
                store.rotate_token(user.id, revision=store.get(user.id)[1])
                raise RuntimeError("операция не подтверждена")

            with patch.object(module, "apply_user", side_effect=fail_during_rotation):
                with self.assertRaisesRegex(UserApplyError, "user_apply_failed"):
                    controller.change(grant, revision=revision)
            self.assertFalse(store.get(user.id)[2][0].can_export(user, module.state()))

    def test_two_modules_and_observable_backend_failure(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            first, second = FakeModule("xray"), FakeModule("hysteria", fail=True)
            controller = UserController(store, {"xray": first, "hysteria": second})
            revision = controller.change(UserGrant("alice", "xray", True), revision=1)
            with self.assertRaisesRegex(UserApplyError, "user_apply_failed") as error:
                controller.change(UserGrant("alice", "hysteria", True), revision=revision)
            self.assertNotIn("секрет", str(error.exception))
            self.assertTrue(error.exception.__suppress_context__)
            user, revision, grants = store.get("alice")
            states = {item.grant.module_id: item for item in grants}
            self.assertTrue(states["xray"].can_export(user, first.state()))
            self.assertEqual(states["hysteria"].status(user, second.state()), "error")
            self.assertEqual(first.applied, [("alice", True)])
            self.assertEqual(second.applied, [])
            second.fail = False
            revision = controller.reconcile("alice", "hysteria", revision=revision)
            user, _, grants = store.get("alice")
            self.assertTrue(grants[0].can_export(user, second.state()))
            controller.change(UserGrant("alice", "xray", False), revision=revision)
            self.assertEqual(first.applied[-1], ("alice", False))

    def test_missing_or_disabled_module_saves_without_apply(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            disabled = FakeModule("xray", enabled=False)
            controller = UserController(store, {"xray": disabled})
            revision = controller.change(UserGrant("alice", "xray", True), revision=1)
            controller.change(UserGrant("alice", "hysteria", True), revision=revision)
            user, _, grants = store.get("alice")
            states = {item.grant.module_id: item for item in grants}
            self.assertEqual(states["xray"].status(user, disabled.state()), "disabled")
            self.assertEqual(states["hysteria"].status(user, ModuleState("hysteria", False, False)), "awaiting_install")
            self.assertEqual(disabled.applied, [])

    def test_changed_generation_never_confirms_old_apply(self):
        class ReplacedModule(FakeModule):
            def apply_user(self, user, enabled):
                super().apply_user(user, enabled)
                self.current = ModuleState("xray", True, True, "b" * 64)

        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            module = ReplacedModule("xray")
            with self.assertRaises(UserApplyError):
                UserController(store, {"xray": module}).change(UserGrant("alice", "xray", True), revision=1)
            user, _, grants = store.get("alice")
            self.assertFalse(grants[0].can_export(user, module.state()))
            self.assertEqual(grants[0].status(user, module.state()), "error")

    def test_disabled_user_never_gets_active_backend_access(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice", enabled=False))
            module = FakeModule("xray")
            UserController(store, {"xray": module}).change(UserGrant("alice", "xray", True), revision=1)
            self.assertEqual(module.applied, [])
            user, _, grants = store.get("alice")
            self.assertFalse(grants[0].can_export(user, module.state()))

    def test_subscription_excludes_unauthorized_and_rotated_tokens(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            store.create(User("bob", "bob"))
            first, second = FakeModule("xray"), FakeModule("hysteria")
            controller = UserController(store, {"xray": first, "hysteria": second})
            revision = controller.change(UserGrant("alice", "xray", True), revision=1)
            revision = controller.change(UserGrant("bob", "hysteria", True), revision=1)
            alice = store.rotate_token("alice", revision=store.get("alice")[1])
            bob = store.rotate_token("bob", revision=revision)
            service = SubscriptionService(store, {"xray": first, "hysteria": second}, nullcontext)
            self.assertEqual(base64.b64decode(service.render(alice)).decode(), "vless://fixture@vpn.example:443#alice\n")
            self.assertEqual(base64.b64decode(service.render(bob)).decode(), "hysteria2://fixture@vpn.example:443#bob\n")
            store.rotate_token("alice", revision=store.get("alice")[1])
            self.assertIsNone(service.render(alice))
            second.current = ModuleState("hysteria", True, True, "b" * 64)
            self.assertEqual(service.render(bob), b"")

    def test_subscription_rejects_untrusted_or_concurrent_export(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            module = FakeModule("xray")
            revision = UserController(store, {"xray": module}).change(UserGrant("alice", "xray", True), revision=1)
            token = store.rotate_token("alice", revision=revision)
            service = SubscriptionService(store, {"xray": module}, nullcontext)
            module.subscription_uris = lambda user: ("vless://id@vpn.example:443\nhysteria2://injected",)
            self.assertIsNone(service.render(token))
            def rotate_during_export(user):
                store.rotate_token(user.id, revision=store.get(user.id)[1])
                return ("vless://id@vpn.example:443",)
            module.subscription_uris = rotate_during_export
            self.assertIsNone(service.render(token))

    def test_telemt_link_is_private_and_not_in_the_happ_subscription(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            module = FakeModule("telemt")
            link = "tg://proxy?server=proxy.example&port=443&secret=ee" + "a" * 32 + b"cover.example".hex()
            module.subscription_uris = lambda user: (link,)
            controller = UserController(store, {"telemt": module})
            revision = controller.change(UserGrant("alice", "telemt", True), revision=1)
            token = store.rotate_token("alice", revision=revision)
            service = SubscriptionService(store, {"telemt": module}, nullcontext)
            self.assertEqual(service.profiles("alice"), (link,))
            self.assertEqual(service.render(token), b"")
            controller.change(UserGrant("alice", "telemt", False), revision=store.get("alice")[1])
            self.assertEqual(service.profiles("alice"), ())

    def test_subscription_uses_real_xray_and_hysteria_exporters(self):
        with TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / "users")
            store.create(User("alice", "alice"))
            xray, hy = FakeModule("xray"), FakeModule("hysteria")
            xs = set_xray_user(XraySettings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, "portal.example"),))),
                               "alice", True)
            hs = set_hysteria_user(HysteriaSettings(identity("portal.example")), "alice", True)
            account_id = xs.accounts[0].id
            xray.subscription_uris = lambda user: tuple(p.uri() for p in xray_profiles(
                xs, account_id, "portal.example", None, active=True))
            hy.subscription_uris = lambda user: (hysteria_profile(hs, user.id, active=True).uri(),)
            self.assertEqual(xray_user_uris(xs, "alice", "portal.example", None),
                             tuple(p.uri() for p in xray_profiles(xs, account_id, "portal.example", None, active=True)))
            self.assertEqual(hysteria_user_uris(hs, "alice"), (hysteria_profile(hs, "alice", active=True).uri(),))
            self.assertEqual(xray_user_uris(xs, "bob", "portal.example", None), ())
            self.assertEqual(hysteria_user_uris(hs, "bob"), ())
            controller = UserController(store, {"xray": xray, "hysteria": hy})
            revision = controller.change(UserGrant("alice", "xray", True), revision=1)
            revision = controller.change(UserGrant("alice", "hysteria", True), revision=revision)
            token = store.rotate_token("alice", revision=revision)
            subscription = SubscriptionService(store, {"xray": xray, "hysteria": hy}, nullcontext)
            result = base64.b64decode(subscription.render(token)).decode().splitlines()
            self.assertEqual(len(result), 2)
            self.assertTrue(result[0].startswith("hysteria2://"))
            self.assertTrue(result[1].startswith("vless://"))
            controller.change(UserGrant("alice", "xray", False), revision=store.get("alice")[1])
            result = base64.b64decode(subscription.render(token)).decode().splitlines()
            self.assertEqual(len(result), 1)
            self.assertTrue(result[0].startswith("hysteria2://"))

    def test_real_module_settings_integrate_with_guard_and_recovery(self):
        class Packages:
            def runtime_guard(self):
                return nullcontext()

            def require_network_idle(self, *, allow_user_recovery=False):
                return None

            def installed(self):
                return ({"module": "xray", "enabled": True}, {"module": "hysteria", "enabled": True})

            def require_user_idle(self):
                return None

        class Adapter:
            def __init__(self, module, root, settings):
                self.module, self.root, self.kind = module, root, type(settings)
                self.live = True
                settings.save(root / "settings.json")

            def settings(self):
                return self.kind.load(self.root / "settings.json")

            def running(self):
                return self.live

            def stop(self):
                self.live = False

            def start(self):
                self.live = True

            def verify(self):
                if not self.live:
                    raise RuntimeError("служба недоступна")

        with TemporaryDirectory() as folder:
            root = Path(folder)
            store = UserStore(root / "users")
            store.create(User("alice", "alice"))
            packages, modules = Packages(), {}
            specs = (("xray", XraySettings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, "portal.example"),))),
                      set_xray_user),
                     ("hysteria", HysteriaSettings(identity("portal.example"), (HysteriaAccount.create("bob"),)),
                      set_hysteria_user))
            for name, settings, transform in specs:
                path = root / name
                path.mkdir(mode=0o700)
                adapter = Adapter(name, path, settings)
                backend = SettingsBackend(name, adapter, transform, lambda value: None)
                modules[name] = SettingsUserModule(store, packages, backend, UserApplyJournal(path / "pending"),
                                                   lambda user, data: ())
                store.confirm_module(name)
            controller = UserController(store, modules)
            revision = controller.change(UserGrant("alice", "xray", True), revision=1)
            revision = controller.change(UserGrant("alice", "hysteria", True), revision=revision)
            user, _, grants = store.get("alice")
            self.assertTrue(all(item.can_export(user, modules[item.grant.module_id].state()) for item in grants))
            target = modules["xray"]
            original = target.backend.snapshot()
            target.journal.write(PendingUserApply(UserGrant("alice", "xray", False), revision, original))
            with self.assertRaisesRegex(UserApplyError, "user_recovery_required"):
                target.state()
            self.assertTrue(target.recover())
            user, _, grants = store.get("alice")
            xray_grant = next(item for item in grants if item.grant.module_id == "xray")
            self.assertEqual(xray_grant.status(user, target.state()), "pending")
            hy_grant = next(item for item in grants if item.grant.module_id == "hysteria")
            self.assertTrue(hy_grant.can_export(user, modules["hysteria"].state()))
            target.journal.write(PendingUserApply(UserGrant("alice", "xray", False), revision, original))
            UserRecovery(packages, store, modules).recover_offline_locked()
            self.assertFalse(target.backend.adapter.running())
            self.assertIsNone(store.module_generation("xray"))
            self.assertIsNone(target.journal.read())
            self.assertTrue(modules["hysteria"].backend.adapter.running())
            revision = store.get("alice")[1]
            store.set_grant(UserGrant("alice", "xray", False), revision=revision)
            projected = UserRecovery(packages, store, modules).project_locked("xray")
            self.assertEqual(projected, (("alice", False),))
            self.assertFalse(target.backend.adapter.settings().accounts[0].grants)
            target.backend.adapter.start()
            target.backend.adapter.verify()
            store.confirm_module("xray", policy=projected)
            user, _, grants = store.get("alice")
            self.assertEqual(next(grant for grant in grants if grant.grant.module_id == "xray")
                             .status(user, target.state()), "revoked")


class UsersPortalTests(unittest.TestCase):
    def test_card_export_rotation_and_backend_failure_through_unix_rpc(self):
        origin = "https://localhost"
        with TemporaryDirectory() as folder, socket.socket(socket.AF_UNIX) as listener:
            path = Path(folder) / "users.sock"
            store = UserStore(Path(folder) / "state")
            xray, hy = FakeModule("xray"), FakeModule("hysteria", fail=True)
            modules = {"xray": xray, "hysteria": hy}
            inventory = SimpleNamespace(runtime_guard=nullcontext, require_network_idle=lambda: None,
                                        installed=lambda: tuple({"module": key, "enabled": mod.current.enabled}
                                                                for key, mod in modules.items()))
            runtime = SimpleNamespace(inventory=inventory, user_modules=modules)
            agent = Application(os.geteuid(), users_factory=lambda: UsersApplication(store, lambda: runtime))
            listener.bind(str(path))
            listener.listen(2)
            listener.settimeout(0.1)
            stop = Event()

            def serve():
                while not stop.is_set():
                    try:
                        connection, _ = listener.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        agent.handle(connection)

            worker = Thread(target=serve, daemon=True)
            worker.start()
            self.addCleanup(worker.join, 2)
            self.addCleanup(stop.set)
            app = create_app({"session_key": "fixture-only", "allowed_hosts": ["localhost"]}, client=object(),
                             users_client=UsersClient(path))
            browser, guest = app.test_client(), app.test_client()
            self.assertEqual(guest.get("/users", base_url=origin).status_code, 303)
            with browser.session_transaction(base_url=origin) as session:
                session.update(admin=True, csrf="fixture-csrf")

            def post(route, **fields):
                return browser.post(route, base_url=origin, headers={"Origin": origin},
                                    data={"csrf": "fixture-csrf", **fields})

            self.assertEqual(post("/users", name="alice", csrf="wrong").status_code, 403)
            created = post("/users", name="alice")
            self.assertEqual(created.status_code, 303)
            card = created.location
            uid = card.rsplit("/", 1)[-1]
            self.assertEqual(post("/users", name="alice").location, "/users")
            self.assertEqual(len(store.list_users()), 1)

            def action(name, **fields):
                return post(card + "/" + name, revision=store.get(uid)[1], **fields)

            self.assertEqual(action("grant", module="wireguard", enabled="yes").status_code, 303)
            self.assertIn("Ожидает установки".encode(), browser.get(card, base_url=origin).data)
            conf = card + "/files/wireguard.conf"
            self.assertEqual(browser.get(conf, base_url=origin).status_code, 404)
            self.assertEqual(guest.get(conf, base_url=origin).status_code, 303)
            wg = FakeModule("wireguard")
            wg.client_config = lambda user: b"[Interface]\nPrivateKey = synthetic-profile-secret\n"
            modules["wireguard"] = wg
            self.assertEqual(action("retry", module="wireguard").status_code, 303)
            exported = browser.get(conf, base_url=origin)
            self.assertEqual(exported.status_code, 200)
            self.assertIn(b"synthetic-profile-secret", exported.data)
            self.assertEqual(exported.headers["Content-Disposition"], 'attachment; filename="wireguard.conf"')
            self.assertEqual(exported.headers["Cache-Control"], "no-store")
            self.assertNotIn(b"synthetic-profile-secret", browser.get(card, base_url=origin).data)
            self.assertEqual(action("grant", module="xray", enabled="yes").status_code, 303)
            self.assertEqual(action("grant", module="hysteria", enabled="yes").status_code, 303)
            page = browser.get(card, base_url=origin).data
            self.assertIn("Не подтверждено".encode(), page)
            self.assertNotIn("секрет не должен".encode(), page)
            hy.fail = False
            self.assertEqual(action("retry", module="hysteria").status_code, 303)
            rotated = action("rotate")
            self.assertEqual(rotated.status_code, 200)
            token = re.search(rb"/sub/([A-Za-z0-9_-]{43})", rotated.data)[1].decode()
            path_sub = f"/sub/{token}"
            subscription = guest.get(path_sub, base_url=origin)
            self.assertEqual(subscription.status_code, 200)
            self.assertEqual(subscription.headers["Cache-Control"], "no-store")
            lines = base64.b64decode(subscription.data).splitlines()
            self.assertEqual(tuple(line.split(b":", 1)[0] for line in lines), (b"hysteria2", b"vless"))
            self.assertEqual(guest.get("/sub/" + "x" * 43, base_url=origin).status_code, 404)
            self.assertEqual(guest.get(card + "/profiles.txt", base_url=origin).status_code, 303)
            self.assertEqual(browser.get(card + "/profiles.txt", base_url=origin).data.splitlines(), lines)
            png = b"\x89PNG\r\n\x1a\nfixture"
            with patch("v5.portal.user_routes.subprocess.run", return_value=SimpleNamespace(stdout=png)) as qr:
                response = browser.get(card + "/qr/0", base_url=origin)
                self.assertEqual(response.data, png)
                self.assertEqual(qr.call_args.kwargs["input"], lines[0])
                self.assertNotIn(lines[0].decode(), qr.call_args.args[0])
            xray.current = ModuleState("xray", True, False)
            self.assertIn("Модуль выключен".encode(), browser.get(card, base_url=origin).data)
            self.assertEqual(base64.b64decode(guest.get(path_sub, base_url=origin).data).splitlines(), lines[:1])
            self.assertEqual(action("grant", module="hysteria", enabled="no").status_code, 303)
            self.assertEqual(guest.get(path_sub, base_url=origin).data, b"")
            self.assertEqual(action("revoke").status_code, 303)
            self.assertEqual(guest.get(path_sub, base_url=origin).status_code, 404)
            self.assertEqual(action("grant", module="wireguard", enabled="no").status_code, 303)
            self.assertEqual(browser.get(conf, base_url=origin).status_code, 404)
            stop.set()
            worker.join(2)


if __name__ == "__main__":
    unittest.main()
