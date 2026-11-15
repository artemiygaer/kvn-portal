"""Сетевой план проверяется до apply; живые сетевые пробы выполняются отдельно."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests.v5.test_packages import new_key
from v5.core.lifecycle.assembly import reconcile_boot
from v5.core.lifecycle.controller import Lifecycle, LifecycleError
from v5.core.lifecycle.journal import IntentJournal, PENDING_NAME
from v5.core.network.nft import TABLE, Nftables, compile_nft
from v5.core.network.plan import Binding, ModuleNetwork, NetworkConflict, Publication, Route, build_plan
from v5.core.network.runtime import check_binding
from v5.core.network.stream import render_stream
from v5.core.packages.manifest import PackageError
from v5.core.packages.registry import PackageRegistry
from v5.packaging.build_module import build


def route(name, port=12443, *, self_steal=False):
    return Route(name, Binding("tcp", "127.0.0.1", port), self_steal)


class NetworkPlanTests(unittest.TestCase):
    def test_disabled_module_does_not_contribute_any_network_resource(self):
        xray = ModuleNetwork("xray", False, (route("xray.example"),),
                             (Publication(Binding("tcp", "0.0.0.0", 2443)),))
        wg = ModuleNetwork("wireguard", False, publications=(
            Publication(Binding("udp", "0.0.0.0", 51821)), Publication(Binding("udp", "::", 51821)),
        ))
        result = build_plan((xray, wg), site_names=("portal.example",))
        self.assertEqual((result.active, result.routes, result.publications), ((), (), ()))

    def test_core_ports_and_address_families_do_not_collide_with_443_udp(self):
        for core in (80, 443, 8443, 10443):
            for address in ("0.0.0.0", "::"):
                service = ModuleNetwork("xray", True, publications=(Publication(Binding("tcp", address, core)),))
                with self.subTest(core=core, address=address), self.assertRaisesRegex(NetworkConflict, "^core_port_conflict$"):
                    build_plan((service,))
        v4 = Binding("udp", "0.0.0.0", 443)
        v6 = Binding("udp", "::", 443)
        hy2 = ModuleNetwork("hysteria", True, publications=(Publication(v4), Publication(v6)))
        result = build_plan((hy2,))
        self.assertEqual(tuple(item.publication.public for item in result.publications), (v4, v6))
        self.assertFalse(v4.overlaps(v6))
        self.assertTrue(v4.overlaps(Binding("udp", "192.0.2.9", 443)))
        with self.assertRaisesRegex(NetworkConflict, "^unmanaged_port_conflict$"):
            build_plan((hy2,), occupied=(Binding("udp", "192.0.2.9", 443),))
        for ip in ("fe80::1%eth0", "::ffff:192.0.2.9", "224.0.0.1", "invalid"):
            with self.subTest(ip=ip), self.assertRaisesRegex(NetworkConflict, "^invalid_binding_address$"):
                Binding("tcp", ip, 2443)

    def test_sni_exclusivity_and_explicit_own_site_route(self):
        xray = ModuleNetwork("xray", True, (route("Portal.Example.", self_steal=True),))
        mtg = ModuleNetwork("mtg", True, (route("tg.example", 13128),))
        result = build_plan((mtg, xray), site_names=("portal.example",))
        self.assertEqual(tuple(item.route.sni for item in result.routes), ("portal.example", "tg.example"))
        self.assertEqual(tuple(item.owner for item in result.routes), ("xray", "mtg"))
        self.assertEqual(build_plan((xray, mtg), site_names=("portal.example",)), result)
        self.assertEqual(build_plan((ModuleNetwork("xray"), mtg), site_names=("portal.example",)).routes,
                         (result.routes[1],))
        with self.assertRaisesRegex(NetworkConflict, "^sni_conflict$"):
            build_plan((xray, ModuleNetwork("mtg", True, (route("portal.example", 13128),))),
                       site_names=("portal.example",))
        with self.assertRaisesRegex(NetworkConflict, "^sni_conflict$"):
            build_plan((ModuleNetwork("xray", True, (route("portal.example"),)),), site_names=("portal.example",))
        with self.assertRaisesRegex(NetworkConflict, "^invalid_self_steal$"):
            build_plan((xray,), site_names=("other.example",))
        with self.assertRaisesRegex(NetworkConflict, "^invalid_sni$"):
            route("bad.example; return 403")
        with self.assertRaisesRegex(NetworkConflict, "^backend_port_conflict$"):
            build_plan((ModuleNetwork("xray", True, (route("one.example"),)),
                        ModuleNetwork("mtg", True, (route("two.example"),))))

    def test_shared_publication_remains_only_until_last_owner(self):
        public = Binding("tcp", "0.0.0.0", 2443)
        target = Binding("tcp", "192.0.2.9", 12443)
        shared = Publication(public, target, shared=True)
        one = ModuleNetwork("xray", True, publications=(shared,))
        two = ModuleNetwork("telemt", True, publications=(shared,))
        self.assertEqual(build_plan((one, two)).publications[0].owners, ("telemt", "xray"))
        self.assertEqual(build_plan((ModuleNetwork("xray"), two)).publications[0].owners, ("telemt",))
        self.assertEqual(build_plan((ModuleNetwork("xray"), ModuleNetwork("telemt"))).publications, ())
        conflicting = ModuleNetwork("telemt", True, publications=(
            Publication(Binding("tcp", "192.0.2.9", 2443)),))
        with self.assertRaisesRegex(NetworkConflict, "^publication_conflict$"):
            build_plan((one, conflicting))
        also_public = ModuleNetwork("telemt", True, publications=(Publication(target),))
        with self.assertRaisesRegex(NetworkConflict, "^backend_publication_conflict$"):
            build_plan((one, also_public))

    def test_stream_routes_disappear_without_removing_site_fallback(self):
        name = ("a" * 59 + ".") * 4 + "example"
        xray = ModuleNetwork("xray", True, (route(name),))
        mtg = ModuleNetwork("mtg", True, (Route("tg.example", Binding("tcp", "::1", 13128)),))
        both = render_stream(build_plan((xray, mtg)), ipv6=True)
        one = render_stream(build_plan((ModuleNetwork("xray"), mtg)), ipv6=True)
        self.assertIn("map_hash_bucket_size 512;", both)
        self.assertIn(f'"{name}" 127.0.0.1:12443;', both)
        self.assertNotIn(name, one)
        self.assertIn('"tg.example" [::1]:13128;', one)
        self.assertIn("default 127.0.0.1:10443;", one)
        self.assertIn("~: [::1]:10443;", one)
        self.assertNotIn("listen [::]", render_stream(build_plan((xray,)), ipv6=False))
        self.assertEqual(render_stream(build_plan((ModuleNetwork("mtg"),)), ipv6=True), "")

    def test_nft_batches_target_only_own_table_and_guard_private_ports(self):
        plan = build_plan((ModuleNetwork("hysteria", True, publications=(
            Publication(Binding("udp", "0.0.0.0", 443), Binding("udp", "192.0.2.8", 11443)),
            Publication(Binding("udp", "::", 443), Binding("udp", "fd42::8", 11443)),
        )),))
        compiled = compile_nft(plan)
        batch = compiled.batch(42).decode()
        self.assertTrue(batch.startswith(f'delete table inet handle 42\ncreate table inet {TABLE}'))
        self.assertIn('iifname != "lo" meta nfproto ipv4 fib daddr type local', batch)
        self.assertIn("dnat ip to 192.0.2.8:11443", batch)
        self.assertIn("dnat ip6 to [fd42::8]:11443", batch)
        self.assertIn("ct status dnat ct original proto-dst 443 return", batch)
        self.assertIn("udp dport 11443 drop", batch)
        self.assertNotIn("flush ruleset", batch)
        self.assertEqual(compiled.rule_count, 6)
        self.assertEqual(compile_nft(build_plan(())).batch(42), b"delete table inet handle 42\n")
        self.assertEqual(compile_nft(build_plan(())).batch(None), b"")
        with self.assertRaisesRegex(NetworkConflict, "^invalid_nft_handle$"):
            compiled.batch(0)

    def test_legacy_nft_json_uses_only_matching_top_level_text_comment(self):
        inventory = Nftables()
        table = {"family": "inet", "name": TABLE, "handle": 17}
        marker = "kvn-v5:ingress:" + "a" * 64
        head = f'table inet {TABLE} {{ # handle 17\n'
        comment = f'\tcomment "{marker}"\n'
        rows = ([{"table": table}], [{"table": table}, {"rule": {}}])
        with (patch.object(inventory, "_document", side_effect=rows),
              patch.object(inventory, "_call", return_value=(head + comment + "}\n").encode()) as call):
            snapshot = inventory._snapshot(required=True)
        self.assertEqual((snapshot.handle, snapshot.comment, snapshot.rules), (17, marker, 1))
        call.assert_called_once_with("-a", "list", "table", "inet", TABLE)
        for text in (head.replace("17", "18") + comment, head + "\tchain forward {\n" + comment,
                     head + '\tcomment "another-owner"\n'):
            with (patch.object(inventory, "_document", side_effect=rows),
                  patch.object(inventory, "_call", return_value=text.encode()),
                  self.assertRaisesRegex(NetworkConflict, "^unmanaged_nft_table$")):
                inventory._snapshot(required=True)
        invalid = ([{"table": table}], [{"table": table | {"comment": "invalid"}}])
        with (patch.object(inventory, "_document", side_effect=invalid),
              patch.object(inventory, "_call") as call,
              self.assertRaisesRegex(NetworkConflict, "^unmanaged_nft_table$")):
            inventory._snapshot(required=True)
        call.assert_not_called()

    def test_preflight_bind_probe_refuses_real_occupied_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            candidate = Binding("tcp", "0.0.0.0", listener.getsockname()[1])
            with self.assertRaisesRegex(NetworkConflict, "^publication_port_unavailable$"):
                check_binding(candidate)
        check_binding(candidate)

    def test_empty_boot_does_not_create_package_store_or_require_dependencies(self):
        with tempfile.TemporaryDirectory() as root:
            packages = Path(root) / "packages"
            with patch("v5.core.lifecycle.assembly.host_gateway",
                       return_value=SimpleNamespace(network_routes=lambda: build_plan(()))), patch(
                "v5.core.lifecycle.assembly.build_lifecycle", side_effect=AssertionError("Не должно запускаться")
            ):
                reconcile_boot(root=packages)
            self.assertFalse(packages.exists())


class FakeAdapter:
    def __init__(self, name, events):
        self.name, self.events, self.live = name, events, False

    def network(self):
        return ModuleNetwork(self.name, routes=(route("vpn.example"),))

    def running(self):
        return self.live

    def start(self):
        self.live = True
        self.events.append("start:" + self.name)

    def stop(self):
        self.live = False
        self.events.append("stop:" + self.name)

    def verify(self):
        assert self.live


class FakeIngress:
    def __init__(self, events):
        self.events = events
        self.fail_once = False
        self.fail_always = False
        self.plan = build_plan(())

    def preflight(self, plan, previous):
        assert previous == self.plan
        self.events.append("preflight")

    def apply(self, plan, *, reconcile=False):
        self.plan = plan
        self.events.append("publish:" + ",".join(plan.active))
        if self.fail_once or self.fail_always:
            self.fail_once = False
            raise OSError("Учебный отказ после публикации")

    def verify(self, plan):
        assert self.plan == plan
        self.events.append("verify")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.key = root / "fixture.pem"
        publisher = new_key(self.key)
        self.inventory = PackageRegistry(root / "packages", publisher)
        self.now = datetime.now(timezone.utc)
        self.package = root / "fixture.tar.gz"
        self.inventory.install(self._prepare("1.0.0"), now=self.now)
        self.journal = IntentJournal(self.inventory.root / PENDING_NAME)
        self.events = []
        self.adapter = FakeAdapter("xray", self.events)
        self.ingress = FakeIngress(self.events)
        self.lifecycle = Lifecycle(self.inventory, {"xray": self.adapter}, self.ingress, self.journal,
                                   site_names=("portal.example",))
        self.settings = root / "fixture-settings"
        self.settings.write_bytes(b"fixture")

    def _prepare(self, version):
        build(self.package, self.key, module_id="xray", version=version, image_digest="3" * 64,
              issued_at=self.now.strftime("%Y-%m-%dT%H:%M:%SZ"),
              expires_at=(self.now + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), now=self.now)
        with self.package.open("rb") as handle:
            return self.inventory.prepare(handle, now=self.now).ticket

    def test_commit_order_and_disabled_update_do_not_restore_ports(self):
        self.lifecycle.change("xray", True)
        self.assertEqual(self.events, ["preflight", "start:xray", "publish:xray", "verify"])
        self.assertEqual(self.inventory.installed()[0]["enabled"], 1)
        self.events.clear()
        self.lifecycle.change("xray", False)
        self.assertEqual(self.events, ["preflight", "publish:", "stop:xray", "verify"])
        self.inventory.install(self._prepare("1.0.1"), now=self.now)
        self.assertEqual(self.lifecycle.reconcile().active, ())
        self.assertFalse(self.adapter.running())
        self.assertIsNone(self.journal.read())
        self.lifecycle.change("xray", True)
        self.assertEqual(self.settings.read_bytes(), b"fixture")

    def test_plan_reports_only_declarations_without_running_or_binding(self):
        from v5.core.contracts import CORE_API_VERSION
        from v5.core.lifecycle.rpc import Application

        app = Application(0, factory=lambda: self.lifecycle)
        request = {"version": CORE_API_VERSION, "method": "lifecycle.plan", "params": {"module": "xray"}}
        self.assertEqual(app.dispatch(request), {"module": "xray", "sni": ["vpn.example"], "ports": []})
        self.assertEqual(self.events, [])
        self.assertEqual(self.inventory.installed()[0]["enabled"], 0)
        self.assertIsNone(self.journal.read())
        self.journal.write(frozenset(), frozenset({"xray"}))
        with self.assertRaisesRegex(LifecycleError, "module_reconcile_required"):
            app.dispatch(request)
        self.assertEqual(self.events, [])
        self.assertEqual(self.journal.read(), (frozenset(), frozenset({"xray"})))

    def test_module_epoch_rotates_after_verified_transitions(self):
        from v5.core.users.store import UserStore

        epochs = UserStore(self.inventory.root.parent / "user-fixture")
        self.lifecycle.epochs = epochs
        other = epochs.confirm_module("mtg")
        self.assertIsNone(epochs.module_generation("xray"))
        self.lifecycle.change("xray", True)
        first = epochs.module_generation("xray")
        self.assertIsNotNone(first)
        self.lifecycle.change("xray", False)
        self.assertIsNone(epochs.module_generation("xray"))
        self.assertEqual(epochs.module_generation("mtg"), other)
        self.lifecycle.change("xray", True)
        second = epochs.module_generation("xray")
        self.assertNotEqual(first, second)
        self.lifecycle.reconcile()
        self.assertNotEqual(second, epochs.module_generation("xray"))

    def test_failed_enable_cannot_leave_confirmed_epoch(self):
        from v5.core.contracts import UserGrant
        from v5.core.users.model import ModuleState, User
        from v5.core.users.store import UserStore

        epochs = UserStore(self.inventory.root.parent / "user-fixture")
        self.lifecycle.epochs = epochs
        user = User("alice", "alice")
        epochs.create(user)
        epochs.set_grant(UserGrant(user.id, "xray", True), revision=1)

        class Projection:
            @staticmethod
            def project_locked(module):
                return epochs.module_policy(module)

        self.lifecycle.user_recovery = Projection()
        self.ingress.fail_once = True
        with self.assertRaisesRegex(LifecycleError, "network_apply_rolled_back"):
            self.lifecycle.change("xray", True)
        self.assertIsNone(epochs.module_generation("xray"))
        self.assertFalse(epochs.get(user.id)[2][0].applied)
        self.lifecycle.change("xray", True)
        generation = epochs.module_generation("xray")
        self.assertTrue(epochs.get(user.id)[2][0].can_export(user, ModuleState("xray", True, True, generation)))

    def test_pending_user_journal_blocks_lifecycle_and_package_changes(self):
        path = self.inventory.root.parent / "modules" / "xray" / "users.pending.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"fixture")
        for operation in (lambda: self.lifecycle.change("xray", True), self.lifecycle.reconcile,
                          self.inventory.require_network_idle):
            with self.assertRaisesRegex(PackageError, "user_recovery_required"):
                operation()
        self.assertEqual(self.events, [])
        self.inventory.require_network_idle(allow_user_recovery=True)

    def test_boot_recovery_precedes_network_reconcile(self):
        path = self.inventory.root.parent / "modules" / "xray" / "users.pending.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"fixture")
        events = self.events

        class Recovery:
            def recover_offline_locked(self):
                events.append("restore-user-settings")
                path.unlink()

        self.lifecycle.user_recovery = Recovery()
        self.assertEqual(self.lifecycle.reconcile().active, ())
        self.assertEqual(events[0], "restore-user-settings")
        self.assertFalse(self.adapter.running())
        self.assertFalse(path.exists())

    def test_assembly_wires_private_user_recovery(self):
        from unittest.mock import patch
        from v5.core.lifecycle.assembly import build_lifecycle

        gateway = SimpleNamespace(site_names=("portal.example",), ipv6=False)
        with patch("v5.core.lifecycle.assembly.host_gateway", return_value=gateway), \
                patch("v5.core.lifecycle.assembly.load_publisher", return_value=self.inventory.publisher), \
                patch("v5.core.lifecycle.assembly.NetworkRuntime"):
            lifecycle = build_lifecycle(root=self.inventory.root)
        self.assertEqual(lifecycle.user_store.root, self.inventory.root.parent / "users")
        self.assertIs(lifecycle.epochs, lifecycle.user_store)
        self.assertEqual(set(lifecycle.user_modules), {"xray", "hysteria", "amneziawg", "wireguard", "telemt"})
        self.assertIsNotNone(lifecycle.user_recovery)

    def test_failure_and_interrupted_operation_restore_committed_state(self):
        self.ingress.fail_once = True
        with self.assertRaisesRegex(LifecycleError, "^network_apply_rolled_back$"):
            self.lifecycle.change("xray", True)
        self.assertEqual(self.inventory.installed()[0]["enabled"], 0)
        self.assertFalse(self.adapter.running())
        self.assertIsNone(self.journal.read())
        # Сбой процесса до фиксации в SQLite: применённое состояние не считается подтверждённым.
        empty, active = frozenset(), frozenset({"xray"})
        self.journal.write(empty, active)
        self.adapter.start()
        self.ingress.apply(build_plan((ModuleNetwork("xray", True, (route("vpn.example"),)),)))
        with self.assertRaisesRegex(PackageError, "^module_reconcile_required$"):
            self.inventory.remove("xray")
        self.assertEqual(self.lifecycle.reconcile().active, ())
        self.assertIsNone(self.journal.read())
        self.assertFalse(self.adapter.running())
        # Сбой после COMMIT, до очистки журнала: подтверждённое включение сохраняется.
        self.journal.write(empty, active)
        with self.inventory.runtime_guard():
            self.inventory.commit_enabled(empty, active)
        self.assertEqual(self.lifecycle.reconcile().active, ("xray",))
        self.assertTrue(self.adapter.running())
        self.assertIsNone(self.journal.read())

    def test_failed_gateway_recovery_still_closes_uncommitted_direct_listeners(self):
        self.ingress.fail_always = True
        with self.assertRaisesRegex(LifecycleError, "^network_rollback_unconfirmed$"):
            self.lifecycle.change("xray", True)
        self.assertFalse(self.adapter.running())
        self.assertEqual(self.inventory.installed()[0]["enabled"], 0)
        self.assertIsNotNone(self.journal.read())
        self.ingress.fail_always = False
        self.assertEqual(self.lifecycle.reconcile().active, ())
        self.assertIsNone(self.journal.read())

    def test_failed_and_interrupted_active_upgrade_preserve_committed_version(self):
        self.lifecycle.change('xray', True)
        old_verify = self.adapter.verify

        def health():
            old_verify()
            if self.inventory.installed()[0]['version'] == '1.0.1':
                raise OSError('Учебный отказ новой версии')

        self.adapter.verify = health
        with self.assertRaisesRegex(LifecycleError, '^module_upgrade_rolled_back$'):
            self.lifecycle.upgrade('xray', self._prepare('1.0.1'))
        self.assertEqual(self.inventory.installed()[0]['version'], '1.0.0')
        self.assertTrue(self.adapter.running())
        self.assertIsNone(self.inventory.pending_upgrade())

        with self.inventory.runtime_guard():
            pending = self.inventory.begin_upgrade('xray', self._prepare('1.0.2'))
            self.inventory.select_upgrade(pending)
        self.assertEqual(self.inventory.installed()[0]['version'], '1.0.2')
        visible = self.inventory.public_status()[0]
        self.assertEqual(visible['version'], '1.0.0')
        self.assertTrue(visible['updating'])
        self.assertEqual(self.lifecycle.reconcile().active, ('xray',))
        self.assertEqual(self.inventory.installed()[0]['version'], '1.0.0')
        self.assertIsNone(self.inventory.pending_upgrade())

        self.lifecycle.upgrade('xray', self._prepare('1.0.3'))
        row = self.inventory.installed()[0]
        self.assertTrue(row['previous'] and row['enabled'])
        self.assertEqual(row['version'], '1.0.3')
        self.assertEqual(self.settings.read_bytes(), b'fixture')

    def test_image_preparation_failure_leaves_running_module_untouched(self):
        self.lifecycle.change('xray', True)
        self.events.clear()

        def prepare(manifest, archive):
            self.assertTrue(self.adapter.running())
            self.assertEqual(manifest.version, '1.0.1')
            self.assertTrue(archive.is_dir())
            self.assertEqual(self.inventory.installed()[0]['version'], '1.0.0')
            raise PackageError('docker_pull_failed')

        self.adapter.prepare_upgrade = prepare
        with self.assertRaisesRegex(PackageError, '^docker_pull_failed$'):
            self.lifecycle.upgrade('xray', self._prepare('1.0.1'))
        self.assertEqual(self.events, [])
        self.assertTrue(self.adapter.running())
        self.assertEqual(self.inventory.installed()[0]['version'], '1.0.0')
        self.assertIsNone(self.inventory.pending_upgrade())

    def test_adapter_preflight_failure_does_not_change_ingress(self):
        def missing():
            raise LifecycleError('wireguard_kernel_missing')

        self.adapter.preflight = missing
        with self.assertRaisesRegex(LifecycleError, '^wireguard_kernel_missing$'):
            self.lifecycle.change('xray', True)
        self.assertEqual(self.events, [])
        self.assertIsNone(self.journal.read())
        self.assertFalse(self.inventory.installed()[0]['enabled'])
