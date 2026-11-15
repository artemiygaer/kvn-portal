"""Контракт двух модулей; сетевой FakeTLS-прогон выполняется отдельно."""

from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from io import BytesIO
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import tomllib
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from tests.v5.test_packages import EXPIRES, ISSUED, NOW, new_key
from v5.core.network.plan import Binding, NetworkConflict, SITE_BACKEND_PORT, build_plan
from v5.core.packages.manifest import PackageError
from v5.core.packages.registry import PackageRegistry
from v5.modules.mtg import settings as mtg
from v5.modules.mtproto_common.profiles import CoverTarget, Exposure, Secret
from v5.modules.mtproto_common.adapter import MTProtoAdapter
from v5.modules.mtproto_common.runtime import Runtime, cover_target, inspect_container, listening
from v5.modules.telemt import settings as telemt
from v5.packaging.build_module import build


class MTProtoTests(unittest.TestCase):
    def setUp(self):
        self.public = Exposure("Cover.Example.", direct_ip="0.0.0.0")
        self.own = Exposure("portal.example", own_site=True, direct_ip="0.0.0.0")
        self.on = telemt.Account("reader", Secret("a" * 32))
        self.off = telemt.Account("off", Secret("b" * 32), enabled=False)
        self.telemt = telemt.Settings(self.public, (self.on, self.off))
        self.mtg = mtg.Settings(self.own, Secret("c" * 32))

    def test_initial_configuration_does_not_overwrite_existing_secrets(self):
        with TemporaryDirectory() as directory:
            for module, settings, settings_type in (('telemt', self.telemt, telemt.Settings),
                                                     ('mtg', self.mtg, mtg.Settings)):
                packages = Mock()
                packages.runtime_guard.return_value = nullcontext()
                packages.installed.return_value = [{'module': module, 'enabled': False}]
                context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(site_names=('portal.example',)))
                adapter = MTProtoAdapter(context, module, settings_type, Mock(), root=Path(directory) / module,
                                         docker=Mock())
                with self.subTest(module=module), patch.object(adapter, 'running', return_value=False):
                    adapter.configure(settings, initial=True, validate=lambda _network: None)
                    path = Path(directory) / module / 'settings.json'
                    before = path.read_bytes()
                    with self.assertRaisesRegex(PackageError, 'mtproto_already_configured'):
                        adapter.configure(settings, initial=True)
                    self.assertEqual(path.read_bytes(), before)

    def test_exposure_changes_preserve_secrets_and_reject_stale_or_running(self):
        with TemporaryDirectory() as directory:
            for module, settings, settings_type in (('telemt', self.telemt, telemt.Settings),
                                                     ('mtg', self.mtg, mtg.Settings)):
                packages = Mock()
                packages.runtime_guard.return_value = nullcontext()
                packages.installed.return_value = [{'module': module, 'enabled': False}]
                context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(site_names=('portal.example',)))
                adapter = MTProtoAdapter(context, module, settings_type, Mock(), root=Path(directory) / module,
                                         docker=Mock())
                with self.subTest(module=module), patch.object(adapter, 'running', return_value=False):
                    self.assertIsNone(adapter.exposure_view())
                    adapter.configure(settings, initial=True)
                    view = adapter.exposure_view()
                    for secret in ('a' * 32, 'b' * 32, 'c' * 32):
                        self.assertNotIn(secret, repr(view))
                    new = Exposure('new.example', direct_ip='0.0.0.0')
                    before = (adapter.root / 'settings.json').read_bytes()
                    def reject_network(_network):
                        raise NetworkConflict('sni_conflict')
                    with self.assertRaises(NetworkConflict):
                        adapter.change_exposure(new, view['revision'], validate=reject_network)
                    self.assertEqual((adapter.root / 'settings.json').read_bytes(), before)
                    adapter.change_exposure(new, view['revision'], validate=lambda _network: None)
                    changed = adapter.settings()
                    self.assertEqual(changed, replace(settings, exposure=new))
                    before = (adapter.root / 'settings.json').read_bytes()
                    with self.assertRaisesRegex(PackageError, 'mtproto_settings_changed'):
                        adapter.change_exposure(self.public, view['revision'])
                    with patch.object(adapter, 'running', return_value=True):
                        with self.assertRaisesRegex(PackageError, 'module_must_be_disabled'):
                            adapter.change_exposure(self.public, adapter.exposure_view()['revision'])
                    self.assertEqual((adapter.root / 'settings.json').read_bytes(), before)

    def test_fake_tls_uri_and_distinct_account_models(self):
        user = telemt.client_profile(self.telemt, "reader", "198.51.100.8", active=True)
        shared = mtg.client_profile(self.mtg, "Proxy.Example", active=True, allowed=True, direct=True)
        for item, scope, user_id, key, port in ((user, "user", "reader", self.on.secret, 443),
                                                (shared, "shared", None, self.mtg.secret, 2447)):
            parsed = urlsplit(item.uri())
            query = parse_qs(parsed.query)
            self.assertEqual((parsed.scheme, parsed.netloc), ("tg", "proxy"))
            self.assertEqual(query["server"], [item.server])
            self.assertEqual(query["port"], [str(port)])
            self.assertEqual(query["secret"], ["ee" + key.value + item.sni.encode().hex()])
            self.assertEqual((item.scope, item.user), (scope, user_id))
            self.assertNotIn(key.value, repr(item))
        self.assertIsNone(telemt.client_profile(self.telemt, "off", "proxy.example", active=True))
        self.assertIsNone(telemt.client_profile(self.telemt, "reader", "proxy.example", active=False))
        for active, allowed in ((False, True), (True, False)):
            self.assertIsNone(mtg.client_profile(self.mtg, "proxy.example", active=active, allowed=allowed))

    def test_native_configs_exclude_observability_and_disallowed_secrets(self):
        native = tomllib.loads(telemt.render_server(self.telemt, CoverTarget("1.1.1.1", 443)).decode())
        self.assertEqual(native["general"]["modes"], {"classic": False, "secure": False, "tls": True})
        self.assertEqual(native["general"]["links"]["show"], [])
        self.assertFalse(native["server"]["api"]["enabled"])
        self.assertNotIn("metrics_port", native["server"])
        self.assertEqual(native["access"]["users"], {"reader": self.on.secret.value})
        self.assertEqual(native["censorship"]["mask_host"], "1.1.1.1")
        native = tomllib.loads(mtg.render_server(self.mtg, CoverTarget("127.0.0.1", SITE_BACKEND_PORT)).decode())
        self.assertEqual(native["domain-fronting"], {"host": "127.0.0.1", "port": SITE_BACKEND_PORT,
                                                    "proxy-protocol": False})
        self.assertEqual(native["bind-to"], "0.0.0.0:2447")
        self.assertEqual(native["prefer-ip"], "prefer-ipv4")
        self.assertNotIn("stats", native)
        with self.assertRaises(ValueError):
            mtg.render_server(self.mtg, CoverTarget("1.1.1.1", 443))

    def test_settings_keep_secrets_root_only_and_independent(self):
        with TemporaryDirectory() as directory:
            first, second = (Path(directory) / name for name in ("telemt", "mtg"))
            self.telemt.save(first)
            self.mtg.save(second)
            self.assertEqual(first.stat().st_mode & 0o777, 0o600)
            self.assertEqual(second.stat().st_mode & 0o777, 0o600)
            self.assertEqual(telemt.Settings.load(first), self.telemt)
            self.assertEqual(mtg.Settings.load(second), self.mtg)
        self.assertNotIn(self.on.secret.value, repr(self.telemt))
        self.assertNotIn(self.mtg.secret.value, repr(self.mtg))
        with self.assertRaises(ValueError):
            telemt.Settings(self.public, (self.on, replace(self.off, secret=self.on.secret)))
        with self.assertRaises(ValueError):
            Exposure("cover.example", own_site=True, shared=False, direct_ip="0.0.0.0")
        with self.assertRaises(ValueError):
            Exposure("cover.example", direct_ip="192.0.2.3")

    def test_port_and_sni_ownership_are_independent(self):
        names = ("portal.example",)
        first = replace(self.public.network("telemt", site_names=names), enabled=True)
        second = replace(self.own.network("mtg", site_names=names), enabled=True)
        plan = build_plan((first, second), site_names=names)
        self.assertEqual({(row.owner, row.route.sni, row.route.backend.port) for row in plan.routes},
                         {("telemt", "cover.example", 2446), ("mtg", "portal.example", 2447)})
        self.assertEqual({item.publication.public for item in plan.publications},
                         {Binding("tcp", "0.0.0.0", 2446), Binding("tcp", "0.0.0.0", 2447)})
        without = build_plan((replace(first, enabled=False), second), site_names=names)
        self.assertEqual(tuple(row.owner for row in without.routes), ("mtg",))
        self.assertEqual(tuple(row.publication.public.port for row in without.publications), (2447,))
        other = replace(self.public.network("mtg", site_names=names), enabled=True)
        with self.assertRaisesRegex(NetworkConflict, "sni_conflict"):
            build_plan((first, other), site_names=names)
        with self.assertRaises(ValueError):
            self.own.network("mtg", site_names=())

    def test_cover_rejects_loops_and_private_addresses(self):
        gateway = SimpleNamespace(identities=(SimpleNamespace(is_ip=True, name="1.1.1.1"),))
        with patch("v5.modules.mtproto_common.runtime._command") as command:
            self.assertEqual(cover_target(self.own, gateway), CoverTarget("127.0.0.1", SITE_BACKEND_PORT))
            command.assert_not_called()
            command.side_effect = [b"[]", b"1.1.1.1 STREAM cover.example\n"]
            with self.assertRaisesRegex(PackageError, "mtproto_cover_loop"):
                cover_target(self.public, gateway)
            command.side_effect = [b"[]", b"192.168.2.3 STREAM cover.example\n"]
            with self.assertRaisesRegex(PackageError, "mtproto_cover_not_public"):
                cover_target(self.public, gateway)

    def test_pinned_runtime_never_passes_secret_or_docker_socket(self):
        with patch("v5.modules.mtproto_common.runtime._mount"):
            args = Runtime("telemt", "sha256:" + "a" * 64, Path("/fixture/config"), "127.0.0.1").arguments()
        self.assertIn("--pull=never", args)
        self.assertIn("--read-only", args)
        self.assertIn("65532:65532", args)
        self.assertIn("/app/telemt", args)
        self.assertNotIn("--publish", args)
        self.assertNotIn("docker.sock", " ".join(args))

    def test_absent_container_is_not_assumed_when_docker_is_unavailable(self):
        docker = Mock()
        docker.run.side_effect = [None, PackageError("mtproto_inspect_unavailable")]
        with self.assertRaisesRegex(PackageError, "mtproto_inspect_unavailable"):
            inspect_container(docker, "mtg")
        docker.run.side_effect = [None, b"29.0"]
        self.assertIsNone(inspect_container(docker, "mtg"))

    def test_dual_stack_listener_requires_ipv4_reachability(self):
        wildcard = b"0: " + b"0" * 32 + b":098F 0:0 0A 0 0 0 65532\n"
        with patch.object(Path, "open", side_effect=[BytesIO(b""), BytesIO(wildcard),
                                                     BytesIO(b""), BytesIO(wildcard)]):
            with patch("v5.modules.mtproto_common.runtime.socket.create_connection") as connect:
                self.assertTrue(listening(123, "0.0.0.0", 2447))
                connect.assert_called_once_with(("127.0.0.1", 2447), timeout=1)
                connect.side_effect = OSError("IPv6-only")
                self.assertFalse(listening(123, "0.0.0.0", 2447))

    def test_dual_stack_listener_rejects_wrong_uid_and_ipv4_conflict(self):
        wildcard = b"0: " + b"0" * 32 + b":098F 0:0 0A 0 0 0 65533\n"
        conflict = b"0: 0100007F:098F 0:0 0A 0 0 0 1234\n"
        with patch.object(Path, "open", side_effect=[BytesIO(b""), BytesIO(wildcard), BytesIO(conflict)]):
            with patch("v5.modules.mtproto_common.runtime.socket.create_connection") as connect:
                self.assertFalse(listening(123, "0.0.0.0", 2447))
                self.assertFalse(listening(123, "0.0.0.0", 2447))
                connect.assert_not_called()

    def test_signed_install_off_remove_one_leaves_the_other(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "publisher.key"
            registry = PackageRegistry(root / "registry", new_key(key))
            for module, version in (("telemt", "3.5.17"), ("mtg", "2.3.0")):
                archive = root / f"{module}.tar.gz"
                build(archive, key, module_id=module, version=version, image_digest="a" * 64,
                      issued_at=ISSUED, expires_at=EXPIRES, now=NOW)
                with archive.open("rb") as stream:
                    registry.install(registry.prepare(stream, now=NOW).ticket, now=NOW)
            before = {row["module"]: row for row in registry.installed()}
            self.assertEqual(set(before), {"telemt", "mtg"})
            self.assertTrue(all(not row["enabled"] for row in before.values()))
            self.assertTrue(registry.remove("telemt", now=NOW))
            self.assertEqual(registry.installed(), (before["mtg"],))
