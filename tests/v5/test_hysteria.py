"""Контракт независимого Hysteria2, не подменяющий сетевой E2E."""

import base64
from contextlib import nullcontext
from dataclasses import replace
from io import BytesIO
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from v5.core.network.plan import Binding, NetworkConflict, build_plan
from v5.core.network.runtime import check_binding
from v5.core.lifecycle.controller import LifecycleError
from v5.core.packages.docker_image import Docker, LocalImage
from v5.core.packages.manifest import PackageError, canonical_json
from v5.core.private_files import write_private
from v5.modules.hysteria.clients import client_profile, subscription
from v5.modules.hysteria.adapter import HysteriaAdapter
from v5.modules.hysteria.config import CONFIG_ROOT, TLS_ROOT, Account, Settings, identity, parse_settings, render_server
from v5.modules.hysteria.runtime import INNER_PORT, Runtime, inspect_container, listening, publish_certificate
from v5.modules.hysteria.idle import idle_secret


class HysteriaTests(unittest.TestCase):
    def setUp(self):
        self.account = Account("reader", "b" * 43)
        self.disabled = Account("disabled", "c" * 43, False)
        self.settings = Settings(identity("portal.example"), (self.account, self.disabled))

    def test_initial_setup_preserves_existing_settings_and_users(self):
        with TemporaryDirectory() as directory:
            packages = Mock()
            packages.runtime_guard.return_value = nullcontext()
            packages.installed.return_value = [{'module': 'hysteria', 'enabled': False}]
            context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(identities=(self.settings.tls,)))
            adapter = HysteriaAdapter(context, root=Path(directory) / 'hysteria', docker=Mock())
            with patch.object(adapter, 'running', return_value=False):
                adapter.configure(self.settings, initial=True, validate=lambda _network: None)
                path = Path(directory) / 'hysteria' / 'settings.json'
                before = path.read_bytes()
                with self.assertRaisesRegex(PackageError, 'hysteria_already_configured'):
                    adapter.configure(Settings(self.settings.tls), initial=True)
                self.assertEqual(path.read_bytes(), before)

    def test_edit_preserves_accounts_and_salamander_and_rejects_conflicts(self):
        with TemporaryDirectory() as directory:
            packages = Mock()
            packages.runtime_guard.return_value = nullcontext()
            packages.installed.return_value = [{'module': 'hysteria', 'enabled': False}]
            context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(identities=(self.settings.tls,)))
            adapter = HysteriaAdapter(context, root=Path(directory) / 'hysteria', docker=Mock())
            original = replace(self.settings, salamander='d' * 43)
            with patch.object(adapter, 'running', return_value=False):
                self.assertIsNone(adapter.settings_view())
                adapter.configure(original, initial=True)
                view = adapter.settings_view()
                self.assertNotIn(original.salamander, repr(view))
                self.assertNotIn(self.account.password, repr(view))
                def conflict(_network):
                    raise NetworkConflict('port_conflict')
                before = (adapter.root / 'settings.json').read_bytes()
                with self.assertRaises(NetworkConflict):
                    adapter.change_settings(original.tls, 2443, True, view['revision'], validate=conflict)
                self.assertEqual((adapter.root / 'settings.json').read_bytes(), before)
                adapter.change_settings(original.tls, 2443, True, view['revision'])
                self.assertEqual(adapter.settings(), replace(original, port=2443))
                with self.assertRaisesRegex(PackageError, 'hysteria_settings_changed'):
                    adapter.change_settings(original.tls, 2443, True, view['revision'])
                with patch.object(adapter, 'running', return_value=True):
                    with self.assertRaisesRegex(PackageError, 'module_must_be_disabled'):
                        adapter.change_settings(original.tls, 2443, True, adapter.settings_view()['revision'])

    def test_strict_settings_round_trip(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "settings.json"
            self.settings.save(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(Settings.load(path), self.settings)
            with self.assertRaisesRegex(PackageError, "duplicate_json_key"):
                parse_settings(path.read_bytes().replace(b'"schema":1', b'"schema":1,"schema":1'))
        for invalid in ("::", "127.0.0.1", "fe80::1", "169.254.1.1", "224.0.0.1"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                replace(self.settings, bind=invalid)
        with self.assertRaises(ValueError):
            replace(self.settings, accounts=(self.account, self.account))
        with self.assertRaises(ValueError):
            Account("reader", "weak")
        self.assertNotIn(self.account.password, repr(self.settings))
        self.assertNotIn(self.account.password, repr(self.account))

    def test_native_server_has_no_disabled_user_or_additional_service(self):
        value = render_server(self.settings)
        self.assertEqual(value["auth"], {"type": "userpass", "userpass": {"reader": self.account.password}})
        self.assertEqual(value["listen"], f"0.0.0.0:{INNER_PORT}")
        self.assertEqual(value["tls"]["sniGuard"], "strict")
        self.assertNotIn("masquerade", value)
        self.assertNotIn("trafficStats", value)
        self.assertFalse(value["speedTest"])
        self.assertIn("reject(169.254.0.0/16)", value["acl"]["inline"])
        with self.assertRaisesRegex(PackageError, "hysteria_accounts_required"):
            render_server(replace(self.settings, accounts=(self.disabled,)))

    def test_last_user_can_be_revoked_without_a_known_placeholder_password(self):
        with TemporaryDirectory() as first, TemporaryDirectory() as second:
            secret = idle_secret(Path(first), create=True)
            self.assertEqual(secret, idle_secret(Path(first)))
            self.assertNotEqual(secret, idle_secret(Path(second), create=True))
            self.assertEqual((Path(first) / "idle-auth.json").stat().st_mode & 0o777, 0o600)
            settings = replace(self.settings, accounts=(self.disabled,))
            auth = render_server(settings, idle_secret=secret)["auth"]["userpass"]
            self.assertEqual(auth, {"_kvn_no_user": secret})
            self.assertNotIn(self.disabled.password, auth.values())
            with self.assertRaises(ValueError):
                Account("_kvn_no_user", secret)

    def test_export_keeps_tls_identity_and_filters_grants(self):
        for user, active in (("reader", False), ("disabled", True), ("other", True)):
            item = client_profile(self.settings, user, active=active)
            self.assertIsNone(item)
            self.assertEqual(subscription(item), b"")
        settings = replace(self.settings, salamander="s" * 32)
        profile = client_profile(settings, "reader", active=True, endpoint="198.51.100.8")
        uri = urlsplit(profile.uri())
        self.assertEqual((uri.scheme, uri.username, uri.password, uri.hostname, uri.port),
                         ("hysteria2", "reader", self.account.password, "198.51.100.8", 443))
        self.assertEqual(parse_qs(uri.query), {"sni": ["portal.example"], "obfs": ["salamander"],
                                               "obfs-password": ["s" * 32]})
        self.assertEqual(profile.native()["tls"], {"sni": "portal.example", "insecure": False})
        self.assertEqual(base64.b64decode(subscription(profile)).decode().strip(), profile.uri())
        settings = replace(settings, tls=identity("198.51.100.8"))
        with self.assertRaises(ValueError):
            client_profile(settings, "reader", active=True, endpoint="198.51.100.9")
        ip_profile = client_profile(settings, "reader", active=True)
        self.assertEqual(ip_profile.native()["tls"], {"insecure": False})
        self.assertNotIn("sni", parse_qs(urlsplit(ip_profile.uri()).query))

    def test_network_declares_one_udp_and_conflict_is_protocol_specific(self):
        declaration = replace(self.settings.network(), enabled=True)
        self.assertEqual(declaration.routes, ())
        plan = build_plan((declaration,), occupied=(Binding("tcp", "0.0.0.0", 443),))
        self.assertEqual(plan.publications[0].publication.public, Binding("udp", "0.0.0.0", 443))
        with self.assertRaisesRegex(NetworkConflict, "unmanaged_port_conflict"):
            build_plan((declaration,), occupied=(Binding("udp", "192.0.2.8", 443),))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as owned:
            owned.bind(("127.0.0.1", 0))
            with self.assertRaisesRegex(NetworkConflict, "publication_port_unavailable"):
                check_binding(Binding("udp", "0.0.0.0", owned.getsockname()[1]))
            check_binding(Binding("tcp", "0.0.0.0", owned.getsockname()[1]))

    def test_docker_runtime_publishes_only_exact_udp_and_rejects_foreign(self):
        image = "sha256:" + "a" * 64
        binding = Binding("udp", "198.51.100.8", 443)
        runtime = Runtime(image, Path("/root/fixture/generations/config"), binding)
        with patch("v5.modules.hysteria.runtime.validate_mount"):
            args = runtime.arguments()
        self.assertEqual(args.count("--publish"), 1)
        self.assertIn("198.51.100.8:443:11443/udp", args)
        self.assertIn("65532:65532", args)
        self.assertIn("--read-only", args)
        self.assertIn("--pull=never", args)
        self.assertNotIn("--privileged", args)
        mounts = [{"Destination": dest, "Source": str(source), "Type": "bind", "RW": False}
                  for dest, source in ((CONFIG_ROOT, runtime.folder), (TLS_ROOT, runtime.tls_folder))]
        current = {"image": image, "network": "bridge", "mounts": mounts,
                   "ports": {"11443/udp": [{"HostIp": binding.ip, "HostPort": "443"}]}}
        self.assertTrue(runtime.matches(current))
        self.assertFalse(runtime.matches({**current, "network": "host"}))
        self.assertFalse(runtime.matches({**current, "mounts": [{**mounts[0], "RW": True}, mounts[1]]}))
        self.assertFalse(runtime.matches({**current, "ports": {**current["ports"], "443/tcp": []}}))
        docker = Mock()
        snapshot = {"owner": "hysteria", "id": "b" * 64, "image": image,
                    "running": True, "pid": 12, "ports": {}, "network": "bridge"}
        docker.run.return_value = canonical_json(snapshot)
        self.assertEqual(inspect_container(docker)["pid"], 12)
        docker.run.return_value = canonical_json({**snapshot, "owner": "foreign"})
        with self.assertRaisesRegex(PackageError, "foreign_hysteria_container"):
            inspect_container(docker)
        docker.run.return_value = canonical_json({**snapshot, "pid": 0})
        with self.assertRaisesRegex(PackageError, "foreign_hysteria_container"):
            inspect_container(docker)

    def test_ready_socket_is_in_inspected_process_namespace(self):
        for port, status, uid, result in (("2CB3", "07", 65532, True), ("2CB3", "07", 0, False),
                                          ("2CB3", "01", 65532, False), ("2CB4", "07", 65532, False)):
            line = f"0: 00000000:{port} 00000000:0000 {status} 0:0 0:0 0 {uid}\n".encode()
            with patch("v5.modules.hysteria.runtime.Path", wraps=Path) as path, \
                    patch.object(Path, "open", return_value=BytesIO(b"header\n" + line)):
                self.assertEqual(listening(1234), result)
                path.assert_called_once_with("/proc/1234/net/udp")
        with patch.object(Path, "open", side_effect=FileNotFoundError):
            self.assertFalse(listening(1234))
        self.assertFalse(listening(True))

    def test_readiness_retries_transport_timeout_but_not_untrusted_state(self):
        adapter = HysteriaAdapter(None, docker=Mock())
        package = "v5.modules.hysteria.adapter"
        with patch(f"{package}.runtime_state") as runtime, patch(f"{package}.time.sleep"), \
                patch(f"{package}.inspect_container") as inspect, patch(f"{package}.listening", return_value=True):
            runtime.return_value.matches.return_value = True
            inspect.side_effect = [PackageError("hysteria_inspect_unavailable"), {"running": True, "pid": 44}]
            adapter._probe()
            self.assertEqual(inspect.call_count, 2)
            self.assertEqual(inspect.call_args.kwargs["timeout"], 25)

            inspect.reset_mock(side_effect=True)
            inspect.side_effect = PackageError("foreign_hysteria_container")
            with self.assertRaisesRegex(PackageError, "foreign_hysteria_container"):
                adapter._probe()
            self.assertEqual(inspect.call_count, 1)

            inspect.reset_mock(side_effect=True)
            inspect.side_effect = PackageError("hysteria_inspect_unavailable")
            with patch(f"{package}.time.monotonic", side_effect=[0, 117, 120, 120]):
                with self.assertRaisesRegex(LifecycleError, "hysteria_not_healthy"):
                    adapter._probe()
            self.assertEqual(inspect.call_args.kwargs["timeout"], 3)

    def test_pair_publication_keeps_both_versions_atomic(self):
        if os.geteuid() != 0:
            self.skipTest("Права chown проверяются в WSL root")
        with TemporaryDirectory() as directory:
            root = Path(directory)
            chain, key = root / "chain.pem", root / "key.pem"
            pair = SimpleNamespace(chain=chain, key=key)
            write_private(chain, b"synthetic-chain-1\n")
            write_private(key, b"synthetic-key-1\n")
            publish_certificate(root, pair)
            target = root / "tls" / "server.pem"
            old = target.open("rb")
            with old:
                write_private(chain, b"synthetic-chain-2\n")
                write_private(key, b"synthetic-key-2\n")
                publish_certificate(root, pair)
                self.assertEqual(old.read(), b"synthetic-chain-1\nsynthetic-key-1\n")
            self.assertEqual(target.read_bytes(), b"synthetic-chain-2\nsynthetic-key-2\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_export_does_not_wait_for_start_or_probe_udp_on_wrong_generation(self):
        adapter = HysteriaAdapter(None, docker=Mock())
        package = "v5.modules.hysteria.adapter"
        with patch(f"{package}.runtime_state") as runtime, \
                patch(f"{package}.inspect_container", return_value={"running": True, "pid": 42}) as inspect, \
                patch(f"{package}.listening", return_value=True) as udp:
            runtime.return_value.matches.return_value = True
            adapter.verify_export()
            inspect.assert_called_once_with(adapter.docker, timeout=5)
            udp.assert_called_once_with(42)
            runtime.return_value.matches.return_value = False
            with self.assertRaisesRegex(LifecycleError, "hysteria_not_healthy"):
                adapter.verify_export()
            self.assertEqual(udp.call_count, 1)

    def test_docker_hub_digest_alias_is_exact(self):
        digest = "sha256:" + "a" * 64
        manifest = SimpleNamespace(image_ref=f"docker.io/tobyxdd/hysteria@{digest}",
                                   image_digest=digest.split(":")[1], offline_image=False)
        docker = Docker()
        with patch("v5.core.packages.docker_image.architecture", return_value="amd64"), \
                patch.object(docker, "ready"), patch.object(docker, "inspect") as inspected:
            for repository, valid in (("tobyxdd/hysteria", True), ("docker.io/tobyxdd/hysteria", True),
                                      ("evil.example/tobyxdd/hysteria", False)):
                local = LocalImage(digest, "linux", "amd64", (f"{repository}@{digest}",))
                inspected.return_value = local
                if valid:
                    self.assertEqual(docker.resolve(manifest, Path("/unused")), local)
                else:
                    with self.assertRaisesRegex(PackageError, "docker_online_image_mismatch"):
                        docker.resolve(manifest, Path("/unused"))
