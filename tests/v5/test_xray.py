"""Сетевые режимы, ключи, конфиги и подписки Xray без запуска контейнера."""

import base64
from contextlib import nullcontext
from dataclasses import replace
import hashlib
import io
from pathlib import Path
import stat
import tarfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from v5.core.network.plan import build_plan
from v5.core.packages.manifest import PackageError, canonical_json
from v5.core.packages.oci import CONFIG, IMAGE, INDEX, verify_oci
from v5.modules.xray.adapter import XrayAdapter, public_profile
from v5.modules.xray.clients import client_profiles, subscription
from v5.modules.xray.config import Settings, render_server
from v5.modules.xray.credentials import Account, load_reality
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles, Reality


class XrayProfilesTests(unittest.TestCase):
    def test_initial_profile_never_replaces_existing_settings(self):
        with TemporaryDirectory() as directory:
            packages = MagicMock()
            packages.runtime_guard.return_value = nullcontext()
            packages.installed.return_value = [{'module': 'xray', 'enabled': False}]
            context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(site_names=()))
            adapter = XrayAdapter(context, root=Path(directory) / 'xray', docker=MagicMock())
            profile = Profile(Kind.REALITY_TCP, Exposure.SHARED, 'cdn.example', Reality.EXTERNAL, 'cdn.example')
            settings = Settings(Profiles((profile,)))
            with patch.object(adapter, 'running', return_value=False):
                adapter.configure(settings, initial=True)
                path = Path(directory) / 'xray' / 'settings.json'
                before = path.read_bytes()
                with self.assertRaisesRegex(PackageError, 'xray_already_configured'):
                    adapter.configure(settings, initial=True)
                self.assertEqual(path.read_bytes(), before)

    def test_add_profile_preserves_accounts_and_refuses_failed_preview(self):
        with TemporaryDirectory() as directory:
            packages = MagicMock()
            packages.runtime_guard.return_value = nullcontext()
            packages.installed.return_value = [{'module': 'xray', 'enabled': False}]
            context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(site_names=()))
            adapter = XrayAdapter(context, root=Path(directory) / 'xray', docker=MagicMock())
            old = Profile(Kind.REALITY_TCP, Exposure.SHARED, 'one.example', Reality.EXTERNAL, 'one.example')
            new = Profile(Kind.REALITY_XHTTP, Exposure.SHARED, 'two.example', Reality.EXTERNAL, 'two.example', '/kvn')
            account = Account('test', '12345678-1234-4234-8234-123456789abc', (Kind.REALITY_TCP,))
            with patch.object(adapter, 'running', return_value=False):
                adapter.configure(Settings(Profiles((old,)), (account,)), initial=True)
                path = Path(directory) / 'xray' / 'settings.json'
                before = path.read_bytes()
                def conflict(_network):
                    raise ValueError('конфликт сети')
                with self.assertRaisesRegex(ValueError, 'конфликт сети'):
                    adapter.add_profile(new, validate=conflict)
                self.assertEqual(path.read_bytes(), before)
                adapter.add_profile(new, validate=lambda _network: None)
                result = Settings.load(path)
                self.assertEqual(result.accounts, (account,))
                self.assertEqual(result.profiles.values, (old, new))
                with self.assertRaisesRegex(PackageError, 'xray_profile_conflict'):
                    adapter.add_profile(new)

    def test_edit_and_remove_require_current_revision_and_preserve_credentials(self):
        with TemporaryDirectory() as directory:
            packages = MagicMock()
            packages.runtime_guard.return_value = nullcontext()
            packages.installed.return_value = [{'module': 'xray', 'enabled': False}]
            context = SimpleNamespace(packages=packages, gateway=SimpleNamespace(site_names=()))
            adapter = XrayAdapter(context, root=Path(directory) / 'xray', docker=MagicMock())
            old = Profile(Kind.REALITY_TCP, Exposure.SHARED, 'one.example', Reality.EXTERNAL, 'one.example')
            new = replace(old, sni='new.example', external_host='new.example')
            account = Account('test', '12345678-1234-4234-8234-123456789abc', (Kind.REALITY_TCP,))
            with patch.object(adapter, 'running', return_value=False):
                adapter.configure(Settings(Profiles((old,)), (account,)), initial=True)
                visible = adapter.profile_list()
                self.assertNotIn(account.id, str(visible))
                revision = public_profile(old)['revision']
                adapter.change_profile(old.kind, revision, new)
                self.assertEqual(adapter.settings().accounts, (account,))
                with self.assertRaisesRegex(PackageError, 'xray_profile_changed'):
                    adapter.change_profile(old.kind, revision, old)
                with self.assertRaisesRegex(PackageError, 'xray_profile_in_use'):
                    adapter.change_profile(new.kind, public_profile(new)['revision'], None)
                self.assertEqual(adapter.settings().profiles.values, (new,))
                second = Profile(Kind.REALITY_XHTTP, Exposure.SHARED, 'two.example', Reality.EXTERNAL, 'two.example', '/kvn')
                adapter.add_profile(second)
                adapter.change_profile(second.kind, public_profile(second)['revision'], None)
                self.assertEqual(adapter.settings().profiles.values, (new,))
                self.assertEqual(adapter.settings().accounts, (account,))

    def test_installed_profiles_are_not_enabled_and_empty_has_no_resources(self):
        self.assertEqual(Profiles().network(site_names=()).routes, ())
        self.assertEqual(Profiles().network(site_names=()).publications, ())
        profile = Profile(Kind.REALITY_TCP, Exposure.SHARED, "www.example.org", Reality.EXTERNAL, "www.example.org")
        network = Profiles((profile,)).network(site_names=())
        self.assertEqual(build_plan((network,)).active, ())
        active = build_plan((replace(network, enabled=True),))
        self.assertEqual(active.routes[0].route.backend.port, 2444)
        self.assertEqual(active.publications, ())

    def test_explicit_self_steal_never_uses_admin_as_target(self):
        site = "portal.example"
        profile = Profile(Kind.REALITY_TCP, Exposure.SHARED, site, Reality.SELF_STEAL)
        self.assertEqual(profile.target, "127.0.0.1:10443")
        with self.assertRaisesRegex(ValueError, "не настроено"):
            Profiles((profile,)).network(site_names=())
        network = Profiles((profile,)).network(site_names=(site,))
        self.assertTrue(network.routes[0].self_steal)
        with self.assertRaisesRegex(ValueError, "выберите self-steal явно"):
            Profiles((Profile(Kind.REALITY_TCP, Exposure.SHARED, site, Reality.EXTERNAL, site),)).network(site_names=(site,))
        with self.assertRaisesRegex(ValueError, "требует общего"):
            Profile(Kind.REALITY_TCP, Exposure.DIRECT, site, Reality.SELF_STEAL)

    def test_tls_ip_is_direct_only_and_xhttp_exposes_only_selected_ports(self):
        ip = "192.0.2.8"
        tls = Profile(Kind.TLS, Exposure.DIRECT, ip)
        with self.assertRaisesRegex(ValueError, "по IP"):
            Profile(Kind.TLS, Exposure.SHARED, ip)
        self.assertTrue(tls.tls_identity().is_ip)
        xhttp = Profile(Kind.REALITY_XHTTP, Exposure.BOTH, "cdn.example", Reality.EXTERNAL, "cdn.example", "/download")
        result = Profiles((tls, xhttp)).network(site_names=())
        self.assertEqual(tuple((item.public.ip, item.public.port) for item in result.publications),
                         (('0.0.0.0', 2443), ('::', 2443), ('0.0.0.0', 2445), ('::', 2445)))
        ipv4_only = Profiles((tls,)).network(site_names=(), ipv4=ip)
        self.assertEqual(tuple((item.public.ip, item.public.port) for item in ipv4_only.publications), ((ip, 2443),))
        self.assertEqual(tuple(item.backend.port for item in result.routes), (2445,))
        self.assertEqual(xhttp.target, "cdn.example:443")
        with self.assertRaisesRegex(ValueError, "Недопустимый путь"):
            replace(xhttp, path="/x/../api")
        with self.assertRaisesRegex(ValueError, "Повтор режима"):
            Profiles((xhttp, xhttp))
        with self.assertRaisesRegex(ValueError, "wildcard"):
            Profiles((xhttp,)).network(site_names=(), ipv4=ip)


class XrayCredentialsAndExportTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.key = load_reality(self.root / 'reality.json', create=True)
        self.user = Account('Лаборатория', 'f8b7598c-3411-4c0c-9824-4c5bc2af0f19',
                            (Kind.TLS, Kind.REALITY_TCP, Kind.REALITY_XHTTP))
        self.other = Account('Только TLS', 'ac167b7d-092e-4116-a47c-95e7dc4172bf', (Kind.TLS,))
        self.settings = Settings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, 'portal.example'),
                                           Profile(Kind.REALITY_TCP, Exposure.SHARED, 'portal.example', Reality.SELF_STEAL),
                                           Profile(Kind.REALITY_XHTTP, Exposure.BOTH, 'cdn.example', Reality.EXTERNAL,
                                                   'cdn.example', '/content'))), (self.user, self.other))

    def test_private_settings_and_keys_are_preserved_across_mode_change(self):
        filename = self.root / 'settings.json'
        self.settings.save(filename)
        original = (self.root / 'reality.json').read_bytes()
        self.assertEqual(Settings.load(filename), self.settings)
        first = render_server(self.settings, self.key, site_names=('portal.example',))['inbounds']
        self.assertEqual([item['port'] for item in first], [2443, 2444, 2445])
        self.assertEqual([len(item['settings']['users']) for item in first], [2, 1, 1])
        self.assertEqual(first[1]['streamSettings']['realitySettings']['target'], '127.0.0.1:10443')
        external = Profile(Kind.REALITY_TCP, Exposure.SHARED, 'other.example', Reality.EXTERNAL, 'other.example')
        changed = replace(self.settings, profiles=Profiles((external,)))
        changed.save(filename)
        reopened = load_reality(self.root / 'reality.json', create=True)
        second = render_server(Settings.load(filename), reopened, site_names=('portal.example',))['inbounds']
        self.assertEqual(len(second), 1)
        self.assertEqual(second[0]['streamSettings']['realitySettings']['target'], 'other.example:443')
        self.assertEqual(reopened, self.key)
        self.assertEqual((self.root / 'reality.json').read_bytes(), original)
        for path in (filename, self.root / 'reality.json'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        filename.chmod(0o644)
        with self.assertRaises(ValueError):
            Settings.load(filename)

    def test_v2ray_subscription_keeps_sni_for_ip_and_filters_grants(self):
        def profiles(user, **kwargs):
            return client_profiles(self.settings, user.id, '198.51.100.10', self.key.public, **kwargs)

        result = profiles(self.user, active=True, prefer_direct=True)
        self.assertEqual([entry.port for entry in result], [2443, 443, 2445])
        decoded = base64.b64decode(subscription(result), validate=True).decode('ascii').splitlines()
        self.assertEqual(decoded, [entry.uri() for entry in result])
        urls = [urlsplit(line) for line in decoded]
        fields = [parse_qs(url.query) for url in urls]
        self.assertTrue(all(url.hostname == '198.51.100.10' and url.scheme == 'vless' for url in urls))
        self.assertEqual([item['sni'][0] for item in fields], ['portal.example', 'portal.example', 'cdn.example'])
        self.assertEqual(fields[1]['flow'], ['xtls-rprx-vision'])
        self.assertEqual(fields[2]['type'], ['xhttp'])
        self.assertEqual(fields[2]['path'], ['/content'])
        self.assertEqual(fields[2]['mode'], ['auto'])
        self.assertEqual(fields[2]['pbk'], [self.key.public.key])
        self.assertEqual(fields[2]['sid'], [self.key.public.short_id])
        self.assertNotIn(self.key.private, '\n'.join(decoded))
        self.assertEqual(len(profiles(self.other, active=True)), 1)
        self.assertEqual(subscription(profiles(self.user, active=False)), b'')


class XrayOfflineImageTests(unittest.TestCase):
    def test_signed_digest_binds_oci_and_legacy_views_without_tags(self):
        with TemporaryDirectory() as directory:
            archive = Path(directory) / 'image.tar'
            content = {}

            def blob(media_type, data):
                sha = hashlib.sha256(data).hexdigest()
                content[f'blobs/sha256/{sha}'] = data
                return {'mediaType': media_type, 'digest': f'sha256:{sha}', 'size': len(data)}

            def path(descriptor):
                return 'blobs/sha256/' + descriptor['digest'][7:]

            config = blob(CONFIG, canonical_json({'os': 'linux', 'architecture': 'amd64'}))
            layer = blob('application/vnd.oci.image.layer.v1.tar', b'fake-layer')
            manifest = blob(IMAGE, canonical_json({'schemaVersion': 2, 'mediaType': IMAGE, 'config': config,
                                                   'layers': [layer]}))
            content['oci-layout'] = canonical_json({'imageLayoutVersion': '1.0.0'})
            content['index.json'] = canonical_json({'schemaVersion': 2, 'mediaType': INDEX, 'manifests': [manifest]})
            legacy = {'Config': path(config), 'Layers': [path(layer)], 'RepoTags': None}

            def save(entry):
                content['manifest.json'] = b'[' + canonical_json(entry) + b']'
                with tarfile.open(archive, 'w', format=tarfile.USTAR_FORMAT) as output:
                    for name, raw in content.items():
                        member = tarfile.TarInfo(name)
                        member.size = len(raw)
                        output.addfile(member, io.BytesIO(raw))

            expected = manifest['digest'][7:]
            save(legacy)
            verified = verify_oci(archive, expected, arch='amd64')
            self.assertEqual(verified.config_digest, config['digest'][7:])
            with self.assertRaisesRegex(PackageError, '^oci_platform_mismatch$'):
                verify_oci(archive, expected, arch='arm64')
            with self.assertRaisesRegex(PackageError, '^oci_manifest_digest_mismatch$'):
                verify_oci(archive, 'f' * 64, arch='amd64')
            for changed in ({'RepoTags': ['xray:latest']}, {'Layers': [path(config)]}):
                save(legacy | changed)
                with self.assertRaisesRegex(PackageError, '^unsafe_docker_manifest$'):
                    verify_oci(archive, expected, arch='amd64')
            content[path(layer)] = b'evil-layer'
            save(legacy)
            with self.assertRaisesRegex(PackageError, '^oci_blob_digest_mismatch$'):
                verify_oci(archive, expected, arch='amd64')


class XrayReadinessTests(unittest.TestCase):
    def test_export_checks_mount_and_listener_once_without_waiting(self):
        from v5.core.lifecycle.controller import LifecycleError
        from v5.modules.xray.runtime import CONFIG_ROOT, Runtime

        adapter = XrayAdapter(None)
        runtime = Runtime('sha256:' + '1' * 64, Path('/fixture/verified-generation'))
        current = {'image': runtime.image, 'running': True, 'network': 'host', 'mounts': [
            {'Type': 'bind', 'Source': str(runtime.folder), 'Destination': CONFIG_ROOT, 'RW': False},
        ]}
        with (
            patch.object(adapter, '_addresses', return_value=[('192.0.2.8', 2443)]),
            patch('v5.modules.xray.adapter.runtime_state', return_value=runtime),
            patch('v5.modules.xray.adapter.socket.create_connection', return_value=MagicMock()) as connect,
            patch('v5.modules.xray.adapter.inspect_container', return_value=current) as inspect,
        ):
            adapter.verify_export()
            inspect.assert_called_once_with(adapter.docker, timeout=5)
            connect.assert_called_once_with(('192.0.2.8', 2443), timeout=0.5)
            current['mounts'][0]['RW'] = True
            with self.assertRaisesRegex(LifecycleError, 'xray_not_healthy'):
                adapter.verify_export()
            self.assertEqual(connect.call_count, 1)

    def test_waits_for_socket_and_requires_matching_container_image(self):
        adapter = XrayAdapter(None)
        settings = Settings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, 'portal.example'),)), ipv4='192.0.2.8')
        with (
            patch.object(adapter, 'settings', return_value=settings),
            patch('v5.modules.xray.adapter.runtime_state', return_value=SimpleNamespace(image='expected')),
            patch('v5.modules.xray.adapter.socket.create_connection',
                  side_effect=[ConnectionRefusedError, MagicMock(), MagicMock()]) as connect,
            patch('v5.modules.xray.adapter.inspect_container', side_effect=[
                {'running': True, 'image': 'different'}, {'running': True, 'image': 'expected'},
            ]) as inspect,
            patch('v5.modules.xray.adapter.time.sleep'),
        ):
            adapter._probe()
        self.assertEqual(connect.call_count, 3)
        connect.assert_called_with(('192.0.2.8', 2443), timeout=1)
        self.assertEqual(inspect.call_count, 2)
