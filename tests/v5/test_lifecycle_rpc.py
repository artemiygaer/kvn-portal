"""Портал передаёт только разрешённые команды жизненного цикла по Unix-сокету."""

import json
import os
from pathlib import Path
import socket
from tempfile import TemporaryDirectory
from threading import Thread
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from v5.core.contracts import CORE_API_VERSION
from v5.core.lifecycle.rpc import Application
from v5.core.lifecycle.controller import Lifecycle
from v5.core.network.plan import Binding, ModuleNetwork, NetworkConflict, Route
from v5.modules.host_tunnel.platform import Capability
from v5.portal.app import create_app
from v5.portal.rpc import LifecycleClient


class Runtime:
    def __init__(self):
        self.enabled = False
        self.calls = []

    def change(self, module, enabled):
        self.calls.append(('change', module, enabled))
        self.enabled = enabled
        return SimpleNamespace(active=(module,) if enabled else ())

    def upgrade(self, module, ticket):
        self.calls.append(('upgrade', module, ticket))
        return SimpleNamespace(active=(module,))

    def status(self):
        return {'installed': [{'module': 'xray', 'version': '1.0.0', 'enabled': self.enabled}]}


class LifecycleRPCTests(unittest.TestCase):
    def test_settings_snapshot_is_bounded_and_isolates_module_errors(self):
        wireguard, mtg, xray = Mock(), Mock(), Mock()
        wireguard.egress_view.return_value = {'egress': 'eth0', 'revision': 'a' * 64}
        mtg.exposure_view.side_effect = ValueError('fixture')
        xray.profile_list.return_value = []
        factory = Mock(return_value=SimpleNamespace(adapters={'wireguard': wireguard, 'mtg': mtg, 'xray': xray}))
        rpc = Application(os.geteuid(), factory)
        base = {'version': CORE_API_VERSION, 'method': 'lifecycle.settings_snapshot'}
        result = rpc.dispatch({**base, 'params': {'modules': ['wireguard', 'mtg', 'xray']}})
        self.assertEqual(result['settings']['wireguard']['egress'], 'eth0')
        self.assertEqual(result['settings']['xray'], [])
        self.assertEqual(result['errors'], ['mtg'])
        factory.assert_called_once()
        for modules in (['xray', 'xray'], ['ocserv'], [None], 'xray'):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                rpc.dispatch({**base, 'params': {'modules': modules}})
    def test_tunnel_edit_form_requires_confirmation(self):
        lifecycle = Mock()
        app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost']},
                         client=Mock(), package_client=Mock(), lifecycle_client=lifecycle)
        browser, origin = app.test_client(), 'https://localhost'
        with browser.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf='fixture-csrf')
        data = {'csrf': 'fixture-csrf', 'module': 'wireguard', 'egress': 'eth0', 'revision': 'a' * 64,
                'confirm': 'yes'}
        self.assertEqual(browser.post('/modules/change_tunnel', data=data, base_url=origin).status_code, 403)
        self.assertEqual(browser.post('/modules/change_tunnel', data={**data, 'confirm': ''}, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.change_tunnel.assert_not_called()
        self.assertEqual(browser.post('/modules/change_tunnel', data=data, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.change_tunnel.assert_called_once_with('wireguard', 'eth0', 'a' * 64)

    def test_tunnel_edit_rpc_is_allowlisted(self):
        adapter = Mock()
        rpc = Application(os.geteuid(), lambda: SimpleNamespace(adapters={'wireguard': adapter}))
        request = {'version': CORE_API_VERSION, 'method': 'lifecycle.change_tunnel',
                   'params': {'module': 'wireguard', 'egress': 'eth0', 'revision': 'a' * 64}}
        self.assertEqual(rpc.dispatch(request), {'module': 'wireguard', 'configured': True})
        adapter.change_egress.assert_called_once_with('eth0', 'a' * 64)
        with self.assertRaises(ValueError):
            rpc.dispatch({**request, 'params': {**request['params'], 'module': 'xray'}})
    def test_mtproto_initialization_is_allowlisted_and_never_returns_secret(self):
        adapter = Mock()
        runtime = SimpleNamespace(adapters={'mtg': adapter, 'telemt': adapter}, preview_configuration_locked=Mock())
        rpc = Application(os.geteuid(), lambda: runtime)
        params = {'module': 'mtg', 'sni': 'example.org', 'mode': 'external', 'exposure': 'shared'}
        request = {'version': CORE_API_VERSION, 'method': 'lifecycle.initialize_mtproto', 'params': params}
        result = rpc.dispatch(request)
        self.assertEqual(result, {'module': 'mtg', 'configured': True})
        secret = adapter.configure.call_args.args[0].secret.value
        self.assertNotIn(secret, str(result))
        self.assertTrue(adapter.configure.call_args.kwargs['initial'])
        adapter.configure.reset_mock()
        for bad in ({**params, 'module': 'hysteria'}, {**params, 'mode': 'invalid'},
                    {**params, 'exposure': 'bogus'}, {**params, 'sni': 'bad;id'},
                    {**params, 'mode': 'own', 'exposure': 'direct'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rpc.dispatch({**request, 'params': bad})
        adapter.configure.assert_not_called()

    def test_mtproto_change_passes_revision_without_returning_secrets(self):
        adapter = Mock()
        runtime = SimpleNamespace(adapters={'mtg': adapter}, preview_configuration_locked=Mock())
        rpc = Application(os.geteuid(), lambda: runtime)
        params = {'module': 'mtg', 'sni': 'example.org', 'mode': 'external',
                  'exposure': 'direct', 'revision': 'a' * 64}
        result = rpc.dispatch({'version': CORE_API_VERSION, 'method': 'lifecycle.change_mtproto', 'params': params})
        self.assertEqual(result, {'module': 'mtg', 'configured': True})
        self.assertEqual(adapter.change_exposure.call_args.args[1], 'a' * 64)
        self.assertEqual(adapter.change_exposure.call_args.args[0].sni, 'example.org')
        with self.assertRaises(ValueError):
            rpc.dispatch({'version': CORE_API_VERSION, 'method': 'lifecycle.mtproto_exposure',
                          'params': {'module': 'xray'}})

    def test_mtproto_change_form_requires_csrf_and_confirmation(self):
        lifecycle = Mock()
        app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost']},
                         client=Mock(), package_client=Mock(), lifecycle_client=lifecycle)
        browser, origin = app.test_client(), 'https://localhost'
        with browser.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf='fixture-csrf')
        data = {'csrf': 'fixture-csrf', 'module': 'mtg', 'sni': 'example.org', 'mode': 'external',
                'exposure': 'shared', 'revision': 'a' * 64, 'confirm': 'yes'}
        self.assertEqual(browser.post('/modules/change_mtproto', data=data, base_url=origin).status_code, 403)
        self.assertEqual(browser.post('/modules/change_mtproto', data={**data, 'confirm': ''}, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.change_mtproto.assert_not_called()
        self.assertEqual(browser.post('/modules/change_mtproto', data=data, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.change_mtproto.assert_called_once_with('mtg', 'example.org', 'external', 'shared', 'a' * 64)

    def test_hysteria_initialization_generates_secret_inside_agent(self):
        adapter = Mock()
        runtime = SimpleNamespace(adapters={'hysteria': adapter}, preview_configuration_locked=Mock())
        rpc = Application(os.geteuid(), lambda: runtime)
        params = {'module': 'hysteria', 'identity': 'example.org', 'port': 443, 'salamander': True}
        request = {'version': CORE_API_VERSION, 'method': 'lifecycle.initialize_hysteria', 'params': params}
        result = rpc.dispatch(request)
        self.assertEqual(result, {'module': 'hysteria', 'configured': True})
        generated = adapter.configure.call_args.args[0]
        self.assertIsNotNone(generated.salamander)
        self.assertNotIn(generated.salamander, str(result))
        adapter.configure.reset_mock()
        for bad in ({**params, 'port': '443'}, {**params, 'salamander': 'yes'},
                    {**params, 'module': 'xray'}, {**params, 'port': 65536}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rpc.dispatch({**request, 'params': bad})
        adapter.configure.assert_not_called()

    def test_hysteria_change_passes_only_public_parameters(self):
        adapter = Mock()
        runtime = SimpleNamespace(adapters={'hysteria': adapter}, preview_configuration_locked=Mock())
        rpc = Application(os.geteuid(), lambda: runtime)
        params = {'module': 'hysteria', 'identity': 'example.org', 'port': 443,
                  'salamander': True, 'revision': 'a' * 64}
        self.assertEqual(rpc.dispatch({'version': CORE_API_VERSION, 'method': 'lifecycle.change_hysteria',
                                       'params': params}), {'module': 'hysteria', 'configured': True})
        self.assertEqual(adapter.change_settings.call_args.args[1:], (443, True, 'a' * 64))

    def test_hysteria_change_form_requires_csrf_and_confirmation(self):
        lifecycle = Mock()
        app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost']},
                         client=Mock(), package_client=Mock(), lifecycle_client=lifecycle)
        browser, origin = app.test_client(), 'https://localhost'
        with browser.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf='fixture-csrf')
        data = {'csrf': 'fixture-csrf', 'identity': 'example.org', 'port': '443', 'salamander': 'yes',
                'revision': 'a' * 64, 'confirm': 'yes'}
        self.assertEqual(browser.post('/modules/change_hysteria', data=data, base_url=origin).status_code, 403)
        self.assertEqual(browser.post('/modules/change_hysteria', data={**data, 'confirm': ''}, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.change_hysteria.assert_not_called()
        self.assertEqual(browser.post('/modules/change_hysteria', data=data, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.change_hysteria.assert_called_once_with('example.org', 443, True, 'a' * 64)

    def test_configuration_preview_checks_other_enabled_modules(self):
        inventory = Mock()
        inventory.installed.return_value = [{'module': 'xray', 'enabled': False},
                                            {'module': 'telemt', 'enabled': True}]
        existing = ModuleNetwork('telemt', routes=(Route('shared.example', Binding('tcp', '127.0.0.1', 2450)),))
        candidate = ModuleNetwork('xray', routes=(Route('shared.example', Binding('tcp', '127.0.0.1', 2444)),))
        lifecycle = Lifecycle(inventory, {'xray': Mock(), 'telemt': Mock(network=Mock(return_value=existing))},
                              Mock(), Mock(), site_names=())
        with self.assertRaises(NetworkConflict):
            lifecycle.preview_configuration_locked('xray', candidate)

    def test_xray_initialization_validates_fixed_profile(self):
        adapter = Mock()
        app_rpc = Application(os.geteuid(), lambda: SimpleNamespace(adapters={'xray': adapter}))
        params = {'module': 'xray', 'kind': 'reality-tcp', 'exposure': 'shared', 'sni': 'example.org',
                  'reality': 'external', 'external_host': 'example.org', 'path': None}
        request = {'version': CORE_API_VERSION, 'method': 'lifecycle.initialize_xray', 'params': params}
        self.assertEqual(app_rpc.dispatch(request), {'module': 'xray', 'configured': True})
        self.assertTrue(adapter.configure.call_args.kwargs['initial'])
        adapter.configure.reset_mock()
        for bad in ({**params, 'sni': 'bad;id'}, {**params, 'module': 'wireguard'},
                    {**params, 'external_host': 'bad/path'}, {**params, 'extra': 'id'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                app_rpc.dispatch({**request, 'params': bad})
        adapter.configure.assert_not_called()

    def test_xray_form_requires_csrf_and_confirmation(self):
        lifecycle = Mock()
        app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost']},
                         client=Mock(), package_client=Mock(), lifecycle_client=lifecycle)
        browser, origin = app.test_client(), 'https://localhost'
        with browser.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf='fixture-csrf')
        data = {'csrf': 'fixture-csrf', 'kind': 'reality-tcp', 'exposure': 'shared', 'sni': 'example.org',
                'reality': 'external', 'external_host': 'example.org', 'confirm': 'yes'}
        self.assertEqual(browser.post('/modules/initialize_xray', data=data, base_url=origin).status_code, 403)
        self.assertEqual(browser.post('/modules/initialize_xray', data={**data, 'confirm': ''}, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.initialize_xray.assert_not_called()
        self.assertEqual(browser.post('/modules/initialize_xray', data=data, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.initialize_xray.assert_called_once_with(kind='reality-tcp', exposure='shared', sni='example.org',
                                                         reality='external', external_host='example.org', path=None)
        lifecycle.initialize_xray.reset_mock()
        self.assertEqual(browser.post('/modules/initialize_xray', data={**data, 'profile_action': 'add'},
                                      base_url=origin, headers={'Origin': origin}).status_code, 303)
        lifecycle.initialize_xray.assert_called_once_with(kind='reality-tcp', exposure='shared', sni='example.org',
                                                         reality='external', external_host='example.org', path=None, add=True)
        lifecycle.initialize_xray.reset_mock()
        self.assertEqual(browser.post('/modules/initialize_xray',
                         data={**data, 'profile_action': 'replace', 'revision': 'a' * 64},
                         base_url=origin, headers={'Origin': origin}).status_code, 303)
        lifecycle.initialize_xray.assert_called_once_with(kind='reality-tcp', exposure='shared', sni='example.org',
                             reality='external', external_host='example.org', path=None, revision='a' * 64)
        removed = {'csrf': 'fixture-csrf', 'kind': 'reality-tcp', 'revision': 'a' * 64, 'confirm': 'yes'}
        self.assertEqual(browser.post('/modules/remove_xray', data={**removed, 'confirm': ''},
                         base_url=origin, headers={'Origin': origin}).status_code, 303)
        lifecycle.remove_xray.assert_not_called()
        self.assertEqual(browser.post('/modules/remove_xray', data=removed, base_url=origin,
                                      headers={'Origin': origin}).status_code, 303)
        lifecycle.remove_xray.assert_called_once_with('reality-tcp', 'a' * 64)

    def test_tunnel_initialization_is_allowlisted_and_preserves_keys_in_rpc(self):
        adapter = Mock()
        generated = object()
        adapter.runtime.initial_state.return_value = generated
        runtime = SimpleNamespace(adapters={'wireguard': adapter, 'amneziawg': adapter})
        app_rpc = Application(os.geteuid(), lambda: runtime)

        def request(module, egress, **extra):
            return {'version': CORE_API_VERSION, 'method': 'lifecycle.initialize',
                    'params': {'module': module, 'egress': egress, **extra}}

        for item, error in ((request('xray', None), 'invalid_request'),
                            (request('wireguard', 'eth0;id'), 'tunnel_egress_invalid'),
                            (request('amneziawg', 'lo'), 'tunnel_egress_invalid'),
                            (request('wireguard', 'a' * 16), 'tunnel_egress_invalid'),
                            (request('wireguard', None, command='id'), 'invalid_request')):
            with self.subTest(item=item), self.assertRaisesRegex(ValueError, error):
                app_rpc.dispatch(item)
        adapter.runtime.initial_state.assert_not_called()
        result = app_rpc.dispatch(request('amneziawg', 'eth0'))
        self.assertEqual(result, {'module': 'amneziawg', 'configured': True, 'internet_requested': True})
        adapter.runtime.initial_state.assert_called_once_with(egress='eth0')
        adapter.configure.assert_called_once_with(generated, initial=True)
        self.assertNotIn('secret', json.dumps(result))

    def test_tunnel_initialization_requires_session_csrf_and_confirmation(self):
        lifecycle = Mock()
        lifecycle.initialize_tunnel.return_value = {'configured': True, 'internet_requested': False}
        app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost']},
                         client=Mock(), package_client=Mock(), lifecycle_client=lifecycle)
        browser, origin = app.test_client(), 'https://localhost'

        def post(csrf='fixture-csrf', confirm='yes'):
            return browser.post('/modules/initialize', base_url=origin, headers={'Origin': origin},
                                data={'module': 'wireguard', 'egress': '', 'csrf': csrf, 'confirm': confirm})

        self.assertEqual(post().status_code, 303)
        with browser.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf='fixture-csrf')
        self.assertEqual(post(csrf='bad').status_code, 403)
        self.assertEqual(post(confirm='').status_code, 303)
        lifecycle.initialize_tunnel.assert_not_called()
        self.assertEqual(post().status_code, 303)
        lifecycle.initialize_tunnel.assert_called_once_with('wireguard', None)

    def test_unix_rejects_unauthorized_uid_extra_parameters_and_trailing_body(self):
        runtime = Runtime()
        uid = os.geteuid()
        payload = {'version': CORE_API_VERSION, 'method': 'lifecycle.enable', 'params': {'module': 'xray'}}

        def exchange(web_uid, request, tail=b''):
            server, client = socket.socketpair()
            with server, client:
                app = Application(web_uid, lambda: runtime)
                worker = Thread(target=app.handle, args=(server,), daemon=True)
                worker.start()
                client.sendall(json.dumps(request).encode() + b'\n' + tail)
                client.shutdown(socket.SHUT_WR)
                with client.makefile('rb') as stream:
                    response = json.loads(stream.readline())
                worker.join(2)
                self.assertFalse(worker.is_alive())
                return response

        self.assertEqual(exchange(uid + 1, payload)['error'], 'forbidden')
        self.assertEqual(exchange(uid, payload, b'body')['error'], 'invalid_request')
        self.assertEqual(exchange(uid, payload | {'params': {'module': 'xray', 'unit': 'ssh.service'}})['error'],
                         'invalid_request')
        self.assertEqual(exchange(uid, payload | {'method': 'lifecycle.shell'})['error'], 'invalid_request')
        self.assertEqual(runtime.calls, [])

    def test_authenticated_portal_enable_disable_and_upgrade(self):
        runtime = Runtime()
        app_rpc = Application(os.geteuid(), lambda: runtime)
        with TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as listener:
            path = Path(directory) / 'lifecycle.sock'
            listener.bind(str(path))
            listener.listen(2)
            listener.settimeout(5)

            def serve():
                for _ in range(4):
                    connection, _ = listener.accept()
                    with connection:
                        app_rpc.handle(connection)

            worker = Thread(target=serve, daemon=True)
            worker.start()
            app = create_app({'session_key': 'fixture-only', 'allowed_hosts': ['localhost']}, client=object(),
                             package_client=runtime, lifecycle_client=LifecycleClient(path, timeout=3))
            browser = app.test_client()
            origin = 'https://localhost'

            def post(action, csrf='fixture-csrf', confirm='yes', module='xray'):
                return browser.post(f'/modules/{action}', base_url=origin, headers={'Origin': origin},
                                    data={'module': module, 'csrf': csrf, 'ticket': 'a' * 64, 'confirm': confirm})

            self.assertEqual(post('enable').status_code, 303)
            with browser.session_transaction(base_url=origin) as session:
                session.update(admin=True, csrf='fixture-csrf')
            self.assertEqual(post('enable', csrf='wrong').status_code, 403)
            self.assertEqual(post('enable', confirm='').status_code, 303)
            self.assertEqual(runtime.calls, [])
            self.assertEqual(post('enable').status_code, 303)
            self.assertTrue(runtime.enabled)
            self.assertEqual(post('upgrade').status_code, 303)
            self.assertEqual(post('disable').status_code, 303)
            self.assertFalse(runtime.enabled)
            missing = Capability('6.12.1-fixture', False, False, None, '3.1.20260812', (),
                                 'amneziawg_kernel_headers_missing')
            with patch('v5.core.lifecycle.rpc.capability', return_value=missing):
                diagnostic = post('diagnostics', confirm='', module='amneziawg')
            self.assertEqual(diagnostic.status_code, 200)
            self.assertIn(b'6.12.1-fixture', diagnostic.data)
            self.assertIn('заголовки текущего ядра отсутствуют'.encode(), diagnostic.data)
            worker.join(2)
            self.assertFalse(worker.is_alive())
        self.assertEqual(runtime.calls, [('change', 'xray', True), ('upgrade', 'xray', 'a' * 64),
                                         ('change', 'xray', False)])
