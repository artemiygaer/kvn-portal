"""Пересылка включается только подтверждённой ограниченной операцией."""

from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.contracts import CORE_API_VERSION
from v5.core.maintenance import portal_rpc
from v5.core.maintenance.portal_store import UpdateStoreError
from v5.core.packages.manifest import PackageError
from v5.portal.app import create_app


class ForwardingTests(TestCase):
    def test_service_changes_only_fixed_forwarding_key(self):
        unit = (Path(__file__).resolve().parents[2] / 'v5/install/systemd/kvn-v5-forwarding.service').read_text()
        self.assertIn("/proc/sys/net/ipv4/ip_forward", unit)
        self.assertIn('ReadOnlyPaths=/proc/sys', unit)
        self.assertIn('ReadWritePaths=/proc/sys/net/ipv4/ip_forward', unit)
        self.assertNotIn('-m v5.', unit)

    def test_enable_requires_signed_installed_tunnel_with_egress(self):
        inventory = Mock()
        inventory.runtime_guard.return_value = nullcontext()
        inventory.installed.return_value = [{'module': 'wireguard'}]
        state = SimpleNamespace(settings=SimpleNamespace(egress=None))
        with patch('v5.core.packages.registry.PackageRegistry', return_value=inventory), \
             patch('v5.core.packages.signature.load_publisher'), \
             patch('v5.modules.host_tunnel.state.State.load', return_value=state), \
             patch.object(portal_rpc.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run, \
             patch.object(portal_rpc, '_forwarding_status', return_value={'active': True, 'persistent': True}):
            with self.assertRaisesRegex(UpdateStoreError, 'forwarding_egress_required'):
                portal_rpc._enable_forwarding('wireguard')
            run.assert_not_called()
            state.settings.egress = 'eth0'
            self.assertEqual(portal_rpc._enable_forwarding('wireguard'), {'active': True, 'persistent': True})
            inventory.verified_install.assert_called_with('wireguard')
            self.assertEqual([call.args[0][1:] for call in run.call_args_list],
                             [['start', 'kvn-v5-forwarding.service'], ['enable', 'kvn-v5-forwarding.service']])
            run.reset_mock()
            inventory.verified_install.side_effect = PackageError('invalid_package_signature')
            with self.assertRaisesRegex(PackageError, 'invalid_package_signature'):
                portal_rpc._enable_forwarding('wireguard')
            run.assert_not_called()
            with self.assertRaisesRegex(UpdateStoreError, 'invalid_request'):
                portal_rpc._enable_forwarding('xray')

    def test_rpc_accepts_only_known_module_and_no_extra_parameters(self):
        enable_call = Mock(return_value={'active': True, 'persistent': True})
        app = portal_rpc.PortalUpdateApplication(1, Mock(), forwarding_enable=enable_call)
        base = {'version': CORE_API_VERSION, 'method': 'core.forwarding_enable'}
        with self.assertRaisesRegex(UpdateStoreError, 'invalid_request'):
            app.dispatch({**base, 'params': {'module': 'xray'}}, BytesIO())
        with self.assertRaisesRegex(UpdateStoreError, 'invalid_request'):
            app.dispatch({**base, 'params': {'module': 'wireguard', 'command': 'id'}}, BytesIO())
        enable_call.assert_not_called()
        app.dispatch({**base, 'params': {'module': 'amneziawg'}}, BytesIO())
        enable_call.assert_called_once_with('amneziawg')

    def test_web_requires_origin_csrf_and_explicit_confirmation(self):
        updates = Mock()
        app = create_app({'session_key': 'fixture', 'allowed_hosts': ['localhost']},
                         client=Mock(), package_client=Mock(), lifecycle_client=Mock(), core_update_client=updates)
        browser, origin = app.test_client(), 'https://localhost'
        with browser.session_transaction(base_url=origin) as state:
            state.update(admin=True, csrf='fixture')
        data = {'csrf': 'fixture', 'module': 'wireguard', 'confirm': 'yes'}
        self.assertEqual(browser.post('/modules/forwarding', base_url=origin, data=data).status_code, 403)
        self.assertEqual(browser.post('/modules/forwarding', base_url=origin, headers={'Origin': origin},
                                      data={**data, 'confirm': ''}).status_code, 303)
        updates.forwarding_enable.assert_not_called()
        self.assertEqual(browser.post('/modules/forwarding', base_url=origin, headers={'Origin': origin},
                                      data=data).status_code, 303)
        updates.forwarding_enable.assert_called_once_with('wireguard')
