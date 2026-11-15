import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import Mock, patch

from v5.core.packages.debian_provision import Debian, ProvisionError
from v5.core.packages.provision_state import ProvisionJournal
from v5.core.packages.provision_worker import perform, prepare


class ProvisionWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = ProvisionJournal(Path(self.temp.name))

    @patch('v5.core.packages.provision_worker.audit.record')
    def test_success_is_recorded(self, audit):
        job = self.journal.queue('wireguard')
        calls = []
        self.assertTrue(perform(job['ticket'], self.journal, executor=calls.append))
        self.assertEqual(calls, ['wireguard'])
        self.assertEqual(self.journal.get()['status'], 'ready')
        audit.assert_called_once_with('provision.prepare', True, 'wireguard')

    @patch('v5.core.packages.provision_worker.audit.record')
    def test_known_failure_is_recorded(self, audit):
        job = self.journal.queue('xray')

        def fail(_module):
            raise ProvisionError('docker_unavailable')

        self.assertFalse(perform(job['ticket'], self.journal, executor=fail))
        self.assertEqual(self.journal.get()['code'], 'docker_unavailable')
        audit.assert_called_once_with('provision.prepare', False, 'xray')

    @patch('v5.core.packages.provision_worker.audit.record')
    def test_unexpected_failure_does_not_leak_details(self, _audit):
        job = self.journal.queue('mtg')

        def fail(_module):
            raise RuntimeError('секретные диагностические данные')

        self.assertFalse(perform(job['ticket'], self.journal, executor=fail))
        self.assertEqual(self.journal.get()['code'], 'provision_failed')
        self.assertNotIn('секретные', str(self.journal.get()))

    def test_unrecognized_module_rejected_before_access(self):
        with self.assertRaises(ProvisionError):
            prepare(['wireguard'])

    def test_foreign_daemon_is_never_replaced(self):
        (Path(self.temp.name) / 'registry.sqlite3').touch()
        packages = Mock()
        packages.runtime_guard.return_value = nullcontext()
        packages.installed.return_value = [{'module': 'xray', 'enabled': False}]
        with patch('v5.core.packages.provision_worker.PACKAGE_STATE', Path(self.temp.name)), \
             patch('v5.core.packages.provision_worker.parse_os_release', return_value=Debian('13', 'trixie')), \
             patch('v5.core.packages.provision_worker.PackageRegistry', return_value=packages), \
             patch('v5.core.packages.provision_worker.load_publisher'), \
             patch('v5.core.packages.provision_worker.trusted_tool', return_value=None), \
             patch('v5.core.packages.provision_worker._existing', side_effect=[True, False]), \
             patch('v5.core.packages.provision_worker._debian_docker_daemon', return_value=False), \
             patch('v5.core.packages.provision_worker.run_apt_transaction') as install:
            with self.assertRaisesRegex(ProvisionError, 'provision_existing_tools'):
                prepare('xray')
            install.assert_not_called()

    def test_existing_debian13_daemon_only_receives_missing_cli(self):
        (Path(self.temp.name) / 'registry.sqlite3').touch()
        packages = Mock()
        packages.runtime_guard.return_value = nullcontext()
        packages.installed.return_value = [{'module': 'xray', 'enabled': False}]
        with patch('v5.core.packages.provision_worker.PACKAGE_STATE', Path(self.temp.name)), \
             patch('v5.core.packages.provision_worker.parse_os_release', return_value=Debian('13', 'trixie')), \
             patch('v5.core.packages.provision_worker.PackageRegistry', return_value=packages), \
             patch('v5.core.packages.provision_worker.load_publisher'), \
             patch('v5.core.packages.provision_worker.trusted_tool', return_value=None), \
             patch('v5.core.packages.provision_worker._existing', side_effect=[True, False]), \
             patch('v5.core.packages.provision_worker._debian_docker_daemon', return_value=True), \
             patch('v5.core.packages.provision_worker._docker_ready', return_value=True), \
             patch('v5.core.packages.provision_worker.run_apt_transaction') as install:
            prepare('xray')
            install.assert_called_once_with(Debian('13', 'trixie'), ('docker-cli',))

    def test_awg_existing_legacy_is_never_replaced(self):
        (Path(self.temp.name) / 'registry.sqlite3').touch()
        packages = Mock()
        packages.runtime_guard.return_value = nullcontext()
        packages.installed.return_value = [{'module': 'amneziawg', 'enabled': False}]
        with patch('v5.core.packages.provision_worker.PACKAGE_STATE', Path(self.temp.name)), \
             patch('v5.core.packages.provision_worker.parse_os_release', return_value=Debian('13', 'trixie')), \
             patch('v5.core.packages.provision_worker.PackageRegistry', return_value=packages), \
             patch('v5.core.packages.provision_worker.load_publisher'), \
             patch('v5.core.packages.provision_worker.capability', return_value=Mock(issue=None, profiles=('legacy',), module_available=True)), \
             patch('v5.core.packages.provision_worker._existing', return_value=True), \
             patch('v5.core.packages.provision_worker.run_awg_transaction') as install:
            with self.assertRaisesRegex(ProvisionError, 'provision_existing_tools'):
                prepare('amneziawg')
            install.assert_not_called()

    def test_awg_new_install_requires_real_31_capability_after_apt(self):
        (Path(self.temp.name) / 'registry.sqlite3').touch()
        packages = Mock()
        packages.runtime_guard.return_value = nullcontext()
        packages.installed.return_value = [{'module': 'amneziawg', 'enabled': False}]
        absent = Mock(issue='amneziawg_tools_missing', profiles=(), module_available=False)
        legacy = Mock(issue=None, profiles=('legacy',), module_available=True)
        with patch('v5.core.packages.provision_worker.PACKAGE_STATE', Path(self.temp.name)), \
             patch('v5.core.packages.provision_worker.parse_os_release', return_value=Debian('13', 'trixie')), \
             patch('v5.core.packages.provision_worker.PackageRegistry', return_value=packages), \
             patch('v5.core.packages.provision_worker.load_publisher'), \
             patch('v5.core.packages.provision_worker.capability', side_effect=[absent, legacy]), \
             patch('v5.core.packages.provision_worker._existing', return_value=False), \
             patch('v5.core.packages.provision_worker._awg_package_present', return_value=False), \
             patch('v5.core.packages.provision_worker.run_awg_transaction') as install:
            with self.assertRaisesRegex(ProvisionError, 'amneziawg_profile_unsupported'):
                prepare('amneziawg')
            install.assert_called_once()


if __name__ == '__main__':
    unittest.main()
