import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from v5.core.contracts import CORE_API_VERSION
from v5.core.maintenance.portal_rpc import PortalUpdateApplication
from v5.core.packages.debian_provision import ProvisionError
from v5.core.packages.provision_state import ProvisionJournal


class ProvisionRpcTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 100
        self.journal = ProvisionJournal(Path(self.tmp.name), clock=lambda: self.now)
        self.launch = Mock()
        self.probe = Mock(return_value=True)
        self.app = PortalUpdateApplication(1000, Mock(), provision=self.journal,
                                           provision_launch=self.launch, provision_probe=self.probe)

    def request(self, method, params):
        return self.app.dispatch({'version': CORE_API_VERSION, 'method': method, 'params': params}, io.BytesIO())

    def test_start_and_status_do_not_expose_ticket(self):
        self.assertEqual(self.request('core.provision_start', {'module': 'wireguard'}),
                         {'module': 'wireguard', 'status': 'queued'})
        self.launch.assert_called_once_with(self.journal.get()['ticket'])
        job = self.request('core.provision_status', {})['job']
        self.assertEqual(job['status'], 'queued')
        self.assertNotIn('ticket', job)
        with self.assertRaises(ProvisionError):
            self.request('core.provision_start', {'module': 'xray'})

    def test_failed_launch_and_dead_job_are_reported(self):
        self.launch.side_effect = OSError()
        with self.assertRaises(ProvisionError):
            self.request('core.provision_start', {'module': 'xray'})
        self.assertEqual(self.journal.get()['status'], 'failed')
        self.launch.side_effect = None
        self.request('core.provision_start', {'module': 'mtg'})
        self.now += 11
        self.probe.return_value = False
        self.assertEqual(self.request('core.provision_status', {})['job']['code'], 'provision_unconfirmed')

    def test_unknown_probe_never_marks_running_job_failed(self):
        self.request('core.provision_start', {'module': 'xray'})
        self.now += 600
        self.probe.return_value = None
        self.assertEqual(self.request('core.provision_status', {})['job']['status'], 'queued')


if __name__ == '__main__':
    unittest.main()
