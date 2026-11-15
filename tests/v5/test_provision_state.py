"""Ограниченный журнал фоновой установки зависимостей."""

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from v5.core.packages.debian_provision import ProvisionError
from v5.core.packages.provision_state import ProvisionJournal


class ProvisionJournalTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = ProvisionJournal(self.root, clock=lambda: 1234)

    def test_queue_requires_known_module_and_serializes(self):
        for value in ('../wireguard', 'docker.io', None, []):
            with self.subTest(value=value), self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
                self.store.queue(value)
        first = self.store.queue('wireguard')
        self.assertEqual(first['status'], 'queued')
        self.assertEqual(len(first['ticket']), 64)
        with self.assertRaisesRegex(ProvisionError, 'provision_busy'):
            self.store.queue('xray')
        self.assertEqual(self.store.get(), first)
        self.assertEqual((self.root / 'job.json').stat().st_mode & 0o777, 0o600)

    def test_only_valid_transitions_and_matching_ticket(self):
        job = self.store.queue('wireguard')
        ticket = job['ticket']
        for expected, status, code in (('queued', 'ready', 'ok'), ('queued', 'running', 'provision_failed'),
                                       ('running', 'failed', 'ok'), ('running', 'ready', [])):
            with self.subTest(status=status), self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
                self.store.transition(ticket, expected, status, code)
        with self.assertRaisesRegex(ProvisionError, 'provision_busy'):
            self.store.transition('a' * 64, 'queued', 'running', 'ok')
        self.store.transition(ticket, 'queued', 'running', 'ok')
        self.store.transition(ticket, 'running', 'failed', 'provision_install_incomplete')
        second = self.store.queue('xray')
        self.assertNotEqual(second['ticket'], ticket)
        self.store.transition(second['ticket'], 'queued', 'running', 'ok')
        self.store.transition(second['ticket'], 'running', 'ready', 'ok')
        self.assertEqual(self.store.get()['status'], 'ready')

    def test_rejects_unsafe_or_corrupt_journal_and_lock(self):
        path = self.root / 'job.json'
        path.write_text(json.dumps({'ticket': 'a' * 64, 'module': 'wireguard', 'status': 'failed',
                                    'code': [], 'updated': 1}))
        path.chmod(0o600)
        with self.assertRaisesRegex(ProvisionError, 'provision_failed'):
            self.store.get()
        path.unlink()
        target = self.root / 'other'
        target.write_text('unchanged')
        (self.root / '.lock').symlink_to(target)
        with self.assertRaises(OSError):
            self.store.queue('wireguard')
        self.assertEqual(target.read_text(), 'unchanged')

    def test_failed_and_incomplete_results_cannot_be_marked_ready(self):
        job = self.store.queue('wireguard')
        self.store.transition(job['ticket'], 'queued', 'running', 'ok')
        with self.assertRaisesRegex(ProvisionError, 'invalid_provision_request'):
            self.store.transition(job['ticket'], 'running', 'ready', 'provision_install_incomplete')
        self.assertEqual(self.store.get()['status'], 'running')
