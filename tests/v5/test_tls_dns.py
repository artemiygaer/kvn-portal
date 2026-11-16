"""Ограниченная диагностика зарегистрированных DNS-имён."""

import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from v5.core.agent import AgentApplication
from v5.core.tls.dns import diagnose
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.queue import TLSQueue


class DNSDiagnosticsTests(TestCase):
    def test_matching_mismatching_timeout_and_invalid_result(self):
        name, server = TLSIdentity('portal.example', False), TLSIdentity('192.0.2.8', True)
        answer = '192.0.2.8 STREAM portal.example\n192.0.2.8 DGRAM\n192.0.2.9 STREAM\n'
        result = diagnose(name, server, query=lambda _: answer)
        self.assertEqual(result['status'], 'match')
        self.assertEqual(result['addresses'], ['192.0.2.8', '192.0.2.9'])
        self.assertEqual(diagnose(name, server, query=lambda _: '198.51.100.1 STREAM')['status'], 'mismatch')
        self.assertEqual(diagnose(name, server, query=lambda _: 'bad STREAM')['status'], 'unavailable')
        def timeout(_):
            raise subprocess.TimeoutExpired('fixture', 5)
        self.assertEqual(diagnose(name, server, query=timeout)['status'], 'timeout')

    def test_only_registered_dns_can_be_queued(self):
        name, server = TLSIdentity('portal.example', False), TLSIdentity('192.0.2.8', True)
        with TemporaryDirectory() as directory:
            queue = TLSQueue(Path(directory))
            app = AgentApplication(123, tls=queue, tls_registry=lambda: ((server, name), False))
            request = {'version': 1, 'method': 'tls.diagnose', 'params': {'name': name.name}}
            self.assertEqual(app.dispatch(124, request)['error'], 'forbidden')
            for invalid in ('unknown.example', server.name, 'portal.example;id'):
                self.assertEqual(app.dispatch(123, {**request, 'params': {'name': invalid}})['error'], 'invalid_request')
            self.assertTrue(app.dispatch(123, request)['ok'])
            self.assertEqual(app.dispatch(123, request)['error'], 'tls_busy')
            with queue.exclusive():
                self.assertEqual(queue.take((server, name)).identity, name)
