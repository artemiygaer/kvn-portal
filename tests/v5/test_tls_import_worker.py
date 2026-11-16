"""Безопасность фонового импорта TLS без реальных сертификатов."""

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.tls.acme_service import AcmeResult
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.queue import TLSImportJob
from v5.core.tls import worker
from v5.core.tls.transaction import GatewayApplyError, _pair_digest


class ImportWorkerTests(TestCase):
    def test_failed_gateway_migration_does_not_consume_pending_job(self):
        queue, gateway = Mock(), Mock()
        queue.exclusive.return_value = nullcontext()
        gateway.reconcile_config.side_effect = ValueError('fixture')
        with patch.object(worker, 'TLSQueue', return_value=queue), \
             patch.object(worker, 'registry', return_value=((TLSIdentity('portal.example', False),), False)), \
             patch.object(worker, 'GatewayController', return_value=gateway), \
             patch.object(worker, 'CertificateStore'):
            with self.assertRaises(ValueError):
                worker.run(renew=False)
        queue.take.assert_not_called()

    def test_import_records_only_safe_status_and_never_secret(self):
        identity = TLSIdentity('portal.example', False)
        job = TLSImportJob(identity, b'chain-fixture', b'secret-key-fixture')
        queue = Mock()
        queue.exclusive.return_value = nullcontext()
        queue.take.return_value = job
        queue.results = Path('/nonexistent/fixture')
        gateway = Mock()
        gateway.active.return_value = ()
        service = Mock()
        service.import_pair.return_value = AcmeResult('active', datetime(2027, 1, 1, tzinfo=timezone.utc))
        with patch.object(worker, 'TLSQueue', return_value=queue), \
             patch.object(worker, 'registry', return_value=((identity,), False)), \
             patch.object(worker, 'read_json', return_value={}), \
             patch.object(worker, 'GatewayController', return_value=gateway), \
             patch.object(worker, 'CertificateStore'), patch.object(worker, 'AcmeService', return_value=service), \
             patch.object(worker, 'validate_pair'), patch.object(worker.imported, 'load', return_value={}), \
             patch.object(worker.imported, 'save'):
            worker.run(renew=False)
        service.import_pair.assert_called_once_with(identity, job.chain, job.key)
        records = queue.record.call_args.args[0]
        self.assertEqual(records[identity.slot]['import']['status'], 'active')
        self.assertNotIn('secret-key-fixture', repr(records))

    def test_uncertain_apply_keeps_old_and_new_imported_generations_protected(self):
        identity = TLSIdentity('portal.example', False)
        job = TLSImportJob(identity, b'chain-fixture', b'secret-key-fixture')
        old = 'a' * 64
        queue, gateway, service = Mock(), Mock(), Mock()
        queue.exclusive.return_value = nullcontext()
        queue.take.return_value, queue.results = job, Path('/nonexistent/fixture')
        gateway.generation.return_value = old
        gateway.active.return_value = ()
        service.import_pair.side_effect = GatewayApplyError('rollback_unconfirmed', 'fixture')
        saved = []
        with patch.object(worker, 'TLSQueue', return_value=queue), \
             patch.object(worker, 'registry', return_value=((identity,), False)), \
             patch.object(worker, 'read_json', return_value={}), \
             patch.object(worker, 'GatewayController', return_value=gateway), \
             patch.object(worker, 'CertificateStore'), patch.object(worker, 'AcmeService', return_value=service), \
             patch.object(worker, 'validate_pair'), patch.object(worker.imported, 'load', return_value={identity.slot: [old]}), \
             patch.object(worker.imported, 'save', side_effect=lambda value: saved.append(deepcopy(value))):
            worker.run(renew=False)
        self.assertEqual(saved, [{identity.slot: [old, _pair_digest(job.chain, job.key)]}])
        self.assertEqual(queue.record.call_args.args[0][identity.slot]['import']['status'], 'rollback_unconfirmed')
