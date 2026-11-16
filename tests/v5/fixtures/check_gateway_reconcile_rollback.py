"""Реальный откат nginx при отказе проверки новой конфигурации только в VM."""

from pathlib import Path
from unittest.mock import patch

from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_gateway_revision
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, GatewayApplyError


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    identities, ipv6 = registry()
    config = GATEWAY_ROOT / 'nginx.conf'
    previous = config.read_bytes()
    gateway = GatewayController(config, CertificateStore(GATEWAY_ROOT / 'certs'), identities, ipv6=ipv6)
    calls = []

    def verify(data):
        calls.append(data)
        if len(calls) == 1:
            raise OSError('синтетический отказ проверки кандидата')
        verify_gateway_revision(data, GATEWAY_ROOT / 'bootstrap.crt')

    with patch.object(gateway, '_render', return_value=previous + b'\n# isolated rollback test\n'):
        try:
            gateway.reconcile_config(check=check_nginx, reload=reload_nginx, verify_loaded=verify)
            raise AssertionError('Синтетический отказ не вызвал откат')
        except GatewayApplyError as exc:
            assert exc.code == 'apply_rolled_back', exc.code
    assert calls[1] == previous and config.read_bytes() == previous
    print('nginx: отказ проверки новой конфигурации восстановил прежнюю ревизию.', flush=True)


if __name__ == '__main__':
    main()
