"""Проверить фактическое переиздание и применение TLS на выделенном стенде."""

import ipaddress
import os
from pathlib import Path
import socket
import subprocess
import sys

from v5.core.tls.acme import AcmeMode, AcmePlan
from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore


def main():
    if len(sys.argv) != 5 or os.geteuid() != 0:
        return 2
    ip, domain, hostname, container = sys.argv[1:]
    if not ipaddress.ip_address(ip).is_global or socket.gethostname() != hostname:
        raise RuntimeError('Идентичность стенда не совпала')
    names, ipv6 = registry()
    identities = tuple(item for item in names if item.name in (ip, domain))
    if len(identities) != 2:
        raise RuntimeError('Не найдены DNS и IP выбранного стенда')
    gateway = GatewayController(GATEWAY_ROOT / 'nginx.conf', CertificateStore(GATEWAY_ROOT / 'certs'), names, ipv6=ipv6)
    before = {item: gateway.generation(item) for item in identities}
    if any(value is None for value in before.values()):
        raise RuntimeError('Нет действующих сертификатов для проверки')
    for identity in identities:
        plan = AcmePlan(identity, AcmeMode.PUBLIC)
        # Принудительное переиздание только двух тестовых lineages; stdout может содержать лишние детали.
        result = subprocess.run([*plan.renew(), '--force-renewal'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240, check=False)
        if result.returncode:
            raise RuntimeError('Принудительное тестовое переиздание не подтвердилось')
    subprocess.run(['/usr/bin/systemctl', 'start', 'kvn-v5-tls-renew.service'], check=True, timeout=300)
    after = {item: gateway.generation(item) for item in identities}
    if any(after[item] == before[item] for item in identities):
        raise RuntimeError('Служба продления не применила оба новых сертификата')
    for pair in gateway.active():
        if pair.metadata.identity in identities:
            verify_pair(pair)
    state = subprocess.run(['/usr/bin/docker', 'inspect', '--format', '{{.State.Running}}', container],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=True, text=True, timeout=15).stdout.strip()
    if state != 'true':
        raise RuntimeError('Контейнер наблюдения недоступен после проверки')
    print('DNS и IP: фактическое переиздание и применение службой продления подтверждены.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
