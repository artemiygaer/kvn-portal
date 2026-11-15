"""Без изменения активного шлюза проверить подготовленную конфигурацию nginx."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from v5.core.tls.controller import GatewayController
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0 or socket.gethostname() != sys.argv[1]:
        return 2
    names, ipv6 = registry()
    identity = next(item for item in names if item.name == sys.argv[2])
    store = CertificateStore(GATEWAY_ROOT / 'certs')
    generations = [path for path in (store.directory / identity.slot).iterdir() if path.is_dir()]
    if len(generations) != 1:
        raise RuntimeError('Ожидалось одно подготовленное поколение')
    pair = store.load(identity, generations[0].name)
    gateway = GatewayController(GATEWAY_ROOT / 'nginx.conf', store, names, ipv6=ipv6)
    _, records, network = gateway._snapshot()
    records[identity.slot] = generations[0].name
    candidate = gateway._render(records, network, gateway._pairs(records))
    with tempfile.NamedTemporaryFile(prefix='.kvn-diagnostic-', dir=GATEWAY_ROOT) as output:
        output.write(candidate)
        output.flush()
        for prefix in ([], ['/usr/bin/setpriv', '--bounding-set=-all']):
            result = subprocess.run([*prefix, '/usr/sbin/nginx', '-e', 'stderr', '-t', '-c', output.name],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=25)
            print('caps=' + ('none' if prefix else 'normal') + ' exit=' + str(result.returncode), flush=True)
            print(result.stdout[-2500:], flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
