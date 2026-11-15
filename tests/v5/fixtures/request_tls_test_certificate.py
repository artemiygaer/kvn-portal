"""Поставить тестовый ACME-выпуск в штатную очередь выделенного стенда."""

import argparse
import os
from pathlib import Path
import socket

from v5.core.tls.queue import TLSJob, TLSQueue, registry


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--mode', required=True, choices=('staging', 'public'))
    parser.add_argument('--allow-external-test', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or socket.gethostname() != args.hostname:
        raise RuntimeError('Не совпадают root-доступ или имя выделенного стенда')
    instance = Path('/var/lib/cloud/data/instance-id')
    isolated = instance.is_file() and instance.read_text().strip() == 'kvn-v5-isolated-001'
    if not isolated and not args.allow_external_test:
        raise RuntimeError('Внешний тестовый стенд требует явного флага')
    identities, _ = registry()
    job = TLSJob.parse({'name': args.name, 'mode': args.mode, 'email': ''}, identities)
    TLSQueue().submit(job)
    print('Задача поставлена в штатную очередь без email.')


if __name__ == '__main__':
    main()
