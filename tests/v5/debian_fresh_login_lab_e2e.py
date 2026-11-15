"""Повторить HTTPS-вход с новым синтетическим паролем на учебной VM."""

from pathlib import Path
import secrets
import sys

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 22069
    if port not in (22068, 22069):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    fixture = Path('tests/v5/fixtures/reset_lab_password.py')
    target = '/var/tmp/kvn-v5-phase2/reset_lab_password.py'
    lab.upload(fixture, target)
    password = secrets.token_urlsafe(24)
    lab.run(f'cd /usr/local/lib/kvn-v5; PYTHONPATH=. python3 -u {target}',
            data=password.encode(), timeout=180, capture=False)
    lab.probe(password)


if __name__ == '__main__':
    main()
