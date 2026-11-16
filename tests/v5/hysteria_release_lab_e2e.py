"""Проверить подписанный Hysteria2 на отдельной Debian 13 через портал."""

import sys
from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 22069
    if port not in (22068, 22069):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    for name in ('check_debian_core.py', 'check_tls_gateway.py', 'check_hysteria_release_toggle.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    archive = Path('output/v5-release-candidate-5.0.3-readytest/kvn-module-hysteria-2.13.0.tar.gz')
    lab.upload(archive, f'{STAGE}/hysteria-release.tar.gz')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u '
            f'{STAGE}/check_hysteria_release_toggle.py {STAGE}/hysteria-release.tar.gz',
            timeout=1200, capture=False)


if __name__ == '__main__':
    main()
