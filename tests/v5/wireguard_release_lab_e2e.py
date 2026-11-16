"""Проверить установку и переключение подписанного WireGuard на Debian 13 VM."""

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
    for name in ('check_debian_core.py', 'check_wireguard_release.py', 'check_awg_release_toggle.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    archive = Path('output/v5-release-candidate-5.0.3-readytest/kvn-module-wireguard-1.0.0.tar.gz')
    lab.upload(archive, f'{STAGE}/wireguard-release.tar.gz')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_wireguard_release.py '
            f'{STAGE}/wireguard-release.tar.gz', timeout=1500, capture=False)
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_awg_release_toggle.py wireguard',
            timeout=600, capture=False)


if __name__ == '__main__':
    main()
