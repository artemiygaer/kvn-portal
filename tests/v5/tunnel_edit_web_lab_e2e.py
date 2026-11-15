"""Проверка редактирования туннеля на изолированной Debian VM в WSL."""

from pathlib import Path
import sys

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    lab.run('set -eu; test -f /var/lib/kvn-v5/modules/wireguard/settings.json; '
            '! ip link show wg0 >/dev/null 2>&1')
    if '--reuse-stage' not in sys.argv:
        stage_candidate(lab)
        lab.run(f'cd {INSTALLED}; tar -xzf {STAGE}/candidate.tar.gz --no-same-owner --no-same-permissions '
                'v5/modules/host_tunnel')
    for name in ('check_debian_core.py', 'check_tunnel_edit_web.py', 'refresh_clean_gateway.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 {STAGE}/refresh_clean_gateway.py')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_tunnel_edit_web.py',
            timeout=900, capture=False)


if __name__ == '__main__':
    main()
