"""E2E настройки Xray на изолированной Debian VM в WSL."""

from pathlib import Path
import sys

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 22063
    if port not in (22063, 22068):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    lab.run('test ! -e /var/lib/kvn-v5/modules/xray/settings.json')
    if port == 22063:
        stage_candidate(lab)
        lab.run(f'cd {INSTALLED}; tar -xzf {STAGE}/candidate.tar.gz --no-same-owner --no-same-permissions v5/modules/xray')
    for name in ('check_debian_core.py', 'check_xray_settings_web.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_xray_settings_web.py',
            timeout=300, capture=False)


if __name__ == '__main__':
    main()
