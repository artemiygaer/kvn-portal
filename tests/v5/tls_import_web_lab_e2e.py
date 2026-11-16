"""Проверить TLS-импорт и DNS через панель изолированной Debian 12."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22070, ROOT)
    lab.wait()
    assert lab.run(f'cat {INSTALLED}/core-version').stdout.strip() == b'5.0.3'
    for name in ('check_debian_core.py', 'check_tls_gateway.py', 'check_tls_import_web.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_tls_import_web.py',
            timeout=650, capture=False)


if __name__ == '__main__':
    main()
