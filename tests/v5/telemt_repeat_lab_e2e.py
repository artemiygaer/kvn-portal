"""Повторить цикл Telemt через HTTPS только на выделенной учебной VM."""

from pathlib import Path

from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22068, ROOT)
    lab.wait()
    for name in ('check_debian_core.py', 'check_release_container_toggle.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    for number in range(1, 4):
        print(f'Цикл Telemt {number}/3.', flush=True)
        lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u '
                f'{STAGE}/check_release_container_toggle.py telemt', timeout=900, capture=False)


if __name__ == '__main__':
    main()
