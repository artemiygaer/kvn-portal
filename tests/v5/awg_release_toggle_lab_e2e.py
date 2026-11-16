"""Включить и выключить ранее установленный подписанный AWG на Debian 13 VM."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22069, ROOT)
    lab.wait()
    for name in ('check_debian_core.py', 'check_awg_release_toggle.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_awg_release_toggle.py',
            timeout=600, capture=False)


if __name__ == '__main__':
    main()
