"""Проверить уже завершённую установку AWG без повторного запуска APT."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    lab.upload(Path('tests/v5/fixtures/check_awg_ready.py'), f'{STAGE}/check_awg_ready.py')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 -u {STAGE}/check_awg_ready.py', timeout=120, capture=False)


if __name__ == '__main__':
    main()
