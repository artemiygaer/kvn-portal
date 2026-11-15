"""Проверка доверенного APT-плана AmneziaWG в изолированной VM WSL."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    stage_candidate(lab)
    lab.upload(Path('tests/v5/fixtures/probe_awg_apt.py'), f'{STAGE}/probe_awg_apt.py')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 -u {STAGE}/probe_awg_apt.py', timeout=1000, capture=False)


if __name__ == '__main__':
    main()
