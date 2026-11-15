"""E2E редактирования профилей Xray в изолированной VM WSL."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    stage_candidate(lab)
    lab.run(f'cd {INSTALLED}; tar -xzf {STAGE}/candidate.tar.gz --no-same-owner --no-same-permissions v5/modules/xray')
    for name in ('check_debian_core.py', 'check_xray_edit_web.py', 'refresh_clean_gateway.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 {STAGE}/refresh_clean_gateway.py')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_xray_edit_web.py',
            timeout=300, capture=False)


if __name__ == '__main__':
    main()
