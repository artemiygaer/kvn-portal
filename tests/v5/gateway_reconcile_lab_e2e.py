"""Проверить реальный откат nginx на изолированной Debian 13."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22069, ROOT)
    lab.wait()
    lab.upload(Path('tests/v5/fixtures/check_gateway_reconcile_rollback.py'),
               f'{STAGE}/check_gateway_reconcile_rollback.py')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_gateway_reconcile_rollback.py',
            timeout=180, capture=False)


if __name__ == '__main__':
    main()
