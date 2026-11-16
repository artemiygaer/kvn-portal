"""Замерить готовый подписанный выпуск на пустой VM с 1 vCPU и 1 ГиБ."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22070, ROOT)
    lab.wait()
    assert lab.run(f'cat {INSTALLED}/core-version').stdout.strip() == b'5.0.3'
    lab.run(f'install -d -m 0700 {STAGE}')
    lab.upload(Path('tests/v5/fixtures/check_benchmark_baseline.py'), f'{STAGE}/check_benchmark_baseline.py')
    lab.upload(Path('v5/tools/benchmark_idle.py'), f'{STAGE}/benchmark_idle.py')
    lab.run(f'python3 -u {STAGE}/check_benchmark_baseline.py', timeout=120, capture=False)
    print('Измерение 300 секунд: cgroups агента, веб-службы и шлюза.', flush=True)
    lab.run(f'python3 -u {STAGE}/benchmark_idle.py --seconds 300 --interval 5 '
            'system.slice/kvn-v5-agent.service system.slice/kvn-v5-web.service '
            'system.slice/kvn-v5-gateway.service', timeout=480, capture=False)


if __name__ == '__main__':
    main()
