"""Замерить готовый подписанный выпуск на пустой VM с 1 vCPU и 1 ГиБ."""

import argparse
from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, choices=(22070, 22071), default=22070)
    parser.add_argument('--version', choices=('5.0.3', '5.0.4'), default='5.0.3')
    args = parser.parse_args()
    lab = Lab(args.port, ROOT)
    lab.wait()
    assert lab.run(f'cat {INSTALLED}/core-version').stdout.strip() == args.version.encode('ascii')
    assert lab.run('nproc').stdout.strip() == b'1'
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
