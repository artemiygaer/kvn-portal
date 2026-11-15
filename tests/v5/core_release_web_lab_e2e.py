"""Проверить готовый подписанный архив ядра через HTTPS изолированной VM."""

from pathlib import Path

from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT
from v5.core.maintenance.core_bundle import NAME as BUNDLE_NAME


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    identity = lab.run('cat /var/lib/cloud/data/instance-id; hostname').stdout.splitlines()
    assert identity == [b'kvn-v5-isolated-001', b'kvn-v5-isolated'], identity
    version = lab.run(f'cat {INSTALLED}/core-version').stdout.strip()
    assert version in (b'5.0.0', b'5.0.1'), version
    archive = Path('output/v5-release-candidate-5.0.2') / BUNDLE_NAME
    assert archive.is_file()
    lab.run(f'install -d -m 0700 {STAGE} /etc/kvn-v5/core; '
            'systemctl is-active --quiet kvn-v5-core-update.socket')
    lab.upload(Path('v5/packaging/publisher.json'), '/etc/kvn-v5/core/publisher.json')
    lab.upload(archive, f'{STAGE}/{BUNDLE_NAME}')
    for name in ('check_debian_core.py', 'check_core_update_web.py', 'wait_core_update.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    before = lab.run('sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json').stdout
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_core_update_web.py '
            f'{STAGE}/{BUNDLE_NAME} 5.0.2', timeout=300, capture=False)
    lab.run(f'python3 -u {STAGE}/wait_core_update.py 5.0.2', timeout=630, capture=False)
    assert lab.run('sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json').stdout == before
    print('Релизный кандидат 5.0.2 применён через HTTPS; настройки сохранены.', flush=True)


if __name__ == '__main__':
    main()
