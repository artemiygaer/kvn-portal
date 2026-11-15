"""Проверка автоматического отката после сбоя через HTTPS в учебной VM."""

from pathlib import Path
from tempfile import TemporaryDirectory

from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.migration_lab_e2e import upload
from tests.v5.prepare_tunnel_lab import ROOT
from tests.v5.test_core_update import artifact, publisher
from v5.core.maintenance.core_bundle import NAME


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    assert lab.run('cat /var/lib/cloud/data/instance-id; hostname').stdout.splitlines() == [
        b'kvn-v5-isolated-001', b'kvn-v5-isolated']
    assert lab.run(f'cat {INSTALLED}/core-version').stdout.strip() == b'5.0.1'
    for name in ('check_debian_core.py', 'check_core_update_web.py', 'wait_core_update.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    before = lab.run('sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json').stdout
    with TemporaryDirectory(dir=ROOT, prefix='core-web-rollback-') as directory:
        root = Path(directory)
        _, key, pin = publisher(root)
        lab.upload(pin, '/etc/kvn-v5/core/publisher.json')
        source = artifact(root / 'broken', key, pin, '5.0.2', break_web=True)
        upload(lab, source / NAME, STAGE)
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_core_update_web.py '
            f'{STAGE}/{NAME} 5.0.2', timeout=300, capture=False)
    lab.run(f'python3 -u {STAGE}/wait_core_update.py 5.0.2 failed 5.0.1', timeout=630, capture=False)
    assert lab.run('sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json').stdout == before
    print('Ошибка нового веб-кода: ядро 5.0.1 автоматически восстановлено; настройки сохранены.', flush=True)


if __name__ == '__main__':
    main()
