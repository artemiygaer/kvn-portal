"""Обновление через портал на отдельном Debian в WSL, без рабочих серверов."""

from pathlib import Path
from tempfile import TemporaryDirectory

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.migration_lab_e2e import upload
from tests.v5.prepare_tunnel_lab import ROOT
from tests.v5.test_core_update import artifact, publisher
from v5.core.maintenance.core_bundle import NAME as BUNDLE_NAME


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    assert lab.run('cat /var/lib/cloud/data/instance-id; hostname').stdout.splitlines() == [
        b'kvn-v5-isolated-001', b'kvn-v5-isolated']
    stage_candidate(lab)
    lab.run('install -d -m 0700 /etc/kvn-v5/core')
    # Исключительно учебный экземпляр, его установка уже подтверждена выше.
    lab.run('printf \'{"format":1,"path":"/root/portal"}\' > /etc/kvn-v5/core/install-location.json; '
            'chmod 600 /etc/kvn-v5/core/install-location.json')
    lab.run(f'set -eu; cd {INSTALLED}; uid=$(id -u kvn-v5-web); '
            'for unit in kvn-v5-core-update.socket kvn-v5-core-update@.service kvn-v5-core-apply@.service; do '
            f'tar -xOzf {STAGE}/candidate.tar.gz v5/install/systemd/$unit | '
            'sed "s/@WEB_UID@/$uid/g" > /etc/systemd/system/$unit; done; '
            'systemctl daemon-reload; systemctl enable --now kvn-v5-core-update.socket')
    fixtures = Path('tests/v5/fixtures')
    for name in ('check_debian_core.py', 'check_core_update_web.py', 'refresh_clean_gateway.py', 'wait_core_update.py'):
        lab.upload(fixtures / name, f'{STAGE}/{name}')
    # На VM ранее проверялась фаза 13 со старым шаблоном nginx. Здесь воспроизводим
    # шаблон свежей установки из проверяемого кандидата, а не обновление старой v5.
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 {STAGE}/refresh_clean_gateway.py')
    with TemporaryDirectory(dir=ROOT, prefix='core-web-e2e-') as directory:
        root = Path(directory)
        _, key, pin = publisher(root)
        lab.upload(pin, '/etc/kvn-v5/core/publisher.json')
        source = artifact(root / 'release', key, pin, '5.0.1')
        upload(lab, source / BUNDLE_NAME, STAGE)
    before = lab.run('sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json').stdout
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_core_update_web.py '
            f'{STAGE}/{BUNDLE_NAME}', timeout=300, capture=False)
    lab.run(f'python3 -u {STAGE}/wait_core_update.py', timeout=630, capture=False)
    assert lab.run('sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json').stdout == before
    print('Подписанная версия 5.0.1 применена; настройки портала и модулей сохранены.', flush=True)


if __name__ == '__main__':
    main()
