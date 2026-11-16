"""Реальная установка Docker через портал на учебной Debian VM в WSL."""

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.migration_lab_e2e import upload
from tests.v5.prepare_tunnel_lab import ROOT
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 22063
    if port not in (22063, 22065, 22066, 22067, 22068, 22069):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    lab.run('test ! -e /usr/bin/docker')
    if port in (22068, 22069):
        # На свежей установке проверяем оригинальный подписанный пакет издателя,
        # не подменяя ни код ядра, ни доверенный ключ, ни systemd units.
        version = '5.0.2' if port == 22068 else '5.0.3'
        lab.run(f'test "$(cat {INSTALLED}/core-version)" = {version}; install -d -m 0700 {STAGE}')
        for name in ('check_debian_core.py', 'check_provision_install_web.py'):
            lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
        archive = Path('output/v5-release-candidate-5.0.2/kvn-module-xray-26.10.31.tar.gz')
        payload = archive.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        lab.run(f'umask 077; cat > {STAGE}/xray.tar.gz', data=payload, timeout=300)
        lab.run(f'cd {STAGE}; sha256sum --check --strict', data=f'{digest}  xray.tar.gz\n'.encode(), timeout=120)
        lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_provision_install_web.py '
                f'{STAGE}/xray.tar.gz', timeout=1800, capture=False)
        return
    stage_candidate(lab)
    # Базовый снимок фазы 2 старше модульной архитектуры.
    lab.run(f'tar -xzf {STAGE}/candidate.tar.gz -C {INSTALLED} v5/modules')
    units = ('kvn-v5-provision@.service', 'kvn-v5-core-update.socket', 'kvn-v5-core-update@.service',
             'kvn-v5-package.socket', 'kvn-v5-package@.service',
             'kvn-v5-lifecycle.socket', 'kvn-v5-lifecycle@.service')
    for name in units:
        lab.upload(Path('v5/install/systemd') / name, f'{STAGE}/{name}')
    lab.run(f'uid=$(id -u kvn-v5-web); '
            + ' '.join(f'sed "s/@WEB_UID@/$uid/g" {STAGE}/{name} > /etc/systemd/system/{name};'
                       for name in units)
            + ' install -d -m 0700 /etc/kvn-v5/packages /var/lib/kvn-v5/packages /var/lib/kvn-v5/modules '
              '/var/lib/kvn-v5/users /var/lib/kvn-v5/tls; '
              'install -d -m 0755 /var/lib/kvn-v5/acme /var/lib/kvn-v5/site; '
              'systemctl daemon-reload; systemctl enable --now kvn-v5-package.socket kvn-v5-lifecycle.socket '
              'kvn-v5-core-update.socket')
    for name in ('check_debian_core.py', 'check_provision_install_web.py', 'refresh_clean_gateway.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 {STAGE}/refresh_clean_gateway.py')
    with TemporaryDirectory(dir=ROOT, prefix='docker-provision-e2e-') as directory:
        root = Path(directory)
        signer = root / 'signer.pem'
        publisher = new_key(signer)
        pin = root / 'publisher.json'
        pin.write_bytes(canonical_json({'public_der': publisher.public_der.hex(), 'sha256': publisher.fingerprint}))
        lab.upload(pin, '/etc/kvn-v5/packages/publisher.json')
        now = datetime.now(timezone.utc)
        archive = root / 'xray.tar.gz'
        build(archive, signer, module_id='xray', version='1.0.0', image_digest='1' * 64,
              issued_at=(now - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
              expires_at=(now + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        upload(lab, archive, STAGE)
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_provision_install_web.py '
            f'{STAGE}/xray.tar.gz', timeout=1350, capture=False)


if __name__ == '__main__':
    main()
