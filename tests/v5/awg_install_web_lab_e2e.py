"""Установка и ABI-проверка AWG в изолированной Debian VM внутри WSL."""

from datetime import datetime, timedelta, timezone
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
    if port not in (22063, 22068, 22069, 22070):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    lab.run('test ! -e /usr/bin/awg')
    if port in (22068, 22069, 22070):
        # Свежая установка сохраняет код ядра и настоящий ключ издателя.
        lab.run(f'install -d -m 0700 {STAGE}')
        for name in ('check_debian_core.py', 'check_awg_install_web.py'):
            lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
        archive = Path('output/v5-release-candidate-5.0.2/kvn-module-amneziawg-1.0.0.tar.gz')
        resume = len(sys.argv) > 2 and sys.argv[2] == '--resume'
        if not resume:
            upload(lab, archive, STAGE)
        argument = '--resume' if resume else f'{STAGE}/{archive.name}'
        lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_awg_install_web.py '
                f'{argument}', timeout=2550, capture=False)
        return
    stage_candidate(lab)
    for name in ('check_debian_core.py', 'check_awg_install_web.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    with TemporaryDirectory(dir=ROOT, prefix='awg-provision-e2e-') as directory:
        root = Path(directory)
        signer = root / 'signer.pem'
        publisher = new_key(signer)
        pin = root / 'publisher.json'
        pin.write_bytes(canonical_json({'public_der': publisher.public_der.hex(), 'sha256': publisher.fingerprint}))
        lab.upload(pin, '/etc/kvn-v5/packages/publisher.json')
        now = datetime.now(timezone.utc)
        archive = root / 'amneziawg.tar.gz'
        build(archive, signer, module_id='amneziawg', version='1.0.0',
              issued_at=(now - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
              expires_at=(now + timedelta(hours=4)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        upload(lab, archive, STAGE)
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_awg_install_web.py '
            f'{STAGE}/amneziawg.tar.gz', timeout=2550, capture=False)


if __name__ == '__main__':
    main()
