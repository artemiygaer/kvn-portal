"""HTTPS E2E подготовки Telemt и MTG на изолированной VM в WSL."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.migration_lab_e2e import upload
from tests.v5.prepare_tunnel_lab import ROOT
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    lab.run('test ! -e /var/lib/kvn-v5/modules/telemt/settings.json && test ! -e /var/lib/kvn-v5/modules/mtg/settings.json')
    stage_candidate(lab)
    lab.run(f'cd {INSTALLED}; tar -xzf {STAGE}/candidate.tar.gz --no-same-owner --no-same-permissions '
            'v5/modules/mtproto_common v5/modules/telemt v5/modules/mtg')
    for name in ('check_debian_core.py', 'check_mtproto_init_web.py', 'refresh_clean_gateway.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 {STAGE}/refresh_clean_gateway.py')
    with TemporaryDirectory(dir=ROOT, prefix='mtproto-web-e2e-') as directory:
        root = Path(directory)
        signer = root / 'signer.pem'
        publisher = new_key(signer)
        pin = root / 'publisher.json'
        pin.write_bytes(canonical_json({'public_der': publisher.public_der.hex(), 'sha256': publisher.fingerprint}))
        lab.upload(pin, '/etc/kvn-v5/packages/publisher.json')
        now = datetime.now(timezone.utc)
        for module in ('telemt', 'mtg'):
            archive = root / f'{module}.tar.gz'
            build(archive, signer, module_id=module, version='1.0.0', image_digest='1' * 64,
                  issued_at=(now - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  expires_at=(now + timedelta(hours=4)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            upload(lab, archive, STAGE)
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_mtproto_init_web.py '
            f'{STAGE}/telemt.tar.gz {STAGE}/mtg.tar.gz', timeout=900, capture=False)


if __name__ == '__main__':
    main()
