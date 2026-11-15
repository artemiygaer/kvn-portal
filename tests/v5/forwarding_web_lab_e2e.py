"""Ограниченный HTTPS E2E для IPv4 forwarding на учебной Debian."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import time

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
    lab.run('set -eu; test -f /var/lib/kvn-v5/modules/wireguard/settings.json; '
            '! ip link show wg0 >/dev/null 2>&1')
    stage_candidate(lab)
    lab.upload(Path('v5/install/systemd/kvn-v5-core-update@.service'), f'{STAGE}/kvn-v5-core-update@.service')
    lab.run(f'set -eu; uid=$(id -u kvn-v5-web); sed "s/@WEB_UID@/$uid/g" '
            f'{STAGE}/kvn-v5-core-update@.service > {STAGE}/core-update-unit; '
            f'install -m 0644 {STAGE}/core-update-unit /etc/systemd/system/kvn-v5-core-update@.service; '
            'systemctl daemon-reload')
    for name in ('check_debian_core.py', 'check_forwarding_web.py', 'refresh_clean_gateway.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=. python3 {STAGE}/refresh_clean_gateway.py')
    with TemporaryDirectory(dir=ROOT, prefix='forwarding-web-e2e-') as directory:
        root = Path(directory)
        signer = root / 'signer.pem'
        publisher = new_key(signer)
        pin = root / 'publisher.json'
        pin.write_bytes(canonical_json({'public_der': publisher.public_der.hex(), 'sha256': publisher.fingerprint}))
        lab.upload(pin, '/etc/kvn-v5/packages/publisher.json')
        now = datetime.now(timezone.utc)
        archive = root / 'wireguard.tar.gz'
        build(archive, signer, module_id='wireguard', version=f'{int(time.time()) % 1000000000}.0.0',
              issued_at=(now - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
              expires_at=(now + timedelta(hours=4)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        upload(lab, archive, STAGE)
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_forwarding_web.py '
            f'{STAGE}/wireguard.tar.gz', timeout=900, capture=False)


if __name__ == '__main__':
    main()
