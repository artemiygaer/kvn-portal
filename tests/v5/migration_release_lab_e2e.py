"""Проверить импорт v4.2 на свежей установке релизного кандидата."""

from pathlib import Path
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.fixtures.make_v42_fixture import build_fixture
from tests.v5.migration_lab_e2e import BASE, FIXTURES, upload
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22069, ROOT)
    lab.wait()
    lab.run(f'test ! -e /usr/bin/docker; test ! -e /var/lib/kvn-v5/packages/registry.sqlite3; '
            f'test ! -e /var/lib/kvn-v5/users/users.sqlite3; install -d -m 0700 {BASE}')
    with TemporaryDirectory(dir=ROOT, prefix='v42-import-release-') as temporary:
        archive = Path(temporary) / 'fixture.kvn'
        archive.write_bytes(build_fixture())
        upload(lab, archive, BASE)
    for name in ('check_debian_core.py', 'check_network_nft.py', 'check_tunnel_vm.py', 'check_migration_vm.py'):
        upload(lab, FIXTURES / name, BASE)
    lab.run(f'cd /usr/local/lib/kvn-v5; PYTHONPATH=.:{BASE} '
            f'python3 -u {BASE}/check_migration_vm.py --fixture-session --import-only',
            timeout=900, capture=False)


if __name__ == '__main__':
    main()
