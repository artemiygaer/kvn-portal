"""Проверить Xray, Telemt и MTG на изолированной Debian 13 через портал."""

import sys
from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 22069
    if port not in (22068, 22069):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    for name in ('check_debian_core.py', 'check_release_container_toggle.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    release = Path('output/v5-release-candidate-5.0.3-readytest')
    modules = (('xray', None), ('telemt', 'kvn-module-telemt-3.5.17.tar.gz'),
               ('mtg', 'kvn-module-mtg-2.3.0.tar.gz'))
    for module, filename in modules:
        argument = ''
        if filename:
            lab.upload(release / filename, f'{STAGE}/{filename}')
            argument = f' {STAGE}/{filename}'
        lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u '
                f'{STAGE}/check_release_container_toggle.py {module}{argument}', timeout=900, capture=False)


if __name__ == '__main__':
    main()
