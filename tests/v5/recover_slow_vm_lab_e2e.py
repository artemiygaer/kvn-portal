"""Штатный откат с расширенным ожиданием только на закреплённой VM 22068."""

from pathlib import Path
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22068, ROOT)
    lab.wait()
    lab.upload(Path('tests/v5/fixtures/recover_slow_vm.py'), '/var/tmp/kvn-v5-phase12/recover_slow_vm.py')
    lab.run('cd /usr/local/lib/kvn-v5; PYTHONPATH=. python3 -u /var/tmp/kvn-v5-phase12/recover_slow_vm.py',
            timeout=330, capture=False)


if __name__ == '__main__':
    main()
