"""Проверка редактирования MTProto на изолированной учебной VM."""

from pathlib import Path
from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    lab.run('test -f /var/lib/kvn-v5/modules/telemt/settings.json && test -f /var/lib/kvn-v5/modules/mtg/settings.json')
    stage_candidate(lab)
    lab.run(f'cd {INSTALLED}; tar -xzf {STAGE}/candidate.tar.gz --no-same-owner --no-same-permissions '
            'v5/modules/mtproto_common v5/modules/telemt v5/modules/mtg')
    lab.upload(Path('tests/v5/fixtures/check_mtproto_edit_web.py'), f'{STAGE}/check_mtproto_edit_web.py')
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_mtproto_edit_web.py',
            timeout=900, capture=False)


if __name__ == '__main__':
    main()
