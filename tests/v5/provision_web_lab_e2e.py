"""E2E фоновой подготовки на изолированной Debian VM в WSL."""

from pathlib import Path
import sys

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    module = sys.argv[1] if len(sys.argv) >= 2 else 'wireguard'
    if module not in ('wireguard', 'xray'):
        raise ValueError('Неизвестный тестовый модуль')
    wait_only = len(sys.argv) >= 3 and sys.argv[2] == '--wait-only'
    port = int(sys.argv[3]) if len(sys.argv) == 4 and wait_only else 22063
    if port not in (22063, 22067):
        raise ValueError('Разрешены только выделенные учебные VM')
    lab = Lab(port, ROOT)
    lab.wait()
    if not wait_only:
        stage_candidate(lab)
        for name in ('kvn-v5-provision@.service', 'kvn-v5-core-update@.service'):
            lab.upload(Path('v5/install/systemd') / name, f'{STAGE}/{name}')
        # Идентификатор берётся из созданной установщиком учётной записи, не из браузера.
        lab.run(f"uid=$(id -u kvn-v5-web); sed -i \"s/@WEB_UID@/$uid/g\" {STAGE}/kvn-v5-core-update@.service; "
                f"install -m 0644 {STAGE}/kvn-v5-provision@.service /etc/systemd/system/; "
                f"install -m 0644 {STAGE}/kvn-v5-core-update@.service /etc/systemd/system/; "
                'systemctl daemon-reload')
    for name in ('check_debian_core.py', 'check_provision_web.py'):
        lab.upload(Path('tests/v5/fixtures') / name, f'{STAGE}/{name}')
    option = ' --wait-only' if wait_only else ''
    lab.run(f'cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_provision_web.py {module}{option}',
            timeout=1350, capture=False)


if __name__ == '__main__':
    main()
