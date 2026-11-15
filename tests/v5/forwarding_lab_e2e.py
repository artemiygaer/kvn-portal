"""Проверка отдельной службы и reboot только учебной Debian VM в WSL."""

from pathlib import Path
import time

from tests.v5.audit_lab_e2e import STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    lab.run('set -eu; ! ip link show wg0 >/dev/null 2>&1; ! ip link show awg0 >/dev/null 2>&1')
    stage_candidate(lab)
    lab.upload(Path('v5/install/systemd/kvn-v5-forwarding.service'), f'{STAGE}/kvn-v5-forwarding.service')
    lab.run(f'set -eu; install -m 0644 {STAGE}/kvn-v5-forwarding.service /etc/systemd/system/kvn-v5-forwarding.service; '
            'systemd-analyze verify /etc/systemd/system/kvn-v5-forwarding.service; systemctl daemon-reload',
            timeout=120)
    lab.run('set -eu; printf 0 > /proc/sys/net/ipv4/ip_forward; systemctl start kvn-v5-forwarding.service; '
            'test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1; systemctl enable kvn-v5-forwarding.service; '
            'systemctl is-enabled --quiet kvn-v5-forwarding.service', timeout=120)
    print('Учебная Debian: служба безопасно включила IPv4, проверяем reboot.', flush=True)
    before = lab.run('cat /proc/sys/kernel/random/boot_id').stdout
    lab.run('systemctl --no-block --no-wall reboot', check=False)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        time.sleep(5)
        try:
            # Проверка идентичности до любого дальнейшего действия в гостевой VM.
            lab.wait()
            if lab.run('cat /proc/sys/kernel/random/boot_id').stdout != before:
                break
        except (OSError, TimeoutError):
            continue
    else:
        raise RuntimeError('Учебная VM не подтвердила новый boot ID')
    lab.run('set -eu; test "$(cat /proc/sys/net/ipv4/ip_forward)" = 1; '
            'systemctl is-enabled --quiet kvn-v5-forwarding.service; '
            'for unit in kvn-v5-agent kvn-v5-web kvn-v5-gateway; do systemctl is-active --quiet "$unit"; done',
            timeout=120)
    print('Учебная Debian: IPv4 и службы портала сохранены после reboot.', flush=True)


if __name__ == '__main__':
    main()
