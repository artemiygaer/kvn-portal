"""Проверить reboot выделенного внешнего Debian без изменения контейнера."""

import argparse
from pathlib import Path
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host')
    parser.add_argument('hostname')
    parser.add_argument('container')
    parser.add_argument('expected_id')
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--known-hosts', type=Path, required=True)
    args = parser.parse_args()
    host, hostname, container, expected_id = args.host, args.hostname, args.container, args.expected_id
    if (re.fullmatch(r'[a-z0-9.-]{1,253}', host) is None
            or re.fullmatch(r'[a-z0-9-]{1,63}', hostname) is None
            or re.fullmatch(r'[a-zA-Z0-9_.-]{1,128}', container) is None
            or re.fullmatch(r'[a-f0-9]{64}', expected_id) is None):
        raise ValueError('Неподходящая идентичность стенда')
    ssh = ['ssh', '-i', str(args.key), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8',
           '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={args.known_hosts}', f'root@{host}']

    def run(command, check=True):
        return subprocess.run([*ssh, command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=25, check=check)

    def identity():
        observed = run('hostname').stdout.decode().strip()
        info = run(f'docker inspect --format "{{{{.Id}}}}:{{{{.HostConfig.RestartPolicy.Name}}}}:{{{{.State.Running}}}}" {container}').stdout.decode().strip()
        if observed != hostname or info != f'{expected_id}:unless-stopped:true':
            raise RuntimeError('Тестовый хост или состояние контейнера не совпадают')
        run('systemctl is-enabled --quiet docker')

    identity()
    before = run('cat /proc/sys/kernel/random/boot_id').stdout.strip()
    snapshots = run('sha256sum /etc/kvn-v5/web/config.json /root/portal/install.json').stdout
    run('systemctl --no-block --no-wall reboot', check=False)
    deadline = time.monotonic() + 420
    while time.monotonic() < deadline:
        time.sleep(5)
        try:
            result = run('cat /proc/sys/kernel/random/boot_id', check=False)
            if result.returncode == 0 and result.stdout.strip() != before:
                break
        except (OSError, subprocess.SubprocessError):
            continue
    else:
        raise RuntimeError('Не подтверждён новый boot ID тестового сервера')
    deadline = time.monotonic() + 180
    while True:
        try:
            identity()
            for unit in ('kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway', 'kvn-v5-tls-renew.timer'):
                run(f'systemctl is-active --quiet {unit}')
            break
        except (RuntimeError, OSError, subprocess.SubprocessError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
    if run('sha256sum /etc/kvn-v5/web/config.json /root/portal/install.json').stdout != snapshots:
        raise RuntimeError('Настройки портала изменились после перезагрузки')
    print('Новый boot ID; портал, таймер продления и исходный контейнер работают; настройки портала сохранены.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
