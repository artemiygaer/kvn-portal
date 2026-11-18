"""Обновить v5.0.5 и проверить SSH-учётки на отдельной Debian VM в WSL."""

from pathlib import Path
import secrets
import sys

from tests.v5.debian_core_e2e import Lab


def main():
    lab = Lab(22125, Path('/var/tmp/kvn-v5-lab'))
    lab.wait()
    assert lab.run('cat /usr/local/lib/kvn-v5/core-version').stdout.strip() == (b'5.0.5' if len(sys.argv) > 1 else b'5.0.6')
    source = Path('tests/v5/fixtures')
    target = '/var/tmp/kvn-ssh-account-test'
    installed = '/usr/local/lib/kvn-v5'
    lab.run(f'install -d -m 0700 {target}')
    for name in ('check_debian_core.py', 'check_core_update_web.py', 'wait_core_update.py',
                 'reset_lab_password.py', 'check_ssh_accounts.py'):
        lab.upload(source / name, f'{target}/{name}')
    if len(sys.argv) > 1:
        lab.upload(Path(sys.argv[1]), f'{target}/update.tar')
        lab.run(f'cd {installed} && PYTHONPATH=. python3 -u {target}/check_core_update_web.py {target}/update.tar 5.0.6',
                capture=False, timeout=240)
        lab.run(f'python3 -u {target}/wait_core_update.py 5.0.6', capture=False, timeout=630)
    password = secrets.token_urlsafe(32).encode()
    lab.run(f'cd {installed} && PYTHONPATH=. python3 -u {target}/reset_lab_password.py',
            data=password, capture=False, timeout=140)
    lab.run(f'cd {installed} && PYTHONPATH=. python3 -u {target}/check_ssh_accounts.py',
            data=password, capture=False, timeout=200)


if __name__ == '__main__':
    main()
