"""Проверка HTTPS и настоящего OpenSSH только на учебной VM."""

import http.client
from contextlib import closing
from http.cookies import SimpleCookie
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    assert socket.gethostname() == 'kvn-v5-isolated'
    password = sys.stdin.read().strip()
    name = 'kvnfixture' + secrets.token_hex(4)
    origin = 'https://127.0.0.1:8443'
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    cookie = signed_fixture_session()

    def call(data=None):
        nonlocal cookie
        headers = {'Cookie': cookie}
        body = None
        if data is not None:
            headers.update({'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
            body = urlencode({'csrf': csrf, 'admin_password': password, 'login': name, **data})
        with closing(http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=55)) as conn:
            conn.request('GET' if data is None else 'POST', '/users/ssh-accounts', body=body, headers=headers)
            response = conn.getresponse()
            for header, value in response.getheaders():
                if header.lower() == 'set-cookie':
                    updated = SimpleCookie(value).get('__Host-kvn-v5')
                    if updated is not None:
                        cookie = '__Host-kvn-v5=' + updated.value
            return response.status, response.read().decode()

    def action(expected, **fields):
        code, _ = call(fields)
        assert code == 303, f'{fields["action"]}: HTTP {code}'
        status, page = call()
        if status != 200 or expected not in page:
            error = re.search(r'<p class="alert"[^>]*>(.*?)</p>', page)
            raise RuntimeError(f'Действие {fields["action"]} не подтверждено: {error[1] if error else status}')

    status, page = call()
    assert status == 200 and 'Создать пользователя' in page, 'Раздел недоступен'
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    with TemporaryDirectory() as directory:
        key = Path(directory) / 'key'
        hosts = Path(directory) / 'hosts'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        host = Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text()
        hosts.write_text('127.0.0.1 ' + host)
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', f'UserKnownHostsFile={hosts}', '-i', str(key), f'{name}@127.0.0.1', 'id -Gn']

        def ssh(allowed):
            reply = subprocess.run(cmd, capture_output=True, check=False, timeout=10)
            if allowed:
                assert reply.returncode == 0 and reply.stdout.decode().split() == [name], reply.stderr.decode()
            else:
                denied = (b'Permission denied', b'account has expired')
                assert reply.returncode == 255 and any(item in reply.stderr for item in denied), reply.stderr.decode()

        action('Учётная запись создана', action='create', key=key.with_suffix('.pub').read_text().strip())
        ssh(True)
        action('Пароль изменён', action='password', password=secrets.token_urlsafe(24))
        action('Новые входы заблокированы', action='disable')
        ssh(False)
        action('Вход снова разрешён', action='enable')
        ssh(True)
        action('Новые входы заблокированы', action='disable')
        action('Учётная запись удалена', action='delete', confirm='yes')
        ssh(False)
        assert not (Path('/home') / name).exists() and len(list(Path('/home/.kvn-ssh-retired').glob(name + '-*'))) == 1
    print('HTTPS: создание, смена пароля, SSH по ключу, блокировка, восстановление и удаление подтверждены.', flush=True)


if __name__ == '__main__':
    main()
