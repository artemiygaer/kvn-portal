"""Включить и выключить подписанный AmneziaWG 3.1 только на учебной VM."""

import hashlib
import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import re
import ssl
import subprocess
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    cookie = signed_fixture_session()

    def request(method, path, body=None):
        nonlocal cookie
        conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=240)
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers.update({'Origin': 'https://127.0.0.1:8443',
                            'Content-Type': 'application/x-www-form-urlencoded'})
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            update = response.getheader('Set-Cookie')
            if update:
                jar = SimpleCookie()
                jar.load(update)
                if '__Host-kvn-v5' in jar:
                    cookie = '__Host-kvn-v5=' + jar['__Host-kvn-v5'].value
            return response.status, response.read().decode()
        finally:
            conn.close()

    code, page = request('GET', '/modules')
    assert code == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    payload = urlencode({'csrf': csrf, 'module': 'amneziawg', 'egress': '', 'confirm': 'yes'})
    path = Path('/var/lib/kvn-v5/modules/amneziawg/settings.json')
    if not path.exists():
        assert request('POST', '/modules/initialize', payload)[0] == 303
    assert path.is_file() and path.stat().st_mode & 0o077 == 0
    original = json.loads(path.read_bytes())
    enabled_hash = None

    try:
        assert request('POST', '/modules/enable', payload)[0] == 303
        code, page = request('GET', '/modules')
        assert code == 200 and 'Модуль включён.' in page
        assert Path('/sys/class/net/awg0').exists()
        listener = subprocess.run(['/usr/bin/ss', '-Hlun'], capture_output=True, check=True).stdout
        assert b':51820 ' in listener
        enabled = json.loads(path.read_bytes())
        assert {k: v for k, v in original.items() if k != 'settings'} == {
            k: v for k, v in enabled.items() if k != 'settings'}
        assert {k: v for k, v in original['settings'].items() if k != 'peers'} == {
            k: v for k, v in enabled['settings'].items() if k != 'peers'}
        assert all(peer in enabled['settings']['peers'] for peer in original['settings']['peers'])
        enabled_hash = hashlib.sha256(path.read_bytes()).digest()
    finally:
        assert request('POST', '/modules/disable', payload)[0] == 303
    assert not Path('/sys/class/net/awg0').exists()
    listener = subprocess.run(['/usr/bin/ss', '-Hlun'], capture_output=True, check=True).stdout
    assert b':51820 ' not in listener
    assert enabled_hash is not None and hashlib.sha256(path.read_bytes()).digest() == enabled_hash
    subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'],
                   check=True)
    print('AmneziaWG 3.1: включение и выключение через HTTPS; порт закрыт, настройки сохранены.', flush=True)


if __name__ == '__main__':
    main()
