"""Проверить подписанный контейнерный модуль через HTTPS только на учебной VM."""

import hashlib
import http.client
from http.cookies import SimpleCookie
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session

MODULE_PORT = {'xray': 2444, 'telemt': 2446, 'mtg': 2447}


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    module = sys.argv[1]
    assert module in MODULE_PORT
    port = MODULE_PORT[module]
    archive = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    cookie = signed_fixture_session()
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')

    def request(method, path, body=None, kind=None):
        nonlocal cookie
        conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=360)
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': kind})
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

    status, page = request('GET', '/modules')
    assert status == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    kind = 'application/x-www-form-urlencoded'
    if archive is not None:
        boundary = b'KVNReleaseModuleFixture'
        body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
                + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="package"; filename="module.tar.gz"'
                + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive.read_bytes()
                + b'\r\n--' + boundary + b'--\r\n')
        status, page = request('POST', '/modules/upload', body, 'multipart/form-data; boundary=' + boundary.decode())
        assert status == 200 and 'Пакет проверен' in page
        form = re.search(r'<form[^>]+action="/modules/install"[^>]*>(.*?)</form>', page, re.S)[1]
        ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
        assert request('POST', '/modules/install', urlencode({'csrf': csrf, 'ticket': ticket}), kind)[0] == 303
    path = Path(f'/var/lib/kvn-v5/modules/{module}/settings.json')
    fields = {'csrf': csrf, 'confirm': 'yes'}
    if module == 'xray':
        fields.update(kind='reality-tcp', exposure='direct', sni='www.microsoft.com', reality='external',
                      external_host='www.microsoft.com', profile_action='initial')
        endpoint = '/modules/initialize_xray'
        if path.exists():
            # На этой учебной VM ранее созданы два синтетических профиля.
            status, page = request('GET', '/modules')
            assert status == 200
            removals = re.findall(r'<form[^>]+action="/modules/remove_xray"[^>]*>(.*?)</form>', page, re.S)
            for row in removals:
                name = re.search(r'name="kind" value="([^"]+)"', row)[1]
                if name == 'reality-tcp':
                    continue
                revision = re.search(r'name="revision" value="([0-9a-f]{64})"', row)[1]
                assert request('POST', '/modules/remove_xray', urlencode({
                    'csrf': csrf, 'kind': name, 'revision': revision, 'confirm': 'yes'}), kind)[0] == 303
            status, page = request('GET', '/modules')
            assert status == 200
            forms = re.findall(r'<form[^>]+action="/modules/initialize_xray"[^>]*>(.*?)</form>', page, re.S)
            row = next(item for item in forms if 'name="kind" value="reality-tcp"' in item)
            fields['revision'] = re.search(r'name="revision" value="([0-9a-f]{64})"', row)[1]
            fields['profile_action'] = 'replace'
    else:
        fields.update(module=module, sni='www.microsoft.com', mode='external', exposure='direct')
        endpoint = '/modules/initialize_mtproto'
    if module == 'xray' or not path.exists():
        assert request('POST', endpoint, urlencode(fields), kind)[0] == 303
    assert path.is_file() and path.stat().st_mode & 0o077 == 0
    action = urlencode({'csrf': csrf, 'module': module, 'confirm': 'yes'})
    enabled_hash = None
    try:
        assert request('POST', '/modules/enable', action, kind)[0] == 303
        status, page = request('GET', '/modules')
        assert status == 200 and 'Модуль включён.' in page, f'{module}: включение не подтверждено'
        ports = subprocess.run(['/usr/bin/ss', '-Hltn'], capture_output=True, check=True).stdout
        assert f':{port} '.encode() in ports
        enabled_hash = hashlib.sha256(path.read_bytes()).digest()
    finally:
        assert request('POST', '/modules/disable', action, kind)[0] == 303
    ports = subprocess.run(['/usr/bin/ss', '-Hltn'], capture_output=True, check=True).stdout
    assert f':{port} '.encode() not in ports
    assert enabled_hash is not None and hashlib.sha256(path.read_bytes()).digest() == enabled_hash
    subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'],
                   check=True)
    print(f'{module}: включение и отключение через HTTPS; порт закрыт, настройки сохранены.', flush=True)


if __name__ == '__main__':
    main()
