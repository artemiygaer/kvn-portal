"""Проверка начальных настроек Telemt и MTG через HTTPS учебной VM."""

import hashlib
import http.client
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.mtg.settings import Settings as MTGSettings
from v5.modules.telemt.settings import Settings as TelemtSettings

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=120)
cookie, origin = signed_fixture_session(), 'https://127.0.0.1:8443'


def request(method, path, body=None, content_type=None):
    global cookie
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': origin, 'Content-Type': content_type})
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    if response.getheader('Set-Cookie'):
        cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
assert status == 200
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
kind = 'application/x-www-form-urlencoded'
for module, archive_path, settings_type in (('telemt', sys.argv[1], TelemtSettings), ('mtg', sys.argv[2], MTGSettings)):
    boundary = b'KVNMtprotoFixtureBoundary'
    archive = Path(archive_path).read_bytes()
    body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
            + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="package"; filename="module.tar.gz"'
            + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive + b'\r\n--' + boundary + b'--\r\n')
    status, page = request('POST', '/modules/upload', body, 'multipart/form-data; boundary=' + boundary.decode())
    assert status == 200 and 'Пакет проверен' in page
    form = re.search(r'<form[^>]+action="/modules/install"[^>]*>(.*?)</form>', page, re.S)[1]
    ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
    assert request('POST', '/modules/install', urlencode({'csrf': csrf, 'ticket': ticket}), kind)[0] == 303
    path = Path(f'/var/lib/kvn-v5/modules/{module}/settings.json')
    assert not path.exists()
    data = urlencode({'csrf': csrf, 'module': module, 'sni': f'{module}.example', 'mode': 'external',
                      'exposure': 'shared', 'confirm': 'yes'})
    assert request('POST', '/modules/initialize_mtproto', data, kind)[0] == 303
    assert path.is_file() and path.stat().st_mode & 0o077 == 0
    settings = settings_type.load(path)
    assert settings.exposure.sni == f'{module}.example'
    before = hashlib.sha256(path.read_bytes()).digest()
    assert request('POST', '/modules/initialize_mtproto', data, kind)[0] == 303
    assert hashlib.sha256(path.read_bytes()).digest() == before
    status, page = request('GET', '/modules')
    assert status == 200
    if module == 'mtg':
        assert settings.secret.value not in page
    forms = re.findall(r'<form[^>]+action="/modules/change_mtproto"[^>]*>(.*?)</form>', page, re.S)
    form = next(row for row in forms if f'name="module" value="{module}"' in row)
    revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
    change = urlencode({'csrf': csrf, 'module': module, 'sni': f'{module}-new.example', 'mode': 'external',
                        'exposure': 'direct', 'revision': revision, 'confirm': 'yes'})
    assert request('POST', '/modules/change_mtproto', change, kind)[0] == 303
    changed = settings_type.load(path)
    assert changed.exposure.sni == f'{module}-new.example' and not changed.exposure.shared
    if module == 'mtg':
        assert changed.secret == settings.secret
    else:
        assert changed.accounts == settings.accounts
    after = hashlib.sha256(path.read_bytes()).digest()
    assert after != before
    assert request('POST', '/modules/change_mtproto', change, kind)[0] == 303
    assert hashlib.sha256(path.read_bytes()).digest() == after
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('HTTPS: Telemt и MTG настроены и изменены выключенными, устаревшие формы отклонены, секреты сохранены.', flush=True)
connection.close()
