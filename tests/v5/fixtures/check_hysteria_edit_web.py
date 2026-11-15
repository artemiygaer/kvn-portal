"""Проверка редактирования Hysteria2 через HTTPS в учебной VM."""

from dataclasses import replace
import hashlib
import http.client
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.hysteria.config import Settings

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
path = Path('/var/lib/kvn-v5/modules/hysteria/settings.json')
before = Settings.load(path)
new_port = 14443 if before.port != 14443 else 14444
context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=150)
cookie = signed_fixture_session()


def request(method, target, body=None):
    global cookie
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': 'application/x-www-form-urlencoded'})
    connection.request(method, target, body=body, headers=headers)
    response = connection.getresponse()
    if response.getheader('Set-Cookie'):
        cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
assert status == 200, f'HTTP {status}'
if before.salamander:
    assert before.salamander not in page
for account in before.accounts:
    assert account.password not in page
csrf = re.search(r'name="csrf" value="([^\"]+)"', page)[1]
form = re.search(r'<form[^>]+action="/modules/change_hysteria"[^>]*>(.*?)</form>', page, re.S)[1]
revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
params = {'csrf': csrf, 'identity': before.tls.name, 'port': str(new_port),
          'revision': revision, 'confirm': 'yes'}
if before.salamander:
    params['salamander'] = 'yes'
change = urlencode(params)
assert request('POST', '/modules/change_hysteria', change)[0] == 303
assert Settings.load(path) == replace(before, port=new_port)
digest = hashlib.sha256(path.read_bytes()).digest()
assert request('POST', '/modules/change_hysteria', change)[0] == 303
assert hashlib.sha256(path.read_bytes()).digest() == digest
print('HTTPS: настройки Hysteria2 изменены, ключи сохранены, устаревшая форма отклонена.', flush=True)
connection.close()
