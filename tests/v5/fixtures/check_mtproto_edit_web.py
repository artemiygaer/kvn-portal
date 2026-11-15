"""HTTPS-проверка изменения настроек MTProto только в учебной VM."""

import hashlib
import http.client
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.mtg.settings import Settings as MTGSettings
from v5.modules.telemt.settings import Settings as TelemtSettings

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
connection = http.client.HTTPSConnection('127.0.0.1', 8443,
    context=ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt'), timeout=120)
cookie = signed_fixture_session()


def request(method, path, body=None):
    global cookie
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': 'https://127.0.0.1:8443',
                        'Content-Type': 'application/x-www-form-urlencoded'})
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    if response.getheader('Set-Cookie'):
        cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    return response.status, response.read().decode('utf-8')


for module, settings_type in (('telemt', TelemtSettings), ('mtg', MTGSettings)):
    path = Path(f'/var/lib/kvn-v5/modules/{module}/settings.json')
    old = settings_type.load(path)
    status, page = request('GET', '/modules')
    assert status == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    forms = re.findall(r'<form[^>]+action="/modules/change_mtproto"[^>]*>(.*?)</form>', page, re.S)
    form = next(row for row in forms if f'name="module" value="{module}"' in row)
    revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
    if module == 'mtg':
        assert old.secret.value not in page
    for account in getattr(old, 'accounts', ()):
        assert account.secret.value not in page
    body = urlencode({'csrf': csrf, 'module': module, 'sni': f'{module}-edit.example', 'mode': 'external',
                      'exposure': 'direct', 'revision': revision, 'confirm': 'yes'})
    assert request('POST', '/modules/change_mtproto', body)[0] == 303
    changed = settings_type.load(path)
    assert changed.exposure.sni == f'{module}-edit.example' and not changed.exposure.shared
    assert (changed.secret == old.secret if module == 'mtg' else changed.accounts == old.accounts)
    digest = hashlib.sha256(path.read_bytes()).digest()
    assert request('POST', '/modules/change_mtproto', body)[0] == 303
    assert hashlib.sha256(path.read_bytes()).digest() == digest
print('HTTPS: редактирование Telemt и MTG, сохранение секретов и отклонение устаревших форм: OK', flush=True)
connection.close()
