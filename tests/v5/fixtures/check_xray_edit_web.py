"""Проверить редактирование Xray через HTTPS изолированной учебной VM."""

import http.client
from pathlib import Path
import re
import ssl
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.xray.config import Settings
from v5.modules.xray.profiles import Kind

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
path = Path('/var/lib/kvn-v5/modules/xray/settings.json')
original = Settings.load(path)
assert len(original.profiles.values) == 2 and not original.accounts
connection = http.client.HTTPSConnection('127.0.0.1', 8443,
    context=ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt'), timeout=120)
cookie, origin = signed_fixture_session(), 'https://127.0.0.1:8443'


def request(method, route, data=None):
    global cookie
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
    connection.request(method, route, body=urlencode(data) if data else None, headers=headers)
    response = connection.getresponse()
    if response.getheader('Set-Cookie'):
        cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
if status == 200 and 'reality-xhttp · changed.example' in page:
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    form = next(part for part in re.findall(r'<form[^>]+action="/modules/initialize_xray"[^>]*>(.*?)</form>', page, re.S)
                if 'name="kind" value="reality-xhttp"' in part)
    revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
    restore = {'csrf': csrf, 'kind': 'reality-xhttp', 'exposure': 'shared', 'sni': 'two.example',
               'reality': 'external', 'external_host': 'two.example', 'path': '/kvn', 'confirm': 'yes',
               'profile_action': 'replace', 'revision': revision}
    assert request('POST', '/modules/initialize_xray', restore)[0] == 303
    original = Settings.load(path)
    status, page = request('GET', '/modules')
if 'reality-xhttp · two.example' not in page:
    print('Диагностика: статус', status, 'нет профилей:', 'Не удалось прочитать профили Xray.' in page, flush=True)
assert status == 200 and 'reality-xhttp · two.example' in page
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
form = next(part for part in re.findall(r'<form[^>]+action="/modules/initialize_xray"[^>]*>(.*?)</form>', page, re.S)
            if 'name="kind" value="reality-xhttp"' in part)
revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
data = {'csrf': csrf, 'kind': 'reality-xhttp', 'exposure': 'shared', 'sni': 'changed.example',
        'reality': 'external', 'external_host': 'changed.example', 'path': '/kvn',
        'confirm': 'yes', 'profile_action': 'replace', 'revision': revision}
assert request('POST', '/modules/initialize_xray', data)[0] == 303
assert next(p for p in Settings.load(path).profiles.values if p.kind == Kind.REALITY_XHTTP).sni == 'changed.example'
before = path.read_bytes()
assert request('POST', '/modules/initialize_xray', data)[0] == 303
assert path.read_bytes() == before
status, page = request('GET', '/modules')
assert status == 200 and 'Профиль уже изменился' in page
form = next(part for part in re.findall(r'<form[^>]+action="/modules/remove_xray"[^>]*>(.*?)</form>', page, re.S)
            if 'name="kind" value="reality-xhttp"' in part)
revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
assert request('POST', '/modules/remove_xray', {'csrf': csrf, 'kind': 'reality-xhttp', 'revision': revision,
                                                'confirm': 'yes'})[0] == 303
assert len(Settings.load(path).profiles.values) == 1
data.update(sni='two.example', external_host='two.example', profile_action='add')
data.pop('revision')
assert request('POST', '/modules/initialize_xray', data)[0] == 303
assert Settings.load(path) == original
print('HTTPS: профиль изменён, устаревшая форма отклонена, удаление и повторное добавление проверены.', flush=True)
connection.close()
