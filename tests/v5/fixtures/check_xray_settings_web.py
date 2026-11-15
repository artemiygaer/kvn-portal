"""Проверить начальные и дополнительные профили Xray через HTTPS учебной VM."""

import hashlib
import http.client
from pathlib import Path
import re
import ssl
import subprocess
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=120)
cookie = signed_fixture_session()
origin = 'https://127.0.0.1:8443'


def request(method, path, data=None):
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
    connection.request(method, path, body=urlencode(data) if data else None, headers=headers)
    response = connection.getresponse()
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
assert status == 200 and 'Создать или добавить профиль Xray' in page
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
data = {'csrf': csrf, 'kind': 'reality-tcp', 'exposure': 'shared', 'sni': 'one.example',
        'reality': 'external', 'external_host': 'one.example', 'confirm': 'yes', 'profile_action': 'initial'}
path = Path('/var/lib/kvn-v5/modules/xray/settings.json')
assert not path.exists()
assert request('POST', '/modules/initialize_xray', data)[0] == 303
assert path.is_file() and path.stat().st_mode & 0o077 == 0
before = hashlib.sha256(path.read_bytes()).digest()
assert request('POST', '/modules/initialize_xray', data)[0] == 303
assert hashlib.sha256(path.read_bytes()).digest() == before
data.update(kind='reality-xhttp', sni='two.example', external_host='two.example', path='/kvn', profile_action='add')
assert request('POST', '/modules/initialize_xray', data)[0] == 303
from v5.modules.xray.config import Settings
settings = Settings.load(path)
assert len(settings.profiles.values) == 2 and not settings.accounts
before = hashlib.sha256(path.read_bytes()).digest()
assert request('POST', '/modules/initialize_xray', data)[0] == 303
assert hashlib.sha256(path.read_bytes()).digest() == before
result = subprocess.run(['/usr/bin/docker', 'ps', '--format', '{{.Names}}'], capture_output=True, check=True)
assert b'kvn-v5-xray' not in result.stdout
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('HTTPS: два профиля Xray сохранены; повтор не меняет настройки, контейнер не запущен.', flush=True)
connection.close()
