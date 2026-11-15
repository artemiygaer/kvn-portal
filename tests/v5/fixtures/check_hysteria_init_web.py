"""Начальная настройка Hysteria2 только через HTTPS учебной Debian VM."""

import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.hysteria.config import Settings

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
gateway = json.loads(Path('/etc/kvn-v5/gateway/identities.json').read_text())
identity = gateway['names'][0] if gateway['names'] else gateway['ip']
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
boundary = b'KVNHysteriaFixtureBoundary'
archive = Path(sys.argv[1]).read_bytes()
body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
        + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="package"; filename="module.tar.gz"'
        + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive + b'\r\n--' + boundary + b'--\r\n')
status, page = request('POST', '/modules/upload', body, 'multipart/form-data; boundary=' + boundary.decode())
assert status == 200 and 'Пакет проверен' in page
form = re.search(r'<form[^>]+action="/modules/install"[^>]*>(.*?)</form>', page, re.S)[1]
ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
kind = 'application/x-www-form-urlencoded'
assert request('POST', '/modules/install', urlencode({'csrf': csrf, 'ticket': ticket}), kind)[0] == 303
data = urlencode({'csrf': csrf, 'identity': identity, 'port': '443', 'salamander': 'yes', 'confirm': 'yes'})
path = Path('/var/lib/kvn-v5/modules/hysteria/settings.json')
assert not path.exists()
assert request('POST', '/modules/initialize_hysteria', data, kind)[0] == 303
assert path.is_file() and path.stat().st_mode & 0o077 == 0
settings = Settings.load(path)
assert settings.tls.name == identity and settings.port == 443 and settings.salamander
before = hashlib.sha256(path.read_bytes()).digest()
assert request('POST', '/modules/initialize_hysteria', data, kind)[0] == 303
assert hashlib.sha256(path.read_bytes()).digest() == before
status, page = request('GET', '/modules')
assert status == 200 and settings.salamander not in page
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('HTTPS: Hysteria2 настроен выключенным; секрет не отображается, повтор не меняет файл.', flush=True)
connection.close()
