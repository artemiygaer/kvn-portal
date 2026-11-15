"""Настроить выключенный тестовый WireGuard через HTTPS в учебной VM."""

import hashlib
import http.client
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=240)
cookie = signed_fixture_session()
origin = 'https://127.0.0.1:8443'


def request(method, path, *, body=None, content_type=None):
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': origin, 'Content-Type': content_type})
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
assert status == 200
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
boundary = b'KVNTunnelFixtureBoundary'
archive = Path(sys.argv[1]).read_bytes()
body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
        + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="package"; filename="module.tar.gz"'
        + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive + b'\r\n--' + boundary + b'--\r\n')
status, page = request('POST', '/modules/upload', body=body,
                       content_type='multipart/form-data; boundary=' + boundary.decode())
assert status == 200 and 'Пакет проверен' in page, status
form = re.search(r'<form[^>]+action="/modules/install"[^>]*>(.*?)</form>', page, re.S)[1]
ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
form_type = 'application/x-www-form-urlencoded'
status, _ = request('POST', '/modules/install', body=urlencode({'csrf': csrf, 'ticket': ticket}),
                    content_type=form_type)
assert status == 303
status, page = request('GET', '/modules')
assert status == 200 and 'Создать настройки туннеля' in page
data = urlencode({'csrf': csrf, 'module': 'wireguard', 'egress': '', 'confirm': 'yes'})
status, _ = request('POST', '/modules/initialize', body=data, content_type=form_type)
assert status == 303
path = Path('/var/lib/kvn-v5/modules/wireguard/settings.json')
assert path.is_file() and path.stat().st_mode & 0o077 == 0
before = hashlib.sha256(path.read_bytes()).digest()
status, _ = request('POST', '/modules/initialize', body=data, content_type=form_type)
assert status == 303 and hashlib.sha256(path.read_bytes()).digest() == before
assert not Path('/sys/class/net/wg0').exists()
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('HTTPS: модуль проверен, установлен выключенным; настройки созданы без замены ключей.', flush=True)
connection.close()
