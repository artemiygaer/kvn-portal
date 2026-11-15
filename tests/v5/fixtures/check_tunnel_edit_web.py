"""Проверка изменения выхода WG через HTTPS только на учебной VM."""

from dataclasses import replace
import hashlib
import http.client
from pathlib import Path
import re
import socket
import ssl
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.host_tunnel.config import WG
from v5.modules.host_tunnel.state import State

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
path = Path('/var/lib/kvn-v5/modules/wireguard/settings.json')
before = State.load(WG, path)
candidate = None if before.settings.egress else next(name for _, name in socket.if_nameindex()
                                                       if name not in ('lo', 'wg0', 'awg0'))
context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=120)
cookie = signed_fixture_session()


def request(method, path, body=None):
    global cookie
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': 'application/x-www-form-urlencoded'})
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    if response.getheader('Set-Cookie'):
        cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
assert status == 200, f'HTTP {status}'
assert before.settings.private_key not in page, 'Приватный ключ попал в страницу'
csrf = re.search(r'name="csrf" value="([^\"]+)"', page)[1]
forms = re.findall(r'<form[^>]+action="/modules/change_tunnel"[^>]*>(.*?)</form>', page, re.S)
form = next(row for row in forms if 'name="module" value="wireguard"' in row)
revision = re.search(r'name="revision" value="([0-9a-f]{64})"', form)[1]
change = urlencode({'csrf': csrf, 'module': 'wireguard', 'egress': candidate or '', 'revision': revision, 'confirm': 'yes'})
assert request('POST', '/modules/change_tunnel', change)[0] == 303
changed = State.load(WG, path)
assert changed == replace(before, settings=replace(before.settings, egress=candidate))
digest = hashlib.sha256(path.read_bytes()).digest()
assert request('POST', '/modules/change_tunnel', change)[0] == 303
assert hashlib.sha256(path.read_bytes()).digest() == digest
print('HTTPS: изменение WG без потери ключей и отказ устаревшей форме подтверждены.', flush=True)
connection.close()
