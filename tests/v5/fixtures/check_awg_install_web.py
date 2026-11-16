"""Установить AWG 3.1 через HTTPS только в изолированной учебной VM."""

import http.client
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.host_tunnel.config import AWG
from v5.modules.host_tunnel.platform import capability

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
assert not Path('/usr/bin/awg').exists()
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
if sys.argv[1] != '--resume':
    boundary = b'KVNAwgInstallBoundary'
    archive = Path(sys.argv[1]).read_bytes()
    body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
            + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="package"; filename="module.tar.gz"'
            + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive + b'\r\n--' + boundary + b'--\r\n')
    status, page = request('POST', '/modules/upload', body, 'multipart/form-data; boundary=' + boundary.decode())
    assert status == 200 and 'Пакет проверен' in page
    form = re.search(r'<form[^>]+action="/modules/install"[^>]*>(.*?)</form>', page, re.S)[1]
    ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
    status, _ = request('POST', '/modules/install', urlencode({'csrf': csrf, 'ticket': ticket}), kind)
    assert status == 303
status, _ = request('POST', '/modules/provision',
                    urlencode({'csrf': csrf, 'module': 'amneziawg', 'confirm': 'yes'}), kind)
assert status == 303
deadline = time.monotonic() + 2400
while time.monotonic() < deadline:
    status, page = request('GET', '/modules')
    assert status == 200
    if 'Подготовка зависимостей: amneziawg' in page and 'Зависимости подготовлены.' in page:
        break
    if 'Подготовка не завершена:' in page:
        raise RuntimeError('Подготовка AWG отклонена; см. root-only журнал задачи')
    time.sleep(10)
else:
    raise RuntimeError('Не дождались установки AWG')
host = capability(AWG)
assert host.issue is None and '3.1' in host.profiles
assert not Path('/sys/class/net/awg0').exists()
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('HTTPS → подписанный пакет → APT/DKMS → ABI AWG 3.1 подтверждён; awg0 выключен.', flush=True)
connection.close()
