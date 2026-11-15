"""Проверка фоновой задачи подготовки через HTTPS только в учебной VM."""

import http.client
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=60)
cookie = signed_fixture_session()
origin = 'https://127.0.0.1:8443'
module = sys.argv[1] if len(sys.argv) >= 2 else 'wireguard'
assert module in ('wireguard', 'xray')
wait_only = len(sys.argv) == 3 and sys.argv[2] == '--wait-only'


def request(method, path, body=None):
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': origin, 'Content-Type': 'application/x-www-form-urlencoded'})
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    return response.status, response.read().decode('utf-8')


if not wait_only:
    status, page = request('GET', '/modules')
    assert status == 200
    assert 'Подготовить зависимости' in page
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    body = urlencode({'csrf': csrf, 'module': module, 'confirm': 'yes'})
    status, _ = request('POST', '/modules/provision', body)
    assert status == 303
deadline = time.monotonic() + 1200
transient = 0
while time.monotonic() < deadline:
    status, page = request('GET', '/modules')
    if status in (502, 503, 504) and transient < 3:
        transient += 1
        time.sleep(5)
        continue
    assert status == 200
    if 'Зависимости подготовлены.' in page and f'Подготовка зависимостей: {module}' in page:
        break
    if 'Подготовка не завершена:' in page:
        raise RuntimeError('Фоновая подготовка отклонена; см. защищённый журнал задачи')
    time.sleep(2)
else:
    raise RuntimeError('Не дождались результата фоновой подготовки')
assert not Path('/sys/class/net/wg0').exists()
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print(f'HTTPS → RPC → systemd → подготовка {module}: готово; модуль выключен. '
      f'Временных ошибок шлюза: {transient}.', flush=True)
connection.close()
