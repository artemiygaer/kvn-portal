"""Большой запрос импорта только на изолированной VM; ключи синтетические."""

import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import time
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.core.tls.probe import verify_gateway_revision


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    config = Path('/etc/kvn-v5/gateway/nginx.conf')
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    cookie = signed_fixture_session()

    def request(method, path, body=None, content_type=None):
        conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=45)
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': content_type})
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            return response.status, response.read().decode()
        finally:
            conn.close()

    code, page = request('GET', '/settings/tls')
    assert code == 200
    token = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    if 'location = /settings/tls/import {' not in config.read_text():
        code, _ = request('POST', '/settings/tls/prepare', urlencode({'csrf': token}),
                          'application/x-www-form-urlencoded')
        assert code == 303
        for _ in range(150):
            state = subprocess.run(['/usr/bin/systemctl', 'show', '-p', 'ActiveState', '--value',
                                    'kvn-v5-tls.service'], check=True, capture_output=True).stdout.strip()
            if 'location = /settings/tls/import {' in config.read_text() and state == b'inactive':
                break
            time.sleep(2)
        else:
            raise AssertionError('Подготовка конфигурации nginx не выполнена')
    verify_gateway_revision(config.read_bytes(), Path('/etc/kvn-v5/gateway/bootstrap.crt'))
    boundary = b'KVNLargeTLSFixture'
    chunks = []
    for name, value, filename in (('csrf', token.encode(), None), ('name', b'portal.example', None),
                                  ('confirm', b'yes', None), ('chain', b'A' * 32000, 'chain.pem'),
                                  ('key', b'fake-key', 'key.pem')):
        header = f'Content-Disposition: form-data; name="{name}"'
        if filename:
            header += f'; filename="{filename}"'
        chunks.append(b'--' + boundary + b'\r\n' + header.encode() + b'\r\n\r\n' + value + b'\r\n')
    body = b''.join(chunks) + b'--' + boundary + b'--\r\n'
    results = Path('/var/lib/kvn-v5/tls/results.json')
    try:
        before = json.loads(results.read_text()).get('dns-portal.example', {}).get('import', {}).get('updated_at')
    except (FileNotFoundError, ValueError):
        before = None
    code, _ = request('POST', '/settings/tls/import', body,
                      'multipart/form-data; boundary=' + boundary.decode())
    assert code == 303, f'Большой запрос отклонён до проверки: HTTP {code}'
    for _ in range(150):
        try:
            entry = json.loads(results.read_text()).get('dns-portal.example', {}).get('import', {})
            if entry.get('updated_at') != before and entry.get('status') in ('invalid_certificate', 'invalid_key'):
                break
        except (FileNotFoundError, ValueError):
            pass
        time.sleep(2)
    else:
        raise AssertionError('Служба TLS не подтвердила проверку синтетической пары')
    print('HTTPS: запрос более 4 КиБ дошёл до проверки TLS и некорректная пара отклонена.', flush=True)


if __name__ == '__main__':
    main()
