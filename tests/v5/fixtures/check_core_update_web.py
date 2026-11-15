"""Проверка обновления через настоящий HTTPS только на учебной VM."""

import http.client
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=240)
    cookie = signed_fixture_session()
    origin = 'https://127.0.0.1:8443'

    def call(method, path, body=None, content_type=None):
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers['Origin'] = origin
            headers['Content-Type'] = content_type
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read().decode('utf-8')

    status, page = call('GET', '/maintenance/update')
    assert status == 200, status
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    boundary = b'KVNCoreUpdateFixtureBoundary'
    archive = Path(sys.argv[1]).read_bytes()
    body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
            + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="bundle"; filename="update.tar"'
            + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive + b'\r\n--' + boundary + b'--\r\n')
    status, _ = call('POST', '/maintenance/update/upload', body, 'multipart/form-data; boundary=' + boundary.decode())
    assert status == 303, status
    status, page = call('GET', '/maintenance/update')
    version = sys.argv[2] if len(sys.argv) > 2 else '5.0.1'
    assert status == 200 and version in page and 'готов' in page.lower(), page[:1000]
    start_form = re.search(r'<form[^>]+action="/maintenance/update/start"[^>]*>(.*?)</form>', page, re.S)[1]
    ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', start_form)[1]
    body = urlencode({'csrf': csrf, 'confirm': 'yes', 'ticket': ticket})
    status, _ = call('POST', '/maintenance/update/start', body, 'application/x-www-form-urlencoded')
    assert status == 303, status
    print('HTTPS: архив проверен, обновление запущено отдельным действием.', flush=True)
    conn.close()


if __name__ == '__main__':
    main()
