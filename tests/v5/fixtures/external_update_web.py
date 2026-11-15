"""Проверить подписанное обновление через HTTPS на выделенном внешнем стенде."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlencode

from flask import Flask


def main():
    if len(sys.argv) != 6 or os.geteuid() != 0:
        return 2
    hostname, container, bundle, expected_digest, version = sys.argv[1:]
    if socket.gethostname() != hostname or re.fullmatch(r'[0-9a-f]{64}', expected_digest) is None:
        raise RuntimeError('Идентичность стенда или SHA-256 не совпадают')
    archive = Path(bundle).read_bytes()
    if hashlib.sha256(archive).hexdigest() != expected_digest:
        raise RuntimeError('SHA-256 обновления не совпал')
    app = Flask(__name__)
    app.secret_key = json.loads(Path('/etc/kvn-v5/web/config.json').read_text())['session_key']
    csrf = secrets.token_urlsafe(24)
    cookie = '__Host-kvn-v5=' + app.session_interface.get_signing_serializer(app).dumps(
        {'admin': True, '_permanent': True, 'csrf': csrf})
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=240)

    def request(method, path, body=None, content_type=None):
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': content_type})
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, response.read().decode('utf-8')

    boundary = b'KVNExternalUpdateBoundary'
    body = (b'--' + boundary + b'\r\nContent-Disposition: form-data; name="csrf"\r\n\r\n' + csrf.encode()
            + b'\r\n--' + boundary + b'\r\nContent-Disposition: form-data; name="bundle"; filename="update.tar"'
            + b'\r\nContent-Type: application/octet-stream\r\n\r\n' + archive + b'\r\n--' + boundary + b'--\r\n')
    assert request('POST', '/maintenance/update/upload', body, 'multipart/form-data; boundary=' + boundary.decode())[0] == 303
    status, page = request('GET', '/maintenance/update')
    assert status == 200 and version in page and 'готов' in page.lower()
    form = re.search(r'<form[^>]+action="/maintenance/update/start"[^>]*>(.*?)</form>', page, re.S)[1]
    ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
    assert request('POST', '/maintenance/update/start', urlencode({'csrf': csrf, 'confirm': 'yes', 'ticket': ticket}),
                   'application/x-www-form-urlencoded')[0] == 303
    conn.close()
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        states = [json.loads(path.read_text()) for path in Path('/var/lib/kvn-v5/core-updates').glob('*/state.json')]
        records = sorted((row for row in states if row['version'] == version), key=lambda row: row['created'], reverse=True)
        if records and records[0]['status'] == 'failed':
            raise RuntimeError('Обновление завершилось ошибкой')
        if records and records[0]['status'] == 'applied':
            break
        time.sleep(3)
    else:
        raise RuntimeError('Результат обновления не подтверждён')
    assert Path('/usr/local/lib/kvn-v5/core-version').read_text().strip() == version
    assert not Path('/usr/local/lib/.kvn-v5-core/pending').exists()
    for unit in ('kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'):
        subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', unit], check=True, timeout=15)
    state = subprocess.run(['/usr/bin/docker', 'inspect', '--format', '{{.State.Running}}', container],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=True, text=True, timeout=15).stdout.strip()
    assert state == 'true'
    print(f'Подписанное обновление {version} применено через портал; существующий контейнер работает.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
