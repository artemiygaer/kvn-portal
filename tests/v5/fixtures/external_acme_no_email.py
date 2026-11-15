"""Выпуск тестового или публичного сертификата через HTTPS-панель без email."""

import http.client
import ipaddress
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
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.queue import TLSQueue


def main():
    if len(sys.argv) != 7 or os.geteuid() != 0:
        return 2
    ip, domain, hostname, container, mode, identity_name = sys.argv[1:]
    if mode not in ('staging', 'public') or not ipaddress.ip_address(ip).is_global or socket.gethostname() != hostname:
        raise RuntimeError('Идентичность внешнего стенда не совпала')
    if identity_name not in (ip, domain):
        raise RuntimeError('Имя сертификата не относится к тестовому стенду')
    if ip not in {row[4][0] for row in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)}:
        raise RuntimeError('DNS не указывает на тестовый сервер')
    queue, slot = TLSQueue(), TLSIdentity(identity_name, identity_name == ip).slot
    old = queue.snapshot()['results'].get(slot, {}).get(mode, {}).get('updated_at')
    app = Flask(__name__)
    app.secret_key = json.loads(Path('/etc/kvn-v5/web/config.json').read_text())['session_key']
    serializer = app.session_interface.get_signing_serializer(app)
    csrf = secrets.token_urlsafe(24)
    cookie = '__Host-kvn-v5=' + serializer.dumps({'admin': True, '_permanent': True, 'csrf': csrf})
    tls = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    connection = http.client.HTTPSConnection('127.0.0.1', 8443, context=tls, timeout=20)
    body = urlencode({'name': identity_name, 'mode': mode, 'email': '', 'csrf': csrf})
    connection.request('POST', '/settings/tls', body, headers={'Cookie': cookie,
                       'Origin': 'https://127.0.0.1:8443', 'Content-Type': 'application/x-www-form-urlencoded'})
    response = connection.getresponse()
    assert response.status == 303
    response.read()
    connection.close()
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        data = queue.snapshot()
        entry = data['results'].get(slot, {}).get(mode)
        if not data['busy'] and entry and entry.get('updated_at') != old:
            expected = 'staging_issued' if mode == 'staging' else 'active'
            if entry.get('status') != expected:
                raise RuntimeError('ACME: ' + str(entry.get('status')))
            break
        time.sleep(3)
    else:
        raise RuntimeError('Таймаут ожидания результата ACME')
    state = subprocess.run(['/usr/bin/docker', 'inspect', '--format', '{{.State.Running}}', container],
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           check=True, text=True, timeout=15).stdout.strip()
    if state != 'true':
        raise RuntimeError('Контейнер наблюдения недоступен после проверки')
    print(f'HTTPS: {mode} для {identity_name}, выпуск без email подтверждён; дата окончания {entry.get("expires_at")}.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
