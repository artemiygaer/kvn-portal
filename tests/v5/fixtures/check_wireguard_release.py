"""Установить подписанный WireGuard и зависимости через панель учебной VM."""

import http.client
from http.cookies import SimpleCookie
from pathlib import Path
import re
import ssl
import sys
import time
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
    cookie = signed_fixture_session()

    def request(method, path, body=None, content_type=None):
        nonlocal cookie
        conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=240)
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': content_type})
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            update = response.getheader('Set-Cookie')
            if update:
                jar = SimpleCookie()
                jar.load(update)
                if '__Host-kvn-v5' in jar:
                    cookie = '__Host-kvn-v5=' + jar['__Host-kvn-v5'].value
            return response.status, response.read().decode()
        finally:
            conn.close()

    status, page = request('GET', '/modules')
    assert status == 200
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
    boundary = b'KVNWireGuardFixture'
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
    if not Path('/usr/bin/wg').exists():
        assert request('POST', '/modules/provision', urlencode({'csrf': csrf, 'module': 'wireguard',
                                                                'confirm': 'yes'}), kind)[0] == 303
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            status, page = request('GET', '/modules')
            assert status == 200
            if 'Подготовка зависимостей: wireguard' in page and 'Зависимости подготовлены.' in page:
                break
            if 'Подготовка не завершена:' in page:
                raise RuntimeError('Зависимости WireGuard не установлены')
            time.sleep(5)
        else:
            raise RuntimeError('Не дождались подготовки WireGuard')
    assert Path('/usr/bin/wg').is_file()
    settings = Path('/var/lib/kvn-v5/modules/wireguard/settings.json')
    assert not settings.exists()
    assert request('POST', '/modules/initialize', urlencode({'csrf': csrf, 'module': 'wireguard',
                                                            'egress': '', 'confirm': 'yes'}), kind)[0] == 303
    assert settings.is_file() and settings.stat().st_mode & 0o077 == 0
    print('WireGuard: подписанный пакет, зависимости и настройки подготовлены через HTTPS.', flush=True)


if __name__ == '__main__':
    main()
