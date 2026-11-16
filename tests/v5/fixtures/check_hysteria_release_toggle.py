"""Проверить Hysteria2 с тестовым доверенным TLS только на изолированной VM."""

import hashlib
import http.client
from http.cookies import SimpleCookie
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from check_tls_gateway import make_ca, make_pair
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.probe import check_nginx, reload_nginx, verify_gateway_revision
from v5.core.tls.transaction import publish_gateway


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    identity = TLSIdentity('portal.example', False)
    gateway = Path('/etc/kvn-v5/gateway')
    config = gateway / 'nginx.conf'
    previous = config.read_bytes()
    trust = Path('/etc/ssl/certs/ca-certificates.crt')
    assert trust.is_file() and not trust.is_symlink()
    original_trust = trust.read_bytes()
    imported = Path('/var/lib/kvn-v5/tls/imported.json')
    imported_before = imported.read_bytes() if imported.exists() else None
    results = Path('/var/lib/kvn-v5/tls/results.json')
    results_before = results.read_bytes() if results.exists() else None
    context = ssl.create_default_context(cafile=str(gateway / 'bootstrap.crt'))
    cookie = signed_fixture_session()
    csrf = None
    should_disable = False

    def request(method, path, body=None, kind=None):
        nonlocal cookie
        conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=360)
        headers = {'Cookie': cookie}
        if method == 'POST':
            headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': kind})
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            updated = response.getheader('Set-Cookie')
            if updated:
                jar = SimpleCookie()
                jar.load(updated)
                if '__Host-kvn-v5' in jar:
                    cookie = '__Host-kvn-v5=' + jar['__Host-kvn-v5'].value
            return response.status, response.getheader('Location'), response.read().decode()
        finally:
            conn.close()

    def multipart(fields):
        boundary = b'KVNHysteriaReleaseFixture'
        parts = []
        for name, value, filename in fields:
            header = f'Content-Disposition: form-data; name="{name}"'
            if filename:
                header += f'; filename="{filename}"'
            parts.append(b'--' + boundary + b'\r\n' + header.encode() + b'\r\n\r\n' + value + b'\r\n')
        return b''.join(parts) + b'--' + boundary + b'--\r\n', 'multipart/form-data; boundary=' + boundary.decode()

    def restore_file(path, value):
        if value is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(value)
            path.chmod(0o600)

    try:
        with TemporaryDirectory(prefix='kvn-hysteria-release-') as folder:
            ca, ca_key = make_ca(Path(folder))
            chain, key = make_pair(ca, ca_key, identity, 551)
            trust.write_bytes(original_trust + b'\n' + ca.read_bytes())
            status, _, page = request('GET', '/settings/tls')
            assert status == 200
            csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
            old_stamp = (json.loads(results_before).get(identity.slot, {}).get('import', {}).get('updated_at')
                         if results_before else None)
            body, kind = multipart((('csrf', csrf.encode(), None), ('name', identity.name.encode(), None),
                                    ('confirm', b'yes', None), ('chain', chain, 'chain.pem'), ('key', key, 'key.pem')))
            assert request('POST', '/settings/tls/import', body, kind)[0] == 303
            for _ in range(150):
                try:
                    entry = json.loads(results.read_text()).get(identity.slot, {}).get('import', {})
                    if entry.get('status') == 'active' and entry.get('updated_at') != old_stamp:
                        break
                except (FileNotFoundError, ValueError):
                    pass
                time.sleep(2)
            else:
                raise AssertionError('Тестовый сертификат не применён')
            boundary, kind = multipart((('csrf', csrf.encode(), None),
                                        ('package', Path(sys.argv[1]).read_bytes(), 'module.tar.gz')))
            status, _, page = request('POST', '/modules/upload', boundary, kind)
            assert status == 200 and 'Пакет проверен' in page
            form = re.search(r'<form[^>]+action="/modules/install"[^>]*>(.*?)</form>', page, re.S)[1]
            ticket = re.search(r'name="ticket" value="([0-9a-f]{64})"', form)[1]
            kind = 'application/x-www-form-urlencoded'
            assert request('POST', '/modules/install', urlencode({'csrf': csrf, 'ticket': ticket}), kind)[0] == 303
            settings = Path('/var/lib/kvn-v5/modules/hysteria/settings.json')
            assert not settings.exists()
            assert request('POST', '/modules/initialize_hysteria', urlencode({
                'csrf': csrf, 'identity': identity.name, 'port': '443', 'confirm': 'yes'}), kind)[0] == 303
            assert settings.is_file() and settings.stat().st_mode & 0o077 == 0
            status, location, _ = request('POST', '/users', urlencode({'csrf': csrf, 'name': 'lab-hysteria'}), kind)
            assert status == 303 and re.fullmatch(r'/users/[A-Za-z0-9_-]+', location)
            status, _, page = request('GET', location)
            assert status == 200
            revision = re.search(r'name="revision" value="([0-9]+)"', page)[1]
            assert request('POST', location + '/grant', urlencode({'csrf': csrf, 'module': 'hysteria',
                                                                  'enabled': 'yes', 'revision': revision}), kind)[0] == 303
            action = urlencode({'csrf': csrf, 'module': 'hysteria', 'confirm': 'yes'})
            should_disable = True
            assert request('POST', '/modules/enable', action, kind)[0] == 303
            status, _, page = request('GET', '/modules')
            assert status == 200 and 'Модуль включён.' in page
            assert b':443 ' in subprocess.run(['/usr/bin/ss', '-Hlun'], capture_output=True, check=True).stdout
            enabled_hash = hashlib.sha256(settings.read_bytes()).digest()
            assert request('POST', '/modules/disable', action, kind)[0] == 303
            should_disable = False
            assert b':443 ' not in subprocess.run(['/usr/bin/ss', '-Hlun'], capture_output=True, check=True).stdout
            assert hashlib.sha256(settings.read_bytes()).digest() == enabled_hash
            print('Hysteria2: подписанный модуль включён и выключен; порт закрыт, настройки сохранены.', flush=True)
    finally:
        try:
            if should_disable and csrf:
                request('POST', '/modules/disable', urlencode({'csrf': csrf, 'module': 'hysteria', 'confirm': 'yes'}),
                        'application/x-www-form-urlencoded')
            current = config.read_bytes()
            if current != previous:
                publish_gateway(config, previous, check=check_nginx, reload=reload_nginx,
                                verify_live=lambda: verify_gateway_revision(previous, gateway / 'bootstrap.crt'),
                                verify_restored=lambda: verify_gateway_revision(current, gateway / 'bootstrap.crt'),
                                expected=current)
        finally:
            try:
                restore_file(imported, imported_before)
                restore_file(results, results_before)
            finally:
                trust.write_bytes(original_trust)


if __name__ == '__main__':
    main()
