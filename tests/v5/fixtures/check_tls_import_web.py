"""Проверить импорт и DNS через HTTPS только внутри изолированной VM."""

import http.client
import json
from pathlib import Path
import re
import ssl
import time
from tempfile import TemporaryDirectory
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from check_tls_gateway import make_ca, make_pair
from v5.core.tls.identity import TLSIdentity


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    identity = TLSIdentity('portal.example', False)
    results = Path('/var/lib/kvn-v5/tls/results.json')
    trust = Path('/etc/ssl/certs/ca-certificates.crt')
    assert trust.is_file() and not trust.is_symlink()
    with TemporaryDirectory(prefix='kvn-import-lab-') as folder:
        ca, ca_key = make_ca(Path(folder))
        chain, key = make_pair(ca, ca_key, identity, 301)
        _, wrong_key = make_pair(ca, ca_key, identity, 302)
        original_trust = trust.read_bytes()
        trust.write_bytes(original_trust + b'\n' + ca.read_bytes())
        try:
            context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
            cookie = signed_fixture_session()

            def call(method, path, body=None, content_type=None):
                # Reload nginx штатно завершает keep-alive предыдущего worker.
                conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=45)
                headers = {'Cookie': cookie}
                if method == 'POST':
                    headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': content_type})
                try:
                    conn.request(method, path, body=body, headers=headers)
                    response = conn.getresponse()
                    return response.status, response.read().decode()
                finally:
                    conn.close()

            status, page = call('GET', '/settings/tls')
            assert status == 200
            csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]

            def send(chain_bytes, key_bytes):
                try:
                    previous_stamp = json.loads(results.read_text()).get(identity.slot, {}).get('import', {}).get('updated_at')
                except (FileNotFoundError, ValueError):
                    previous_stamp = None
                boundary = b'KVNImportLabBoundary'
                parts = []
                for name, value, filename in (('csrf', csrf.encode(), None), ('name', identity.name.encode(), None),
                                              ('confirm', b'yes', None), ('chain', chain_bytes, 'chain.pem'),
                                              ('key', key_bytes, 'key.pem')):
                    disposition = f'Content-Disposition: form-data; name="{name}"'
                    if filename:
                        disposition += f'; filename="{filename}"'
                    parts.append(b'--' + boundary + b'\r\n' + disposition.encode() + b'\r\n\r\n' + value + b'\r\n')
                body = b''.join(parts) + b'--' + boundary + b'--\r\n'
                assert call('POST', '/settings/tls/import', body,
                            'multipart/form-data; boundary=' + boundary.decode())[0] == 303
                return previous_stamp

            def wait(expected, previous_stamp):
                for _ in range(120):
                    try:
                        entry = json.loads(results.read_text()).get(identity.slot, {}).get('import', {})
                        if entry.get('status') == expected and entry.get('updated_at') != previous_stamp:
                            return
                    except (FileNotFoundError, ValueError):
                        pass
                    time.sleep(2)
                raise AssertionError('Не получен ожидаемый результат TLS: ' + expected)

            before = send(chain, key)
            wait('active', before)
            valid = ssl.create_default_context(cafile=str(ca))
            conn_dns = http.client.HTTPSConnection('portal.example', 8443, context=valid, timeout=30)
            # DNS фикстуры разрешается только в этой изолированной VM.
            hosts = Path('/etc/hosts')
            previous = hosts.read_bytes()
            try:
                # 127.0.0.1:8443 зарезервирован для bootstrap; vhost имени слушает wildcard.
                hosts.write_bytes(previous + b'\n127.0.0.2 portal.example\n')
                conn_dns.request('GET', '/login')
                assert conn_dns.getresponse().status == 200
                conn_dns.close()
                before = send(chain, wrong_key)
                wait('key_mismatch', before)
                conn_dns = http.client.HTTPSConnection('portal.example', 8443, context=valid, timeout=30)
                conn_dns.request('GET', '/login')
                assert conn_dns.getresponse().status == 200
                conn_dns.close()
                assert call('POST', '/settings/tls/diagnose', urlencode({'csrf': csrf, 'name': identity.name}),
                            'application/x-www-form-urlencoded')[0] == 303
                for _ in range(120):
                    dns = json.loads(results.read_text()).get(identity.slot, {}).get('dns', {})
                    if dns.get('status') == 'mismatch' and '127.0.0.2' in dns.get('addresses', []):
                        break
                    time.sleep(2)
                else:
                    raise AssertionError('Диагностика DNS не подтвердила адрес тестового стенда')
            finally:
                hosts.write_bytes(previous)
            conn_dns = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=30)
            conn_dns.request('GET', '/login')
            assert conn_dns.getresponse().status == 200
            conn_dns.close()
            print('HTTPS: доверенная пара импортирована; неверный ключ отклонён, доступ сохранён.', flush=True)
        finally:
            trust.write_bytes(original_trust)


if __name__ == '__main__':
    main()
