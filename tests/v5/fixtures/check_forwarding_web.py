"""Проверить подтверждённое включение forwarding через HTTPS в учебной VM."""

from dataclasses import replace
import http.client
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
from urllib.parse import urlencode

from check_debian_core import signed_fixture_session
from v5.modules.host_tunnel.config import WG
from v5.modules.host_tunnel.state import State

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
connection = http.client.HTTPSConnection('127.0.0.1', 8443,
    context=ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt'), timeout=150)
cookie = signed_fixture_session()


def request(method, path, body=None, content_type=None):
    global cookie
    headers = {'Cookie': cookie}
    if method == 'POST':
        headers.update({'Origin': 'https://127.0.0.1:8443', 'Content-Type': content_type})
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    if response.getheader('Set-Cookie'):
        cookie = response.getheader('Set-Cookie').split(';', 1)[0]
    return response.status, response.read().decode('utf-8')


status, page = request('GET', '/modules')
assert status == 200
csrf = re.search(r'name="csrf" value="([^"]+)"', page)[1]
boundary = b'KVNForwardingFixtureBoundary'
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
path = Path('/var/lib/kvn-v5/modules/wireguard/settings.json')
state = State.load(WG, path)
interfaces = [name for _, name in socket.if_nameindex() if name not in ('lo', 'wg0', 'awg0')]
assert interfaces
replace(state, settings=replace(state.settings, egress=interfaces[0])).save(path)
result = subprocess.run(['/usr/sbin/ip', 'link', 'show', 'wg0'], stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, check=False)
assert result.returncode != 0
Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
data = urlencode({'csrf': csrf, 'module': 'wireguard'})
assert request('POST', '/modules/forwarding', data, kind)[0] == 303
assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '0'
data = urlencode({'csrf': csrf, 'module': 'wireguard', 'confirm': 'yes'})
assert request('POST', '/modules/forwarding', data, kind)[0] == 303
status, page = request('GET', '/modules')
assert status == 200 and 'Пересылка IPv4 включена' in page, (
    status, re.findall(r'<p class="alert" role="alert">([^<]{1,300})</p>', page))
assert Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1'
subprocess.run(['/usr/bin/systemctl', 'is-enabled', '--quiet', 'kvn-v5-forwarding.service'], check=True)
print('HTTPS: подтверждение, подпись WG и включение IPv4 через ограниченный RPC: OK', flush=True)
connection.close()
