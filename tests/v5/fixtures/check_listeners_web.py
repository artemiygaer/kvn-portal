"""Проверка реальных слушателей TCP/UDP через панель изолированной VM."""

import http.client
from pathlib import Path
import socket
import ssl

from check_debian_core import signed_fixture_session


def main():
    assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
         socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        tcp.listen(1)
        udp.bind(('127.0.0.1', 0))
        tcp_port, udp_port = tcp.getsockname()[1], udp.getsockname()[1]
        context = ssl.create_default_context(cafile='/etc/kvn-v5/gateway/bootstrap.crt')
        conn = http.client.HTTPSConnection('127.0.0.1', 8443, context=context, timeout=60)
        try:
            conn.request('GET', '/observability', headers={'Cookie': signed_fixture_session()})
            response = conn.getresponse()
            html = response.read().decode()
            assert response.status == 200, response.status
            assert f'>{tcp_port}<' in html and f'>{udp_port}<' in html
            assert 'Слушающие порты' in html
        finally:
            conn.close()
    print('HTTPS: реальные локальные TCP и UDP отображаются в наблюдении.', flush=True)


if __name__ == '__main__':
    main()
