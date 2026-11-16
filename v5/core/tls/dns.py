"""Ограниченная диагностика DNS только для зарегистрированного имени."""

from ipaddress import ip_address
import os
import select
import subprocess
import time

from .identity import TLSIdentity

MAX_OUTPUT = 64 * 1024
MAX_ADDRESSES = 16


def _query(name: str, timeout: float = 5.0) -> str:
    deadline = time.monotonic() + timeout
    data = bytearray()
    with subprocess.Popen(['/usr/bin/getent', 'ahosts', name], stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}) as process:
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                    raise subprocess.TimeoutExpired('getent', timeout)
                chunk = os.read(process.stdout.fileno(), min(8192, MAX_OUTPUT + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_OUTPUT:
                    raise ValueError('Ответ DNS слишком большой')
            if process.wait(timeout=max(0.001, deadline - time.monotonic())):
                raise ValueError('DNS не вернул адреса')
        finally:
            if process.poll() is None:
                process.kill()
    return data.decode('ascii', 'strict')


def diagnose(identity: TLSIdentity, server: TLSIdentity, *, query=_query) -> dict:
    if identity.is_ip or not server.is_ip:
        raise ValueError('Для диагностики нужно зарегистрированное DNS-имя и IP сервера')
    try:
        output = query(identity.name)
        addresses = sorted({str(ip_address(line.split()[0])) for line in output.splitlines() if line.split()})
        if not addresses:
            raise ValueError('DNS не вернул адреса')
        truncated = len(addresses) > MAX_ADDRESSES
        return {'status': 'match' if server.name in addresses else 'mismatch',
                'addresses': addresses[:MAX_ADDRESSES], 'truncated': truncated}
    except subprocess.TimeoutExpired:
        return {'status': 'timeout', 'addresses': [], 'truncated': False}
    except (OSError, ValueError, UnicodeError):
        return {'status': 'unavailable', 'addresses': [], 'truncated': False}
