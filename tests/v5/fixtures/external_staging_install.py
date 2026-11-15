"""Установить тестовый кандидат на явно выделенный внешний стенд.

Пароль администратора создаётся в памяти и не выводится. Существующий контейнер
проверяется, но не изменяется. После испытаний доступ восстанавливается по SSH.
"""

import ipaddress
import os
import secrets
import socket
import subprocess
import sys

from v5.install import setup


def main():
    if len(sys.argv) != 5 or os.geteuid() != 0:
        return 2
    ip, domain, hostname, container = sys.argv[1:]
    if not ipaddress.ip_address(ip).is_global or socket.gethostname() != hostname:
        raise RuntimeError('Идентичность внешнего стенда не совпала')
    addresses = {row[4][0] for row in socket.getaddrinfo(domain, 80, type=socket.SOCK_STREAM)}
    if ip not in addresses:
        raise RuntimeError('DNS не указывает на выбранный тестовый сервер')
    status = subprocess.run(['/usr/bin/docker', 'inspect', '--format', '{{.State.Running}}', container],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, text=True, timeout=15).stdout.strip()
    if status != 'true':
        raise RuntimeError('Контейнер наблюдения не работает до начала теста')
    password = secrets.token_urlsafe(32)
    answers = iter(('', ip, domain, 'admin', 'yes'))
    result = setup.main(['--with-acme'], ask=lambda _prompt: next(answers), password_prompt=lambda _prompt: password)
    if result:
        return result
    status = subprocess.run(['/usr/bin/docker', 'inspect', '--format', '{{.State.Running}}', container],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=True, text=True, timeout=15).stdout.strip()
    if status != 'true':
        raise RuntimeError('После установки контейнер наблюдения недоступен')
    print('Кандидат установлен, контейнер наблюдения работает; пароль администратора не выводился.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
