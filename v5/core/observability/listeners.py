"""Ограниченный снимок слушающих TCP/UDP-сокетов без аргументов процессов."""

from ipaddress import ip_address
import re

from .ssh import _query

COMMAND = ('/usr/bin/ss', '-H', '-lntu', '-p')
MAX_ROWS = 256
_OWNER = re.compile(r'"([A-Za-z0-9_.@+-]{1,64})",pid=([0-9]{1,10}),fd=[0-9]{1,10}')


def listeners(*, query=_query):
    rows, partial = [], False
    for line in query(COMMAND).splitlines():
        if len(rows) >= MAX_ROWS:
            partial = True
            break
        fields = line.split(None, 6)
        if len(fields) < 6 or fields[0] not in ('tcp', 'udp'):
            partial = True
            continue
        address, separator, port = fields[4].rpartition(':')
        address = address.strip('[]')
        try:
            address = '*' if address == '*' else str(ip_address(address.split('%', 1)[0]))
            port_number = int(port)
            if not separator or not 1 <= port_number <= 65535:
                raise ValueError('Недопустимый порт')
        except ValueError:
            partial = True
            continue
        owners = []
        for name, pid in _OWNER.findall(fields[6] if len(fields) > 6 else '')[:8]:
            value = {'name': name, 'pid': int(pid)}
            if value not in owners:
                owners.append(value)
        rows.append({'protocol': fields[0], 'address': address, 'port': port_number, 'owners': owners})
    return rows, partial
