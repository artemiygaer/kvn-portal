"""Ограниченный вывод портов и приватность данных процессов."""

from unittest import TestCase
from v5.core.observability.listeners import listeners


class ListenerTests(TestCase):
    def test_tcp_udp_ipv6_and_unknown_owner(self):
        raw = ('tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=15,fd=3))\n'
               'udp UNCONN 0 0 [::]:443 [::]:*\n')
        rows, partial = listeners(query=lambda _: raw)
        self.assertFalse(partial)
        self.assertEqual(rows[0], {'protocol': 'tcp', 'address': '0.0.0.0', 'port': 80,
                                   'owners': [{'name': 'nginx', 'pid': 15}]})
        self.assertEqual(rows[1], {'protocol': 'udp', 'address': '::', 'port': 443, 'owners': []})

    def test_bounded_and_sanitized(self):
        raw = 'tcp LISTEN 0 1 127.0.0.1:8443 0.0.0.0:* users:(("bad secret",pid=12,fd=3))\n'
        rows, partial = listeners(query=lambda _: raw * 257)
        self.assertTrue(partial)
        self.assertEqual(len(rows), 256)
        self.assertNotIn('secret', repr(rows))
        self.assertEqual(rows[0]['owners'], [])

    def test_invalid_rows_mark_partial(self):
        rows, partial = listeners(query=lambda _: 'tcp LISTEN 0 1 example:99999 *:*\n')
        self.assertTrue(partial)
        self.assertEqual(rows, [])
