"""Контракт генератора TLS для nginx; реальная сеть проверяется отдельно."""

from datetime import datetime, timezone
from pathlib import Path
import unittest

from v5.core.tls.certificates import CertificateInfo
from v5.core.tls.gateway import admin_hosts, render_gateway
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.transaction import StoredPair
from v5.core.network.plan import Binding, ModuleNetwork, Route, build_plan


def pair(identity, base=Path("/etc/kvn-v5/gateway/certs")):
    now = datetime.now(timezone.utc)
    directory = base / identity.slot / "fixture"
    return StoredPair(CertificateInfo(identity, now, now), directory / "fullchain.pem", directory / "privkey.pem")


class GatewayRenderingTests(unittest.TestCase):
    def test_stream_module_loads_before_events_and_keeps_admin_on_8443(self):
        name = TLSIdentity("portal.example", False)
        route = Route("vpn.example", Binding("tcp", "127.0.0.1", 12443))
        network = build_plan((ModuleNetwork("xray", True, (route,)),), site_names=(name.name,))
        config = render_gateway((name,), ipv6=True, pairs=(pair(name),), network=network)
        self.assertLess(config.index("load_module"), config.index("events {"))
        self.assertIn("listen 127.0.0.1:10443 ssl", config)
        self.assertIn("listen [::1]:10443 ssl", config)
        self.assertNotIn("listen 443 ssl", config)
        self.assertIn("listen 8443 ssl", config)
        self.assertIn("location = /__kvn_gateway_revision", config)

    def test_each_dns_name_and_ip_use_same_pair_on_443_and_8443(self):
        names = (TLSIdentity("portal.example", False), TLSIdentity("www.portal.example", False),
                 TLSIdentity("192.0.2.8", True), TLSIdentity("2001:db8::8", True))
        pairs = tuple(map(pair, names))
        config = render_gateway(names, ipv6=True, pairs=pairs)
        self.assertEqual(config.count("map_hash_bucket_size 1024;"), 1)
        for item in pairs:
            self.assertEqual(config.count(f"ssl_certificate {item.chain};"), 2)
            self.assertEqual(config.count(f"ssl_certificate_key {item.key};"), 2)
        self.assertIn('"portal.example|portal.example:8443" "dns-portal.example";', config)
        self.assertIn('"|192.0.2.8:8443" "ip-192.0.2.8";', config)
        self.assertIn('"|[2001:db8::8]" "ip-2001_db8__8";', config)
        self.assertNotIn('"portal.example|www.portal.example', config)
        self.assertIn("listen [::]:443 ssl default_server ipv6only=on;", config)
        self.assertIn("listen 8443 ssl default_server reuseport;", config)
        self.assertIn("listen 127.0.0.1:8443 ssl reuseport;", config)
        self.assertEqual(config.count("proxy_pass http://portal;"), 15 * (len(names) + 1))
        self.assertEqual(config.count("location = /modules {"), len(names) + 1)
        self.assertEqual(config.count('location ~ "^/modules/[a-z_]+$" {'), len(names) + 1)
        self.assertEqual(config.count("location = /observability/history {"), len(names) + 1)
        self.assertEqual(config.count("location = /maintenance/update/upload {"), len(names) + 1)
        self.assertEqual(config.count("client_max_body_size 12544k;"), len(names) + 1)
        self.assertEqual(config.count('location ~ "^/users/migration(?:/|$)" {'), len(names) + 1)
        self.assertEqual(config.count("client_max_body_size 8320k;"), len(names) + 1)
        self.assertEqual(config.count('location ~ "^/users/" {'), len(names) + 1)
        self.assertNotIn("location /users/ {", config)
        self.assertEqual(config.count("location ^~ /sub/ {"), len(names) + 1)
        self.assertEqual(config.count("error_log /dev/null crit;"), 2 * (len(names) + 1))
        self.assertEqual(config.count("location = /maintenance/console/ws {"), len(names) + 1)
        self.assertEqual(config.count("proxy_pass http://unix:/run/kvn-v5-console-web.sock;"), len(names) + 1)
        self.assertEqual(config.count("location @console_unavailable { return 404; }"), len(names) + 1)
        self.assertEqual(config.count("limit_req zone=kvn_sub_ip"), len(names) + 1)
        self.assertEqual(config.count("client_max_body_size 136k;"), len(names) + 1)
        self.assertEqual(config.count("location = /modules/upload {"), len(names) + 1)
        self.assertEqual(config.count("proxy_request_buffering off;"), 2 * (len(names) + 1))
        self.assertEqual(config.count("location / { return 404; }"), len(names))
        self.assertIn("sandbox allow-top-navigation-by-user-activation", config)
        self.assertEqual(admin_hosts(names), ["127.0.0.1:8443", "localhost:8443", "portal.example:8443",
                                             "www.portal.example:8443", "192.0.2.8:8443", "[2001:db8::8]:8443"])

    def test_without_ip_certificate_fallback_rejects_handshake(self):
        name = TLSIdentity("one.example", False)
        config = render_gateway((name,), ipv6=False, pairs=(pair(name),))
        self.assertEqual(config.count("ssl_reject_handshake on;"), 2)
        self.assertNotIn("[::]:443", config)

    def test_unregistered_duplicate_and_injected_paths_refused(self):
        name = TLSIdentity("one.example", False)
        bad_path = pair(name, Path("/a; #"))
        for pairs in ((pair(TLSIdentity("other.example", False)),), (pair(name), pair(name)), (bad_path,)):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                render_gateway((name,), ipv6=False, pairs=pairs)
