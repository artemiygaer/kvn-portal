"""Контракт выбора адреса для клиентских конфигураций."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from tools.kvnlib.client_export import (
    ClientExportPolicy,
    ClientExportValidationError,
    client_connection_host,
    normalize_client_export_state,
    subscription_ip_readiness,
    validate_public_ipv4,
)


ROOT = Path(__file__).resolve().parents[1]


class ClientExportPolicyTests(unittest.TestCase):
    def test_legacy_state_uses_server_without_rewrite(self) -> None:
        state = {"server": "vpn.example.test", "users": []}
        before = copy.deepcopy(state)

        policy = ClientExportPolicy.from_state(state)
        normalized_policy, changed = normalize_client_export_state(state)

        self.assertEqual(policy, ClientExportPolicy())
        self.assertEqual(normalized_policy, policy)
        self.assertEqual(client_connection_host(state), "vpn.example.test")
        self.assertFalse(changed)
        self.assertEqual(state, before)
        self.assertNotIn("client_export", state)

    def test_explicit_policy_is_normalized(self) -> None:
        state = {
            "server": "vpn.example.test",
            "client_export": {
                "address_mode": " PUBLIC-IP ",
                "public_ip": " 8.8.4.4 ",
                "include_alternate": True,
            },
        }

        policy, changed = normalize_client_export_state(state)

        self.assertTrue(changed)
        self.assertEqual(policy.address_mode, "public-ip")
        self.assertEqual(
            state["client_export"],
            {
                "address_mode": "public-ip",
                "public_ip": "8.8.4.4",
                "include_alternate": True,
            },
        )

    def test_public_ipv4_validation_matrix(self) -> None:
        self.assertEqual(validate_public_ipv4("8.8.4.4"), "8.8.4.4")
        rejected = (
            "",
            "not-an-ip",
            "2606:4700:4700::1111",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "224.0.0.1",
            "240.0.0.1",
            "0.0.0.0",
        )
        for value in rejected:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ClientExportValidationError,
                    r"(IPv4|публичн)",
                ):
                    validate_public_ipv4(value)

    def test_public_ip_mode_requires_address(self) -> None:
        state = {
            "server": "vpn.example.test",
            "client_export": {"address_mode": "public-ip"},
        }
        with self.assertRaisesRegex(
            ClientExportValidationError,
            "не указан",
        ):
            ClientExportPolicy.from_state(state)

    def test_resolver_is_pure_and_preserves_identity_fields(self) -> None:
        state = {
            "server": "vpn.example.test",
            "subscription": {"public_host": "sub.example.test"},
            "letsencrypt": {"domains": ["vpn.example.test"]},
            "sni_routes": {
                "reality-xhttp": {
                    "default": "github.com",
                    "aliases": ["github.com"],
                }
            },
            "users": [
                {
                    "name": "test",
                    "sni": {"reality-xhttp": "github.com"},
                }
            ],
            "client_export": {
                "address_mode": "public-ip",
                "public_ip": "8.8.4.4",
                "include_alternate": False,
            },
        }
        before = copy.deepcopy(state)

        self.assertEqual(client_connection_host(state), "8.8.4.4")
        self.assertEqual(state, before)
        self.assertEqual(state["server"], "vpn.example.test")
        self.assertEqual(
            state["subscription"]["public_host"],
            "sub.example.test",
        )
        self.assertEqual(
            state["sni_routes"]["reality-xhttp"]["default"],
            "github.com",
        )
        self.assertEqual(
            state["letsencrypt"]["domains"],
            ["vpn.example.test"],
        )

    def test_server_mode_preserves_domain_and_idn_identity(self) -> None:
        for host in ("vpn.example.test", "пример.рф"):
            with self.subTest(host=host):
                state = {
                    "server": host,
                    "client_export": {"address_mode": "server"},
                }
                self.assertEqual(client_connection_host(state), host)

    def test_subscription_ip_readiness_requires_route_and_exact_ip_san(
        self,
    ) -> None:
        state = {
            "server": "vpn.example.test",
            "client_export": {
                "address_mode": "public-ip",
                "public_ip": "8.8.4.4",
            },
        }

        no_route = subscription_ip_readiness(
            state,
            routed_hosts=(),
            certificate_ip_sans=("8.8.4.4",),
        )
        no_san = subscription_ip_readiness(
            state,
            routed_hosts=("8.8.4.4",),
            certificate_ip_sans=("1.1.1.1", "vpn.example.test"),
        )
        ready = subscription_ip_readiness(
            state,
            routed_hosts=("8.8.4.4",),
            certificate_ip_sans=("8.8.4.4",),
        )

        self.assertFalse(no_route.ready)
        self.assertFalse(no_san.ready)
        self.assertTrue(ready.ready)

    def test_deploy_template_has_safe_export_defaults(self) -> None:
        state = json.loads(
            (ROOT / "deploy" / "users.json").read_text(encoding="utf-8")
        )
        self.assertEqual(state["server"], "YOUR_SERVER_IP")
        self.assertEqual(
            state["client_export"],
            {
                "address_mode": "server",
                "public_ip": "",
                "include_alternate": False,
            },
        )
        self.assertEqual(state["users"], [])
        self.assertEqual(state["portal"], {"enabled": False})


if __name__ == "__main__":
    unittest.main()
