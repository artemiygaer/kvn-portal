"""Обезличенный baseline публичных контрактов перед большим рефакторингом."""

from __future__ import annotations

import argparse
import ast
import base64
import json
import re
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from portal.agent_protocol import ALLOWED_METHODS
from tools import kvnctl


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads(
    (ROOT / "tests/fixtures/baseline-contract.json").read_text(encoding="utf-8")
)


def fixture_state() -> dict:
    return {
        "server": "vpn.example.test",
        "subscription": {"enabled": True, "port": 2096},
        "sni_routes": {
            "tls": {"default": "tls.example.test", "aliases": ["tls.example.test"]},
            "reality-xhttp": {"default": "xhttp.example.test", "aliases": ["xhttp.example.test"]},
            "reality-tcp": {"default": "tcp.example.test", "aliases": ["tcp.example.test"]},
            "hysteria": {"default": "hy.example.test", "aliases": ["hy.example.test"]},
            "telemt": {"default": "tg.example.test", "aliases": ["tg.example.test"]},
            "mtg": {"default": "mtg.example.test", "aliases": ["mtg.example.test"]},
            "ocserv": {"default": "oc.example.test", "aliases": ["oc.example.test"]},
        },
        "reality": {"short_id": "a3f9c1b82d4e6f90"},
        "reality_tcp": {
            "short_id": "e7a4b2c91f5d8e30",
            "public_key": "fixture-reality-tcp-public",
        },
        "mtg": {"secret16": "00112233445566778899aabbccddeeff"},
        "amneziawg": {
            "port": 51820,
            "public_key": "fixture-awg-server-public",
            "dns": ["1.1.1.1"],
        },
        "wireguard": {
            "port": 51821,
            "public_key": "fixture-wg-server-public",
            "dns": ["1.1.1.1"],
        },
        "ocserv": {
            "sni_enabled": True,
            "sni": "oc.example.test",
            "tcp_port": 443,
            "udp_port": 4443,
            "dtls_enabled": True,
        },
    }


def fixture_user() -> dict:
    return {
        "name": "AuditFixture",
        "uuid": "00000000-0000-4000-8000-000000000001",
        "hysteria_password": "fixture-password",
        "telemt_secret": "00112233445566778899aabbccddeeff",
        "ocserv_password": "Fixture-Password-1",
        "sub_token": "0123456789abcdef0123456789abcdef",
        "enabled": True,
        "systems": list(kvnctl.ALL_SYSTEMS),
        "sni_overrides": {},
        "amneziawg": {
            "private_key": "fixture-awg-private",
            "preshared_key": "fixture-awg-psk",
            "address": "10.66.66.2/32",
        },
        "wireguard": {
            "private_key": "fixture-wg-private",
            "preshared_key": "fixture-wg-psk",
            "address": "10.67.67.2/32",
        },
    }


class BaselineContractsTests(unittest.TestCase):
    def test_client_exports_match_protocol_and_profile_golden_matrix(self):
        state = fixture_state()
        user = fixture_user()
        expected = FIXTURE["client_export"]
        with (
            mock.patch("tools.kvnctl.certificate_sha256_hex", return_value=""),
            mock.patch("tools.kvnctl.certificate_pin_sha256", return_value=""),
        ):
            links = {
                "tls": kvnctl.vless_tls_link(state, user),
                "reality-xhttp": kvnctl.vless_reality_link(state, user, "fixture-reality-public"),
                "reality-tcp": kvnctl.vless_reality_tcp_link(state, user, "fixture-reality-public"),
                "hysteria": kvnctl.hysteria2_link(state, user),
                "telemt": kvnctl.telemt_link(state, user),
                "mtg": kvnctl.mtg_link(state),
            }
            openconnect = kvnctl.openconnect_client_text(state, user)

        for system, link in links.items():
            contract = expected["protocols"][system]
            parsed = urlparse(link)
            self.assertEqual(parsed.scheme, contract["scheme"], system)
            if parsed.scheme == "tg":
                query = parse_qs(parsed.query)
                self.assertEqual(query["server"], [expected["connection_host"]], system)
                self.assertEqual(int(query["port"][0]), contract["port"], system)
                continue
            self.assertEqual(parsed.hostname, expected["connection_host"], system)
            self.assertEqual(parsed.port, contract["port"], system)
            query = parse_qs(parsed.query)
            for field in ("security", "type", "sni"):
                if field in contract:
                    self.assertEqual(query[field], [str(contract[field])], f"{system}:{field}")

        awg = kvnctl.amneziawg_client_conf(state, user)
        wireguard = kvnctl.wireguard_client_conf(state, user)
        self.assertIn("Endpoint = vpn.example.test:51820", awg)
        self.assertIn("Endpoint = vpn.example.test:51821", wireguard)
        self.assertIn("Server: https://oc.example.test:443/", openconnect)

        profiles = expected["profiles"]
        self.assertEqual(kvnctl.happ_sub_url(state, user), profiles["happ"])
        self.assertEqual(kvnctl.karing_sub_url(state, user), profiles["karing"])
        self.assertEqual(kvnctl.karing_wireguard_sub_url(state, user), profiles["karing-wg"])
        with (
            mock.patch("tools.kvnctl.certificate_sha256_hex", return_value=""),
            mock.patch("tools.kvnctl.certificate_pin_sha256", return_value=""),
        ):
            legacy = base64.b64decode(
                kvnctl.subscription_txt(state, user, "fixture-reality-public")
            ).decode("utf-8").splitlines()
        self.assertEqual([urlparse(item).scheme for item in legacy], profiles["legacy_order"])

    def test_portal_route_and_rpc_snapshots_are_exact_and_secret_free(self):
        catalog_path = ROOT / "portal/app/blueprints/catalog.py"
        catalog_tree = ast.parse(catalog_path.read_text(encoding="utf-8"))
        route_names = {
            node.args[2].value
            for node in ast.walk(catalog_tree)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "RouteSpec"
                and len(node.args) >= 3
                and isinstance(node.args[2], ast.Constant)
                and isinstance(node.args[2].value, str)
            )
        }

        self.assertEqual(sorted(route_names), FIXTURE["portal_route_endpoints"])
        self.assertEqual(sorted(ALLOWED_METHODS), FIXTURE["rpc_methods"])
        serialized = json.dumps(FIXTURE, ensure_ascii=False).lower()
        for forbidden in ("private_key", "preshared", "root_password", "content_base64"):
            self.assertNotIn(forbidden, serialized)
        for required in (
            "project_release_check", "project_release_prepare",
            "project_update_prepare", "project_update_start", "project_update_discard",
            "project.release.settings", "project.release.check",
            "project.release.prepare", "project.update.inspect", "project.update",
        ):
            self.assertIn(required, serialized)

    def test_cli_snapshot_and_publication_ignore_contract(self):
        parser = kvnctl.build_parser()
        subparsers = next(
            action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
        )
        self.assertEqual(sorted(subparsers.choices), FIXTURE["cli_commands"])

        ignored = {
            line.strip()
            for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for required in {
            "users.json", "clients/", "certs/", "site-certs/", ".env",
            "portal-data/", "portal-runtime/", "output/",
            "kvn-vpn-deploy.tar.gz", "kvn-vpn-release-linux-amd64*.tar.gz",
            "kvn-vpn-backup-*.tar",
        }:
            self.assertIn(required, ignored)

        docker_ignored = {
            line.strip()
            for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        for required in {
            "/users.json", "/clients", "/certs", "/site-certs", "/.env",
            "/portal-data", "/portal-runtime", "/output", "/.supergoal",
            "/kvn-vpn-backup-*.tar",
        }:
            self.assertIn(required, docker_ignored)

        canonical = (ROOT / "tools/canonical-files.txt").read_text(encoding="utf-8")
        for forbidden in (
            "users.json", "clients/", "portal-data/", "portal-runtime/",
            "kvn-vpn-release-linux-amd64.tar.gz", ".env",
        ):
            self.assertNotRegex(canonical, rf"(?m)^(?!deploy/users\.json$){re.escape(forbidden)}")


if __name__ == "__main__":
    unittest.main()
