"""Матрица endpoint/SNI и CLI экспорта пользователя."""

from __future__ import annotations

import argparse
import base64
import copy
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from tests.test_baseline_contracts import fixture_state, fixture_user
from tests.deploy_runtime_e2e import docker_daemon_path
from tools import kvnctl


PUBLIC_IP = "8.8.4.4"
REALITY_KEY = "fixture-reality-public"


def all_outputs(state: dict, user: dict) -> dict[str, object]:
    return {
        "tls": kvnctl.vless_tls_link(state, user),
        "reality-xhttp": kvnctl.vless_reality_link(
            state, user, REALITY_KEY
        ),
        "reality-tcp": kvnctl.vless_reality_tcp_link(
            state, user, REALITY_KEY
        ),
        "hysteria": kvnctl.hysteria2_link(state, user),
        "telemt": kvnctl.telemt_link(state, user),
        "mtg": kvnctl.mtg_link(state),
        "awg": kvnctl.amneziawg_client_conf(state, user),
        "wg": kvnctl.wireguard_client_conf(state, user),
        "karing-wg": kvnctl.karing_wireguard_yaml(state, user),
        "openconnect": kvnctl.openconnect_client_text(state, user),
        "tls-json": kvnctl.client_json_tls(state, user),
        "reality-json": kvnctl.client_json_reality(
            state, user, REALITY_KEY
        ),
        "reality-tcp-json": kvnctl.client_json_reality_tcp(
            state, user, REALITY_KEY
        ),
        "hysteria-json": kvnctl.xray_hysteria2_json(state, user),
        "singbox": kvnctl.singbox_subscription(
            state, user, REALITY_KEY
        ),
        "happ": kvnctl.happ_subscription_txt(
            state, user, REALITY_KEY
        ),
        "karing": kvnctl.karing_subscription_txt(
            state, user, REALITY_KEY
        ),
    }


class ClientExportRendererTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = fixture_state()
        self.user = fixture_user()

    def test_docker_e2e_agent_path_is_linux_absolute(self) -> None:
        value = docker_daemon_path(Path(__file__).parent)
        self.assertTrue(value.startswith("/"))
        self.assertNotRegex(value, r"^[A-Za-z]:")

    def test_explicit_server_policy_is_byte_compatible(self) -> None:
        explicit = copy.deepcopy(self.state)
        explicit["client_export"] = {
            "address_mode": "server",
            "public_ip": "",
            "include_alternate": False,
        }
        with (
            mock.patch("tools.kvnctl.certificate_sha256_hex", return_value=""),
            mock.patch("tools.kvnctl.certificate_pin_sha256", return_value=""),
            mock.patch("tools.kvnctl.awg_obfuscation_lines", return_value=[]),
        ):
            legacy = all_outputs(self.state, self.user)
            normalized = all_outputs(explicit, self.user)
        self.assertEqual(normalized, legacy)

    def test_ip_mode_changes_every_endpoint_but_keeps_tls_identity(self) -> None:
        state = copy.deepcopy(self.state)
        state["client_export"] = {
            "address_mode": "public-ip",
            "public_ip": PUBLIC_IP,
            "include_alternate": False,
        }
        with (
            mock.patch("tools.kvnctl.certificate_sha256_hex", return_value=""),
            mock.patch("tools.kvnctl.certificate_pin_sha256", return_value=""),
        ):
            outputs = all_outputs(state, self.user)

        expected_sni = {
            "tls": "tls.example.test",
            "reality-xhttp": "xhttp.example.test",
            "reality-tcp": "tcp.example.test",
            "hysteria": "hy.example.test",
        }
        for name in ("tls", "reality-xhttp", "reality-tcp", "hysteria"):
            parsed = urlparse(str(outputs[name]))
            self.assertEqual(parsed.hostname, PUBLIC_IP, name)
            self.assertEqual(
                parse_qs(parsed.query)["sni"],
                [expected_sni[name]],
                name,
            )
        for name in ("telemt", "mtg"):
            query = parse_qs(urlparse(str(outputs[name])).query)
            self.assertEqual(query["server"], [PUBLIC_IP], name)

        self.assertIn(f"Endpoint = {PUBLIC_IP}:51820", outputs["awg"])
        self.assertIn(f"Endpoint = {PUBLIC_IP}:51821", outputs["wg"])
        self.assertIn(f"server: \"{PUBLIC_IP}\"", outputs["karing-wg"])
        self.assertIn(
            f"Server: https://{PUBLIC_IP}:443/",
            outputs["openconnect"],
        )
        self.assertIn("--sni=oc.example.test", outputs["openconnect"])

        for name in ("tls-json", "reality-json", "reality-tcp-json"):
            self.assertEqual(
                outputs[name]["vnext"][0]["address"],
                PUBLIC_IP,
                name,
            )
        self.assertEqual(
            outputs["hysteria-json"]["outbounds"][0]["settings"]["servers"][0]["address"],
            PUBLIC_IP,
        )
        for outbound in outputs["singbox"]["outbounds"]:
            if "server" in outbound:
                self.assertEqual(outbound["server"], PUBLIC_IP)

        for profile in ("happ", "karing"):
            payload = base64.b64decode(outputs[profile]).decode("utf-8")
            for uri in payload.splitlines():
                self.assertEqual(urlparse(uri).hostname, PUBLIC_IP, profile)

    def test_ip_subscription_url_requires_route_and_exact_ip_san(self) -> None:
        state = copy.deepcopy(self.state)
        state["client_export"] = {
            "address_mode": "public-ip",
            "public_ip": PUBLIC_IP,
            "include_alternate": False,
        }
        with mock.patch("tools.kvnctl.certificate_sans", return_value=[]):
            blocked = kvnctl.happ_sub_url(state, self.user)
        with mock.patch(
            "tools.kvnctl.certificate_sans",
            return_value=[PUBLIC_IP],
        ):
            ready = kvnctl.happ_sub_url(state, self.user)

        self.assertNotIn(PUBLIC_IP, blocked)
        self.assertEqual(
            ready,
            f"https://{PUBLIC_IP}:2096/happ/{self.user['sub_token']}",
        )

    def test_export_user_writes_atomic_private_json_without_policy_save(
        self,
    ) -> None:
        state = copy.deepcopy(self.state)
        state["users"] = [copy.deepcopy(self.user)]
        before = copy.deepcopy(state)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "user-export.json"
            args = argparse.Namespace(
                name=self.user["name"],
                address_mode="public-ip",
                public_ip=PUBLIC_IP,
                format="json",
                output=output,
            )
            stdout = io.StringIO()
            with (
                mock.patch("tools.kvnctl.load_state", return_value=state),
                mock.patch(
                    "tools.kvnctl.ensure_reality_public_key",
                    return_value=(REALITY_KEY, False),
                ),
                mock.patch(
                    "tools.kvnctl.ensure_amneziawg_state",
                    return_value=False,
                ),
                mock.patch(
                    "tools.kvnctl.ensure_wireguard_state",
                    return_value=False,
                ),
                mock.patch("tools.kvnctl.save_state") as save_state,
                mock.patch(
                    "tools.kvnctl.certificate_sha256_hex",
                    return_value="",
                ),
                mock.patch(
                    "tools.kvnctl.certificate_pin_sha256",
                    return_value="",
                ),
                redirect_stdout(stdout),
            ):
                kvnctl.cmd_export_user(args)

            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["connection_host"], PUBLIC_IP)
            self.assertEqual(document["user"], self.user["name"])
            self.assertTrue(document["sections"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertNotIn(self.user["uuid"], stdout.getvalue())
            self.assertEqual(state, before)
            save_state.assert_not_called()


if __name__ == "__main__":
    unittest.main()
