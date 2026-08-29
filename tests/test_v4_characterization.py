"""Характеризационные контракты v3 перед модульной миграцией v4."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from portal.agent_protocol import ALLOWED_METHODS, MUTATION_METHODS, READ_ONLY_METHODS
from portal.app.blueprints.catalog import ROUTES
try:
    from tests.test_baseline_contracts import fixture_state, fixture_user
except ModuleNotFoundError:  # unittest discover с `-s tests`
    from test_baseline_contracts import fixture_state, fixture_user
from tools import kvnctl
from tools.deploy_archive import ArchiveValidationError, inspect_archive


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests/fixtures/v3_contracts"
CONTRACT = json.loads((FIXTURE_ROOT / "contracts.json").read_text(encoding="utf-8"))


def stable_hash(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def cli_inventory(parser: argparse.ArgumentParser, prefix: str = "") -> dict[str, list[str]]:
    path = prefix or "<root>"
    result = {
        path: sorted(
            {option for action in parser._actions for option in action.option_strings}
        )
    }
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        for name, subparser in sorted(action.choices.items()):
            child = f"{prefix} {name}".strip()
            result.update(cli_inventory(subparser, child))
    return result


def golden_outputs() -> dict[str, str]:
    state = fixture_state()
    user = fixture_user()
    state["amneziawg"]["obfuscation"] = {
        "Jc": 5,
        "Jmin": 64,
        "Jmax": 1024,
        "S1": 32,
        "S2": 48,
        "H1": 1000000001,
        "H2": 1000000002,
        "H3": 1000000003,
        "H4": 1000000004,
        "I1": "<r 2><b 0x8580000100010000000004796162730679616e6465780272750000010001c00c000100010000026d000457fa27d1>",
    }
    state["users"] = [user]
    with (
        mock.patch("tools.kvnctl.certificate_sha256_hex", return_value=""),
        mock.patch("tools.kvnctl.certificate_pin_sha256", return_value=""),
    ):
        return {
            "xray_server": json.dumps(
                kvnctl.default_xray_config(state),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            "telemt_server": kvnctl.telemt_config_text(state),
            "mtg_server": kvnctl.mtg_config_text(state),
            "ocserv_server": kvnctl.ocserv_conf_text(state),
            "awg_client": kvnctl.amneziawg_client_conf(state, user),
            "wg_client": kvnctl.wireguard_client_conf(state, user),
            "ocserv_client": kvnctl.openconnect_client_text(state, user),
            "happ": kvnctl.happ_subscription_txt(
                state, user, "fixture-reality-public"
            ),
            "karing": kvnctl.karing_subscription_txt(
                state, user, "fixture-reality-public"
            ),
        }


def add_tar_file(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o644
    member.mtime = 0
    member.uid = 0
    member.gid = 0
    member.uname = ""
    member.gname = ""
    archive.addfile(member, io.BytesIO(payload))


def build_synthetic_deploy(path: Path, *, extra_name: str = "") -> int:
    canonical = (ROOT / "tools/canonical-files.txt").read_text(
        encoding="utf-8"
    ).splitlines()
    manifest = ("\n".join(canonical) + "\n").encode("utf-8")
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        add_tar_file(archive, "deploy/.kvn-canonical-files", manifest)
        for relative in canonical:
            digest = hashlib.sha256(relative.encode("utf-8")).hexdigest().encode("ascii")
            add_tar_file(archive, f"deploy/{relative}", digest * 8)
        template = b'{"server":"YOUR_SERVER_IP","users":[],"portal":{"enabled":false}}\n'
        add_tar_file(archive, "deploy/users.json", template)
        if extra_name:
            add_tar_file(archive, extra_name, b"synthetic")
    return len(canonical) + 2 + bool(extra_name)


class V4CharacterizationTests(unittest.TestCase):
    def test_fixtures_are_metadata_only_and_secret_free(self):
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(FIXTURE_ROOT.rglob("*"))
            if path.is_file()
        ).lower()
        for forbidden in (
            "private_key",
            "preshared",
            "password",
            "token",
            "uuid",
            "root@",
            "gaer.loc.cc",
        ):
            self.assertNotIn(forbidden, text)
        self.assertIsNone(re.search(r"(?<![0-9a-f])(?:\d{1,3}\.){3}\d{1,3}(?![0-9a-f])", text))
        self.assertEqual(CONTRACT["version"], "v3.1.3")

    def test_cli_rpc_http_and_canonical_inventory_is_exact(self):
        cli = cli_inventory(kvnctl.build_parser())
        routes = [
            {
                "group": route.group,
                "rule": route.rule,
                "endpoint": route.endpoint,
                "methods": list(route.methods),
            }
            for route in ROUTES
        ]
        canonical = (ROOT / "tools/canonical-files.txt").read_text(
            encoding="utf-8"
        ).splitlines()
        inventories = {
            "cli": cli,
            "rpc_all": sorted(ALLOWED_METHODS),
            "rpc_read_only": sorted(READ_ONLY_METHODS),
            "rpc_mutations": sorted(MUTATION_METHODS),
            "http_routes": routes,
            "canonical_files": canonical,
        }
        counts = {
            "cli_paths": len(cli),
            "cli_options": sum(len(options) for options in cli.values()),
            "rpc_all": len(ALLOWED_METHODS),
            "rpc_read_only": len(READ_ONLY_METHODS),
            "rpc_mutations": len(MUTATION_METHODS),
            "http_routes": len(routes),
            "canonical_files": len(canonical),
        }
        self.assertEqual(counts, CONTRACT["inventory_counts"])
        self.assertEqual(
            {name: stable_hash(value) for name, value in inventories.items()},
            CONTRACT["inventory_sha256"],
        )

    def test_render_and_export_outputs_match_golden_hashes(self):
        actual = {
            name: {
                "bytes": len(value.encode("utf-8")),
                "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            }
            for name, value in golden_outputs().items()
        }
        self.assertEqual(actual, CONTRACT["golden_outputs"])

    def test_update_archive_inspection_accepts_only_canonical_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "synthetic-deploy.tar.gz"
            expected_members = build_synthetic_deploy(target)
            metadata = inspect_archive(target)
            self.assertEqual(metadata["name"], target.name)
            self.assertEqual(metadata["member_count"], expected_members)
            self.assertEqual(len(metadata["sha256"]), 64)

            unknown = Path(temporary) / "unknown-deploy.tar.gz"
            build_synthetic_deploy(unknown, extra_name="deploy/unknown.txt")
            with self.assertRaisesRegex(ArchiveValidationError, "неразрешённые"):
                inspect_archive(unknown)

            traversal = Path(temporary) / "traversal-deploy.tar.gz"
            build_synthetic_deploy(traversal, extra_name="deploy/../escape")
            with self.assertRaisesRegex(ArchiveValidationError, "небезопасный путь"):
                inspect_archive(traversal)


if __name__ == "__main__":
    unittest.main()
