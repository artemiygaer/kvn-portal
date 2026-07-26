"""Интеграционные контракты GitHub Release с host-agent и existing updater."""

from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from portal.agent import AgentApplication, AgentDispatcher
from portal.agent_protocol import PROTOCOL_VERSION
from tests.test_portal_agent import FakeRunner, make_safe_deploy_archive
from tools import kvnctl


SECRET = "a" * 64


class _StateStore:
    def __init__(self, state):
        self.state = state

    def load(self):
        return self.state


class _Kvnctl:
    def __init__(self, state):
        self.STATE_STORE = _StateStore(state)


class _Control:
    def __init__(self, state):
        self.kvnctl = _Kvnctl(state)


class _GitHubSource:
    def __init__(self, archive: Path, metadata: dict):
        self.archive = archive
        self.metadata = metadata
        self.settings_calls = 0
        self.check_calls = 0
        self.prepare_calls = []

    def settings(self, state):
        self.settings_calls += 1
        return {
            "enabled": True,
            "repository": "artemiygaer/kvn-portal",
            "channel": "stable",
            "tag": "",
            "asset_preference": "deploy",
        }

    def check(self, state):
        self.check_calls += 1
        return self.metadata

    def prepare(self, state, params):
        self.prepare_calls.append(dict(params))
        return {
            "ok": True,
            "ready": True,
            "reused": False,
            "path": self.archive,
            "release": self.metadata,
            "validation": {
                "api_digest": True,
                "download_sha256": True,
                "internal_manifest": {"internal": "deploy-inspector", "member_count": 1},
            },
            "partials_removed": 1,
        }


def _request(method, params):
    return (
        json.dumps({
            "version": PROTOCOL_VERSION,
            "id": "github-rpc",
            "secret": SECRET,
            "method": method,
            "params": params,
        }).encode()
        + b"\n"
    )


class GitHubReleaseAgentTests(unittest.TestCase):
    def test_redacted_rpc_schema_and_existing_update_execution_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            updates = root / "portal-data" / "updates"
            updates.mkdir(parents=True)
            archive = updates / "kvn-vpn-deploy-github-fixture.tar.gz"
            make_safe_deploy_archive(archive)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            metadata = {
                "ok": True,
                "repository": "artemiygaer/kvn-portal",
                "channel": "stable",
                "tag": "v2026.07.24",
                "release_id": 11,
                "release_name": "KVN",
                "published_at": "2026-07-24T10:00:00Z",
                "asset": {
                    "id": 22,
                    "name": "kvn-vpn-deploy.tar.gz",
                    "kind": "deploy",
                    "size": archive.stat().st_size,
                    "sha256": digest,
                },
                "authenticated": True,
            }
            runner = FakeRunner()
            source = _GitHubSource(archive, metadata)
            dispatcher = AgentDispatcher(
                root,
                runner,
                control=_Control({"updates": {"github": {"enabled": True}}}),
                github_source=source,
            )
            app = AgentApplication(SECRET, dispatcher)

            settings = json.loads(app.handle_line(_request("project.release.settings", {})))
            checked = json.loads(app.handle_line(_request("project.release.check", {})))
            expected = {"release_id": 11, "asset_id": 22, "asset_sha256": digest}
            prepared = json.loads(app.handle_line(_request("project.release.prepare", expected)))
            self.assertTrue(checked["ok"])
            self.assertEqual(settings["data"]["repository"], "artemiygaer/kvn-portal")
            self.assertNotIn("token", json.dumps(settings).lower())
            self.assertEqual(source.settings_calls, 1)
            self.assertTrue(prepared["ok"])
            self.assertTrue(prepared["data"]["ready"])
            self.assertEqual(prepared["data"]["archive_sha256"], digest)
            self.assertEqual(prepared["data"]["archive"], archive.relative_to(root).as_posix())
            self.assertEqual(source.prepare_calls, [expected])
            self.assertEqual(runner.calls, [])

            with mock.patch.object(dispatcher, "_verify_root_password", return_value=True):
                started = dispatcher._project_update({
                    "archive": prepared["data"]["archive"],
                    "expected_sha256": digest,
                    "root_password": "RootPassword-2026",
                    "session_owner": "b" * 64,
                })
            self.assertTrue(started["ok"])
            self.assertEqual(started["action"], "update")
            self.assertEqual(runner.calls[-1][0][0], "systemd-run")
            serialized = json.dumps({"checked": checked, "prepared": prepared, "started": started})
            self.assertNotIn("github_pat_", serialized)
            self.assertNotIn("root_password", serialized)
            self.assertNotIn("RootPassword-2026", serialized)

    def test_rpc_rejects_url_and_repository_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner = FakeRunner()
            source = _GitHubSource(root / "unused.tar.gz", {})
            dispatcher = AgentDispatcher(
                root,
                runner,
                control=_Control({}),
                github_source=source,
            )
            app = AgentApplication(SECRET, dispatcher)
            cases = [
                ("project.release.check", {"url": "https://evil.invalid/update"}),
                (
                    "project.release.prepare",
                    {
                        "release_id": 1,
                        "asset_id": 2,
                        "asset_sha256": "0" * 64,
                        "repo": "attacker/repo",
                    },
                ),
            ]
            for method, params in cases:
                with self.subTest(method=method):
                    response = json.loads(app.handle_line(_request(method, params)))
                    self.assertFalse(response["ok"])
                    self.assertEqual(response["error"]["code"], "invalid_params")
            self.assertEqual(source.check_calls, 0)
            self.assertEqual(source.prepare_calls, [])
            self.assertEqual(runner.calls, [])


class GitHubUpdatesCliTests(unittest.TestCase):
    @staticmethod
    def _state():
        return {
            "updates": {
                "github": {
                    "enabled": True,
                    "owner": "artemiygaer",
                    "repo": "kvn-portal",
                    "channel": "stable",
                    "tag": "",
                    "asset_preference": "deploy",
                }
            }
        }

    def test_status_and_configure_never_echo_token(self):
        secret = "github_pat_cli_fixture_value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            supplied = root / "supplied.token"
            supplied.write_text(secret + "\n", encoding="utf-8")
            supplied.chmod(0o600)
            installed = root / "github.token"
            state = self._state()
            parser = kvnctl.build_parser()

            status_args = parser.parse_args(["updates", "status"])
            configure_args = parser.parse_args([
                "updates", "configure", "--enable", "true",
                "--asset-preference", "release", "--token-file", str(supplied),
            ])
            output = io.StringIO()
            with (
                mock.patch.object(kvnctl, "load_state", return_value=state),
                mock.patch.object(kvnctl, "save_state") as save_state,
                mock.patch("portal.github_updates.GITHUB_TOKEN_FILE", installed),
                redirect_stdout(output),
            ):
                status_args.func(status_args)
                configure_args.func(configure_args)

            self.assertTrue(save_state.called)
            self.assertEqual(installed.read_text(encoding="utf-8").strip(), secret)
            if os.name == "posix":
                self.assertEqual(installed.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(secret, output.getvalue())
            self.assertNotIn(secret, json.dumps(vars(configure_args), default=str))
            saved = save_state.call_args.args[0]
            self.assertEqual(saved["updates"]["github"]["asset_preference"], "release")


if __name__ == "__main__":
    unittest.main()
