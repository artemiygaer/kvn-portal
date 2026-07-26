"""Контракты безопасного backend обновлений из GitHub Releases."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

try:
    from portal.agent_protocol import MUTATION_METHODS, READ_ONLY_METHODS
    from portal.github_updates import (
        EXPECTED_ASSETS,
        GITHUB_API_ORIGIN,
        GITHUB_OWNER,
        GITHUB_REPO,
        GitHubReleaseSource,
        GitHubUpdateError,
        HttpResult,
        normalize_github_settings,
    )
    from tests.test_portal_agent import make_safe_deploy_archive
except ModuleNotFoundError as exc:  # pragma: no cover - backend отсутствует в unprivileged runtime image
    raise unittest.SkipTest("GitHub updater проверяется только в окружении host-agent") from exc


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, url, headers, *, timeout, max_bytes, destination=None):
        self.calls.append({
            "url": url,
            "headers": dict(headers),
            "timeout": timeout,
            "max_bytes": max_bytes,
            "destination": destination is not None,
        })
        if not self.responses:
            raise AssertionError("Лишний HTTP-запрос")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        status, response_headers, body = response
        raw_length = response_headers.get("content-length")
        if raw_length is not None and int(raw_length) > max_bytes:
            raise GitHubUpdateError("asset_too_large", "Ответ превысил лимит.")
        if status == 200 and destination is not None:
            if len(body) > max_bytes:
                raise GitHubUpdateError("asset_too_large", "Ответ превысил лимит.")
            destination.write(body)
            return HttpResult(status, response_headers, bytes_written=len(body))
        return HttpResult(status, response_headers, body=body)


def enabled_state(*, channel="stable", tag="", preference="deploy"):
    return {
        "updates": {
            "github": {
                "enabled": True,
                "owner": GITHUB_OWNER,
                "repo": GITHUB_REPO,
                "channel": channel,
                "tag": tag,
                "asset_preference": preference,
            }
        }
    }


def release_response(content: bytes, *, digest=None, name=None, asset_id=22, **overrides):
    asset_name = name or EXPECTED_ASSETS["deploy"]
    asset_digest = hashlib.sha256(content).hexdigest() if digest is None else digest
    release = {
        "id": 11,
        "tag_name": "v2026.07.24",
        "name": "KVN 2026.07.24",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-07-24T10:00:00Z",
        "assets": [{
            "id": asset_id,
            "name": asset_name,
            "state": "uploaded",
            "size": len(content),
            "digest": f"sha256:{asset_digest}",
            "browser_download_url": "https://evil.invalid/ignored",
        }],
    }
    release.update(overrides)
    return 200, {"content-type": "application/json"}, json.dumps(release).encode()


class GitHubSettingsTests(unittest.TestCase):
    def test_defaults_are_disabled_and_repository_is_fixed(self):
        settings = normalize_github_settings({}, mutate=False)
        self.assertEqual(settings["owner"], "artemiygaer")
        self.assertEqual(settings["repo"], "kvn-portal")
        self.assertFalse(settings["enabled"])
        self.assertEqual(settings["channel"], "stable")
        self.assertEqual(settings["asset_preference"], "release")

        for override in [
            {"owner": "attacker"},
            {"repo": "other"},
            {"channel": "url"},
            {"asset_preference": "unknown"},
            {"channel": "tag", "tag": "https://evil.invalid/file"},
        ]:
            state = enabled_state()
            state["updates"]["github"].update(override)
            with self.subTest(override=override), self.assertRaises(GitHubUpdateError) as denied:
                normalize_github_settings(state)
            self.assertEqual(denied.exception.code, "config_invalid")

    def test_tag_channel_uses_only_fixed_api_endpoint(self):
        payload = b"x" * 2048
        transport = FakeTransport([
            release_response(payload, tag_name="v2026.07.24"),
        ])
        source = GitHubReleaseSource(
            Path(tempfile.gettempdir()) / "not-used",
            token_file=Path(tempfile.gettempdir()) / "missing-kvn-token",
            transport=transport,
        )
        source.check(enabled_state(channel="tag", tag="v2026.07.24"))
        self.assertEqual(
            transport.calls[0]["url"],
            f"{GITHUB_API_ORIGIN}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases/tags/v2026.07.24",
        )
        self.assertNotIn("evil.invalid", transport.calls[0]["url"])

    def test_rpc_methods_are_exactly_classified(self):
        self.assertIn("project.release.settings", READ_ONLY_METHODS)
        self.assertIn("project.release.check", READ_ONLY_METHODS)
        self.assertNotIn("project.release.check", MUTATION_METHODS)
        self.assertIn("project.release.prepare", MUTATION_METHODS)
        self.assertNotIn("project.release.prepare", READ_ONLY_METHODS)

    def test_public_settings_do_not_report_token_state(self):
        source = GitHubReleaseSource(
            Path(tempfile.gettempdir()) / "not-used",
            token_file=Path(tempfile.gettempdir()) / "missing-kvn-token",
            transport=FakeTransport([]),
        )
        settings = source.settings(enabled_state())
        self.assertEqual(settings, {
            "enabled": True,
            "repository": "artemiygaer/kvn-portal",
            "channel": "stable",
            "tag": "",
            "asset_preference": "deploy",
        })
        self.assertNotIn("token", json.dumps(settings).lower())


class GitHubHttpTests(unittest.TestCase):
    def test_public_release_needs_no_token_and_ignores_browser_url(self):
        payload = b"x" * 2048
        transport = FakeTransport([release_response(payload)])
        source = GitHubReleaseSource(
            Path(tempfile.gettempdir()) / "not-used",
            token_file=Path(tempfile.gettempdir()) / "missing-kvn-token",
            transport=transport,
        )
        result = source.check(enabled_state())
        self.assertFalse(result["authenticated"])
        self.assertNotIn("Authorization", transport.calls[0]["headers"])
        encoded = json.dumps(result)
        self.assertNotIn("evil.invalid", encoded)
        self.assertNotIn("token", encoded.lower())

    def test_release_notes_are_bounded_plain_text_and_assets_are_allowlisted(self):
        payload = b"x" * 2048
        body = "\x00<script>alert(1)</script>\r\n" + "я" * 5000
        transport = FakeTransport([release_response(payload, body=body)])
        source = GitHubReleaseSource(
            Path(tempfile.gettempdir()) / "not-used",
            token_file=Path(tempfile.gettempdir()) / "missing-kvn-token",
            transport=transport,
        )
        result = source.check(enabled_state())
        self.assertNotIn("\x00", result["notes"])
        self.assertNotIn("\r", result["notes"])
        self.assertLessEqual(len(result["notes"]), 4002)
        self.assertEqual(result["assets"], [result["asset"]])
        self.assertNotIn("browser_download_url", json.dumps(result))

    def test_private_release_uses_root_only_token_without_returning_it(self):
        payload = b"x" * 2048
        secret = "github_pat_private_fixture_value"
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "github.token"
            token_file.write_text(secret + "\n", encoding="utf-8")
            token_file.chmod(0o600)
            transport = FakeTransport([release_response(payload)])
            source = GitHubReleaseSource(Path(tmp) / "updates", token_file=token_file, transport=transport)
            result = source.check(enabled_state())
            self.assertTrue(result["authenticated"])
            self.assertEqual(transport.calls[0]["headers"]["Authorization"], f"Bearer {secret}")
            self.assertNotIn(secret, json.dumps(result))

    def test_http_negative_matrix(self):
        payload = b"x" * 2048
        cases = [
            ("rate-limit", (403, {}, b"limit"), "github_rate_limited"),
            ("not-found", (404, {}, b"missing"), "release_not_found"),
            ("malformed", (200, {}, b"{bad"), "invalid_response"),
            (
                "timeout",
                GitHubUpdateError("github_timeout", "timeout"),
                "github_timeout",
            ),
            (
                "unknown-asset",
                release_response(payload, name="arbitrary-update.tar.gz"),
                "asset_not_found",
            ),
            (
                "digest-missing",
                release_response(payload, digest=""),
                "invalid_asset",
            ),
        ]
        for name, response, code in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                source = GitHubReleaseSource(
                    Path(tmp) / "updates",
                    token_file=Path(tmp) / "missing.token",
                    transport=FakeTransport([response]),
                )
                with self.assertRaises(GitHubUpdateError) as denied:
                    source.check(enabled_state())
                self.assertEqual(denied.exception.code, code)


class GitHubPrepareTests(unittest.TestCase):
    def _archive(self, root: Path) -> bytes:
        archive = root / EXPECTED_ASSETS["deploy"]
        make_safe_deploy_archive(archive)
        return archive.read_bytes()

    @staticmethod
    def _expected(content: bytes):
        return {
            "release_id": 11,
            "asset_id": 22,
            "asset_sha256": hashlib.sha256(content).hexdigest(),
        }

    def test_302_download_is_verified_and_second_prepare_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            content = self._archive(root)
            metadata = release_response(content)
            redirect = (
                302,
                {"location": "https://release-assets.githubusercontent.com/signed/asset"},
                b"",
            )
            download = (200, {"content-length": str(len(content))}, content)
            transport = FakeTransport([metadata, redirect, download, metadata])
            source = GitHubReleaseSource(
                root / "updates",
                token_file=root / "missing.token",
                transport=transport,
            )
            first = source.prepare(enabled_state(), self._expected(content))
            second = source.prepare(enabled_state(), self._expected(content))

            self.assertTrue(first["ready"])
            self.assertFalse(first["reused"])
            self.assertTrue(second["reused"])
            self.assertEqual(first["path"], second["path"])
            self.assertEqual(first["validation"]["internal_manifest"]["internal"], "deploy-inspector")
            self.assertTrue(first["validation"]["api_digest"])
            self.assertTrue(first["validation"]["download_sha256"])
            self.assertEqual(len(list((root / "updates").glob(".*.part-*"))), 0)
            redirect_headers = transport.calls[2]["headers"]
            self.assertNotIn("Authorization", redirect_headers)

    def test_non_https_or_foreign_redirect_is_denied_and_partial_removed(self):
        for location in [
            "http://release-assets.githubusercontent.com/asset",
            "https://evil.invalid/asset",
            "https://release-assets.githubusercontent.com.evil.invalid/asset",
        ]:
            with self.subTest(location=location), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                content = self._archive(root)
                transport = FakeTransport([
                    release_response(content),
                    (302, {"location": location}, b""),
                ])
                source = GitHubReleaseSource(
                    root / "updates",
                    token_file=root / "missing.token",
                    transport=transport,
                )
                with self.assertRaises(GitHubUpdateError) as denied:
                    source.prepare(enabled_state(), self._expected(content))
                self.assertEqual(denied.exception.code, "redirect_denied")
                self.assertEqual(list((root / "updates").glob(".*.part-*")), [])

    def test_digest_mismatch_invalid_archive_and_oversize_all_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            content = self._archive(root)
            corrupted = bytearray(content)
            corrupted[-10] ^= 1
            cases = [
                (
                    "digest",
                    release_response(content),
                    (200, {"content-length": str(len(content))}, bytes(corrupted)),
                    "digest_mismatch",
                ),
                (
                    "invalid-inner",
                    release_response(b"z" * 2048),
                    (200, {"content-length": "2048"}, b"z" * 2048),
                    "invalid_archive",
                ),
                (
                    "oversize",
                    release_response(content),
                    (200, {"content-length": str(200 * 1024 * 1024)}, b""),
                    "asset_too_large",
                ),
            ]
            for name, metadata, download, code in cases:
                with self.subTest(name=name):
                    updates = root / f"updates-{name}"
                    source = GitHubReleaseSource(
                        updates,
                        token_file=root / "missing.token",
                        transport=FakeTransport([metadata, download]),
                    )
                    expected_content = b"z" * 2048 if name == "invalid-inner" else content
                    with self.assertRaises(GitHubUpdateError) as denied:
                        source.prepare(enabled_state(), self._expected(expected_content))
                    self.assertEqual(denied.exception.code, code)
                    self.assertEqual(list(updates.glob(".*.part-*")), [])
                    self.assertEqual(list(updates.glob("*-github-*.tar.gz")), [])

    def test_prepare_rejects_forged_contract_before_http(self):
        source = GitHubReleaseSource(
            Path(tempfile.gettempdir()) / "not-used",
            transport=FakeTransport([]),
        )
        for params in [
            {},
            {"url": "https://evil.invalid/update"},
            {"release_id": 1, "asset_id": 2, "asset_sha256": "0" * 64, "repo": "other"},
        ]:
            with self.subTest(params=params), self.assertRaises(GitHubUpdateError) as denied:
                source.prepare(enabled_state(), params)
            self.assertEqual(denied.exception.code, "invalid_params")

    def test_stale_partial_is_removed_even_when_release_check_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            updates = Path(tmp) / "updates"
            updates.mkdir()
            stale = updates / ".kvn-vpn-deploy.part-stale"
            stale.write_bytes(b"partial")
            source = GitHubReleaseSource(
                updates,
                token_file=Path(tmp) / "missing.token",
                transport=FakeTransport([(404, {}, b"missing")]),
            )
            with self.assertRaises(GitHubUpdateError) as denied:
                source.prepare(
                    enabled_state(),
                    {"release_id": 1, "asset_id": 2, "asset_sha256": "0" * 64},
                )
            self.assertEqual(denied.exception.code, "release_not_found")
            self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()
