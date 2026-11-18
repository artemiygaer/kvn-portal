"""GitHub-источник обновления ядра не принимает произвольные URL."""

from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock

from tests.v5.test_core_update import artifact, publisher
from v5.core.maintenance.core_bundle import NAME, PUBLIC_NAME, build
from v5.core.maintenance.core_github import GitHubCore
from v5.core.maintenance.portal_store import PortalUpdateStore, UpdateStoreError


class Source:
    def __init__(self, data, *, tag="v5.0.1", digest=None):
        self.data, self.urls = data, []
        self.metadata = {"draft": False, "prerelease": False, "tag_name": tag, "assets": [{
            "name": NAME, "id": 123, "size": len(data), "state": "uploaded",
            "digest": "sha256:" + (digest or hashlib.sha256(data).hexdigest()),
        }]}

    @contextmanager
    def _open(self, url, *, binary=False):
        self.urls.append((url, binary))
        yield io.BytesIO(self.data if binary else json.dumps(self.metadata).encode())


class GitHubCoreTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        _, key, cls.pin = publisher(cls.root)
        source = artifact(cls.root / "release", key, cls.pin, "5.0.1")
        bundle = cls.root / "bundle.tar"
        build(source, bundle)
        cls.raw = bundle.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        temporary = TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        store, live = root / "store", root / "live"
        store.mkdir(mode=0o700)
        live.mkdir()
        (live / "core-version").write_text("5.0.0\n")
        self.store = PortalUpdateStore(654, root=store, live=live, pin=self.pin, checker=Mock())

    def test_fixed_release_and_checksum_are_verified_before_ready(self):
        source = Source(self.raw)
        result = GitHubCore(source).prepare(self.store, "v5.0.1")
        self.assertEqual(result["version"], "5.0.1")
        self.assertEqual(source.urls, [
            ("https://api.github.com/repos/artemiygaer/kvn-portal/releases/tags/v5.0.1", False),
            ("https://api.github.com/repos/artemiygaer/kvn-portal/releases/assets/123", True),
        ])

    def test_hash_mismatch_and_tag_version_mismatch_leave_no_ready_package(self):
        for source, tag in ((Source(self.raw, digest="0" * 64), "v5.0.1"),
                            (Source(self.raw, tag="v5.0.2"), "v5.0.2")):
            with self.subTest(tag=tag), self.assertRaises(UpdateStoreError):
                GitHubCore(source).prepare(self.store, tag)
            self.assertEqual(self.store.records(), [])

    def test_prefers_neutral_asset_and_accepts_legacy_name(self):
        source = Source(self.raw)
        legacy = source.metadata["assets"][0]
        neutral = {**legacy, "name": PUBLIC_NAME, "id": 456}
        for assets in ([neutral, legacy], [neutral], [legacy]):
            with self.subTest(assets=assets):
                source.metadata["assets"] = assets
                self.assertEqual(GitHubCore(source).prepare(self.store, "v5.0.1")["version"], "5.0.1")
                self.assertTrue(source.urls[-1][0].endswith(str(assets[0]["id"])))
        source.metadata["assets"] = [neutral, neutral, legacy]
        with self.assertRaisesRegex(UpdateStoreError, "core_github_asset_missing"):
            GitHubCore(source).prepare(self.store, "v5.0.1")

    def test_rejects_urls_prereleases_and_duplicate_assets(self):
        source = Source(self.raw)
        for tag in ("https://example.invalid/file", "v4.2.0", "v5.0.1-rc1", "../v5.0.1"):
            with self.subTest(tag=tag), self.assertRaises(UpdateStoreError):
                GitHubCore(source).prepare(self.store, tag)
        source.metadata["assets"].append(dict(source.metadata["assets"][0]))
        with self.assertRaises(UpdateStoreError):
            GitHubCore(source).prepare(self.store, "v5.0.1")
