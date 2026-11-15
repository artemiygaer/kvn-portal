"""Загрузка только пакета ядра из фиксированного GitHub Releases."""

import hashlib
import hmac
import time

from v5.core.packages.github import GitHubPackages, _API, _Download, _META_LIMIT, _REPO, _release_tag
from v5.core.packages.manifest import SHA256, json_object

from .core_bundle import MAX_BUNDLE, NAME
from .portal_store import UpdateStoreError


class _VerifiedDownload:
    def __init__(self, source, digest):
        self.source, self.digest, self.hasher = source, digest, hashlib.sha256()

    def read(self, amount):
        chunk = self.source.read(amount)
        if chunk:
            self.hasher.update(chunk)
        elif not hmac.compare_digest(self.hasher.hexdigest(), self.digest):
            raise UpdateStoreError("core_github_digest")
        return chunk


class GitHubCore:
    def __init__(self, transport=None):
        self.transport = transport if transport is not None else GitHubPackages()

    def prepare(self, store, tag=None):
        if tag is not None and not _release_tag(tag):
            raise UpdateStoreError("core_github_tag")
        suffix = f"tags/{tag}" if tag is not None else "latest"
        with self.transport._open(f"{_API}{_REPO}/releases/{suffix}") as response:
            raw = bytearray()
            deadline = time.monotonic() + 25
            while True:
                if time.monotonic() > deadline:
                    raise UpdateStoreError("core_github_timeout")
                chunk = response.read1(min(65536, _META_LIMIT + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > _META_LIMIT:
                    raise UpdateStoreError("core_github_metadata")
        release = json_object(bytes(raw))
        if (release.get("draft") is not False or release.get("prerelease") is not False
                or not _release_tag(release.get("tag_name"))
                or tag is not None and tag != release["tag_name"] or not isinstance(release.get("assets"), list)):
            raise UpdateStoreError("core_github_metadata")
        matches = [item for item in release["assets"] if isinstance(item, dict) and item.get("name") == NAME]
        if len(matches) != 1:
            raise UpdateStoreError("core_github_asset_missing")
        asset = matches[0]
        asset_id, size, digest = asset.get("id"), asset.get("size"), asset.get("digest")
        if (asset.get("state") != "uploaded" or type(asset_id) is not int or not 0 < asset_id < 2**63
                or type(size) is not int or not 0 < size <= MAX_BUNDLE or not isinstance(digest, str)
                or not digest.startswith("sha256:") or SHA256.fullmatch(digest[7:]) is None):
            raise UpdateStoreError("core_github_metadata")
        with self.transport._open(f"{_API}{_REPO}/releases/assets/{asset_id}", binary=True) as response:
            source = _Download(response, size, time.monotonic() + 180)
            return store.prepare(_VerifiedDownload(source, digest[7:]), size,
                                 expected_version=release["tag_name"][1:])
