"""Доверенный каталог GitHub. Браузер передаёт только идентификатор и версию."""

import contextlib
import http.client
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime

from .manifest import MAX_PACKAGE, SHA256, VERSION, json_object, reject, version_key
from .registry import PackageRegistry, Prepared, _module

_API = "https://api.github.com"
_REPO = "/repos/artemiygaer/kvn-portal"
_CDN = frozenset({"release-assets.githubusercontent.com", "objects.githubusercontent.com"})
_META_LIMIT = 1024**2


def _cdn_url(value: str) -> bool:
    if not value.isascii() or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value):
        return False
    try:
        url = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    return (url.scheme == "https" and url.netloc in _CDN and url.path.startswith("/")
            and not url.fragment and "\\" not in value)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Download:
    def __init__(self, response, limit: int, deadline: float):
        self.response, self.limit, self.deadline = response, limit, deadline
        self.count = 0

    def read(self, size: int) -> bytes:
        if time.monotonic() > self.deadline:
            reject("github_download_timeout")
        chunk = self.response.read1(min(size, self.limit - self.count + 1))
        self.count += len(chunk)
        if self.count > self.limit:
            reject("github_asset_size")
        if not chunk and self.count != self.limit:
            reject("github_asset_size")
        return chunk


@dataclass(frozen=True)
class Asset:
    module: str
    version: str
    asset_id: int
    size: int
    sha256: str


class GitHubPackages:
    def __init__(self, *, opener=None):
        # Подмена транспорта допустима только в тесте Python, не в RPC.
        self._opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    @staticmethod
    def _request(url: str, *, binary: bool = False) -> urllib.request.Request:
        return urllib.request.Request(url, headers={
            "Accept": "application/octet-stream" if binary else "application/vnd.github+json",
            "User-Agent": "kvn-portal-v5",
            "X-GitHub-Api-Version": "2022-11-28",
            "Accept-Encoding": "identity",
        })

    @contextlib.contextmanager
    def _open(self, url: str, *, binary: bool = False):
        try:
            try:
                response = self._opener.open(self._request(url, binary=binary), timeout=12)
            except urllib.error.HTTPError as exc:
                with exc:
                    if not binary or exc.code not in (301, 302, 303, 307, 308):
                        reject("github_unavailable")
                    location = exc.headers.get("Location", "")
                    if not _cdn_url(location):
                        reject("github_redirect_refused")
                response = self._opener.open(self._request(location, binary=True), timeout=12)
            with response:
                if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                    reject("github_invalid_response")
                yield response
        except urllib.error.HTTPError as exc:
            exc.close()
            reject("github_unavailable")
        except (OSError, http.client.HTTPException):
            reject("github_unavailable")

    def find(self, module: str, version: str, *, tag: str | None = None) -> Asset:
        module = _module(module)
        version_key(version)
        if tag is not None and not _release_tag(tag):
            reject("invalid_github_release")
        release = f"tags/{tag}" if tag is not None else "latest"
        with self._open(f"{_API}{_REPO}/releases/{release}") as response:
            raw = bytearray()
            deadline = time.monotonic() + 25
            while True:
                if time.monotonic() > deadline:
                    reject("github_download_timeout")
                chunk = response.read1(min(65536, _META_LIMIT - len(raw) + 1))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > _META_LIMIT:
                    reject("github_metadata_limit")
        doc = json_object(bytes(raw))
        if (doc.get("draft") is not False or doc.get("prerelease") is not False
                or not _release_tag(doc.get("tag_name"))
                or (tag is not None and tag != doc["tag_name"]) or not isinstance(doc.get("assets"), list)):
            reject("invalid_github_release")
        name = f"kvn-module-{module}-{version}.tar.gz"
        matches = [item for item in doc["assets"] if isinstance(item, dict) and item.get("name") == name]
        if len(matches) != 1:
            reject("github_asset_not_found")
        item = matches[0]
        asset_id, size, digest = item.get("id"), item.get("size"), item.get("digest")
        if (item.get("state") != "uploaded" or type(asset_id) is not int or not 0 < asset_id < 2**63
                or type(size) is not int or not 0 < size <= MAX_PACKAGE):
            reject("invalid_github_asset")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or not SHA256.fullmatch(digest[7:]):
            reject("github_asset_missing_digest")
        return Asset(module, version, asset_id, size, digest[7:])

    def prepare(self, registry: PackageRegistry, module: str, version: str, *,
                tag: str | None = None, now: datetime | None = None) -> Prepared:
        asset = self.find(module, version, tag=tag)
        with self._open(f"{_API}{_REPO}/releases/assets/{asset.asset_id}", binary=True) as response:
            length = response.headers.get("Content-Length")
            if length is not None and length != str(asset.size):
                reject("github_asset_size")
            return registry.prepare(
                _Download(response, asset.size, time.monotonic() + 300), expected_sha256=asset.sha256,
                expected_module=asset.module, expected_version=asset.version, now=now,
            )


def _release_tag(value: object) -> bool:
    return isinstance(value, str) and value.startswith("v5.") and VERSION.fullmatch(value[1:]) is not None
