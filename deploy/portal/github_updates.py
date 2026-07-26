"""Безопасный источник обновлений из фиксированного GitHub Releases."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import re
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Protocol
from urllib.parse import quote, urljoin, urlsplit

from tools.deploy_archive import ArchiveValidationError, MAX_ARCHIVE_BYTES, inspect_archive
from tools.release_archive import (
    MAX_RELEASE_BYTES,
    ReleaseValidationError,
    validate_release,
)


GITHUB_OWNER = "artemiygaer"
GITHUB_REPO = "kvn-portal"
GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_TOKEN_FILE = Path("/etc/kvn-portal/github.token")
EXPECTED_ASSETS = {
    "release": "kvn-vpn-release-linux-amd64.tar.gz",
    "deploy": "kvn-vpn-deploy.tar.gz",
}
ASSET_LIMITS = {
    "release": MAX_RELEASE_BYTES,
    "deploy": MAX_ARCHIVE_BYTES,
}
ALLOWED_DOWNLOAD_HOSTS = {
    "api.github.com",
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}
MAX_API_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
CONNECT_TIMEOUT = 10.0
DOWNLOAD_TIMEOUT = 120.0
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
CONTROL_TEXT_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class GitHubUpdateError(RuntimeError):
    """Ожидаемая ошибка проверки или загрузки release."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes = b""
    bytes_written: int = 0


class HttpTransport(Protocol):
    def request(
        self,
        url: str,
        headers: dict[str, str],
        *,
        timeout: float,
        max_bytes: int,
        destination: BinaryIO | None = None,
    ) -> HttpResult: ...


class StdlibHttpsTransport:
    """Минимальный HTTPS transport без автоматических redirect."""

    def request(
        self,
        url: str,
        headers: dict[str, str],
        *,
        timeout: float,
        max_bytes: int,
        destination: BinaryIO | None = None,
    ) -> HttpResult:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
        ):
            raise GitHubUpdateError("redirect_denied", "Разрешены только HTTPS-адреса GitHub без credentials.")
        connection = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        try:
            connection.request("GET", target, headers=headers)
            response = connection.getresponse()
            response_headers = {key.lower(): value.strip() for key, value in response.getheaders()}
            raw_length = response_headers.get("content-length")
            if raw_length is not None:
                try:
                    content_length = int(raw_length)
                except ValueError as exc:
                    raise GitHubUpdateError("invalid_response", "GitHub вернул неверный Content-Length.") from exc
                if content_length < 0 or content_length > max_bytes:
                    raise GitHubUpdateError("asset_too_large", "Ответ GitHub превышает допустимый размер.")

            if response.status == 200 and destination is not None:
                written = 0
                while True:
                    chunk = response.read(min(1024 * 1024, max_bytes + 1 - written))
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > max_bytes:
                        raise GitHubUpdateError("asset_too_large", "Загрузка превысила допустимый размер.")
                    destination.write(chunk)
                return HttpResult(response.status, response_headers, bytes_written=written)

            body_limit = min(max_bytes, MAX_API_BYTES)
            body = response.read(body_limit + 1)
            if len(body) > body_limit:
                raise GitHubUpdateError("invalid_response", "Ответ GitHub превышает служебный лимит.")
            return HttpResult(response.status, response_headers, body=body)
        except (TimeoutError, socket.timeout) as exc:
            raise GitHubUpdateError("github_timeout", "GitHub не ответил за отведённое время.") from exc
        except GitHubUpdateError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise GitHubUpdateError("github_unavailable", "Не удалось подключиться к GitHub.") from exc
        finally:
            connection.close()


def normalize_github_settings(state: dict, *, mutate: bool = False) -> dict[str, Any]:
    """Возвращает строгие настройки фиксированного GitHub-источника."""
    if not isinstance(state, dict):
        raise GitHubUpdateError("config_invalid", "Корневое состояние должно быть объектом.")
    raw_updates = state.get("updates", {})
    if not isinstance(raw_updates, dict):
        raise GitHubUpdateError("config_invalid", "updates должен быть объектом.")
    raw = raw_updates.get("github", {})
    if not isinstance(raw, dict):
        raise GitHubUpdateError("config_invalid", "updates.github должен быть объектом.")
    allowed = {"enabled", "owner", "repo", "channel", "tag", "asset_preference"}
    if set(raw) - allowed:
        raise GitHubUpdateError("config_invalid", "В updates.github найдены неизвестные настройки.")

    enabled = raw.get("enabled", False)
    owner = raw.get("owner", GITHUB_OWNER)
    repo = raw.get("repo", GITHUB_REPO)
    channel = raw.get("channel", "stable")
    tag = raw.get("tag", "")
    preference = raw.get("asset_preference", "release")
    if not isinstance(enabled, bool):
        raise GitHubUpdateError("config_invalid", "updates.github.enabled должен быть true или false.")
    if owner != GITHUB_OWNER or repo != GITHUB_REPO:
        raise GitHubUpdateError("config_invalid", "Репозиторий обновлений менять запрещено.")
    if channel not in {"stable", "tag"}:
        raise GitHubUpdateError("config_invalid", "Канал должен быть stable или tag.")
    if not isinstance(tag, str) or (tag and TAG_RE.fullmatch(tag) is None):
        raise GitHubUpdateError("config_invalid", "Тег обновления имеет недопустимый формат.")
    if channel == "tag" and not tag:
        raise GitHubUpdateError("config_invalid", "Для канала tag нужен фиксированный тег.")
    if channel == "stable" and tag:
        raise GitHubUpdateError("config_invalid", "Канал stable не принимает тег.")
    if preference not in EXPECTED_ASSETS:
        raise GitHubUpdateError("config_invalid", "Предпочтительный asset должен быть release или deploy.")

    result = {
        "enabled": enabled,
        "owner": GITHUB_OWNER,
        "repo": GITHUB_REPO,
        "channel": channel,
        "tag": tag,
        "asset_preference": preference,
    }
    if mutate:
        updates = state.setdefault("updates", {})
        updates["github"] = dict(result)
    return result


def github_token_status(path: Path = GITHUB_TOKEN_FILE) -> dict[str, bool]:
    """Показывает только наличие и безопасные права token-файла."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"configured": False, "secure": True}
    except OSError:
        return {"configured": False, "secure": False}
    secure = path.is_file() and not path.is_symlink() and stat.st_size <= 4096
    if os.name == "posix":
        secure = secure and stat.st_uid == 0 and stat.st_mode & 0o077 == 0
    return {"configured": stat.st_size > 0, "secure": secure}


class GitHubReleaseSource:
    """Проверяет metadata и атомарно готовит allowlisted release asset."""

    def __init__(
        self,
        storage_root: Path,
        *,
        token_file: Path = GITHUB_TOKEN_FILE,
        transport: HttpTransport | None = None,
    ):
        self.storage_root = storage_root.resolve()
        self.token_file = token_file
        self.transport = transport or StdlibHttpsTransport()

    def _token(self) -> str:
        status = github_token_status(self.token_file)
        if not status["configured"]:
            return ""
        if not status["secure"]:
            raise GitHubUpdateError("credential_insecure", "GitHub token должен быть root-only файлом с mode 0600.")
        try:
            value = self.token_file.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError) as exc:
            raise GitHubUpdateError("credential_invalid", "GitHub token не читается.") from exc
        if not value or len(value) > 512 or any(char.isspace() or ord(char) < 33 for char in value):
            raise GitHubUpdateError("credential_invalid", "GitHub token имеет недопустимый формат.")
        return value

    def _headers(self, *, binary: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/octet-stream" if binary else "application/vnd.github+json",
            "User-Agent": "kvn-portal-agent/1",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }
        token = self._token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    @staticmethod
    def _http_error(result: HttpResult) -> GitHubUpdateError:
        if result.status in {403, 429}:
            return GitHubUpdateError("github_rate_limited", "GitHub отклонил запрос или исчерпан API rate limit.")
        if result.status == 404:
            return GitHubUpdateError("release_not_found", "Опубликованный GitHub Release не найден или недоступен.")
        return GitHubUpdateError("github_http_error", f"GitHub вернул HTTP {result.status}.")

    def _release_url(self, config: dict[str, Any]) -> str:
        base = f"{GITHUB_API_ORIGIN}/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases"
        if config["channel"] == "stable":
            return base + "/latest"
        return base + "/tags/" + quote(config["tag"], safe="")

    def settings(self, state: dict) -> dict[str, Any]:
        """Возвращает только публичную конфигурацию источника, без credential."""
        config = normalize_github_settings(state)
        return {
            "enabled": config["enabled"],
            "repository": f"{GITHUB_OWNER}/{GITHUB_REPO}",
            "channel": config["channel"],
            "tag": config["tag"],
            "asset_preference": config["asset_preference"],
        }

    def _api_json(self, url: str) -> dict[str, Any]:
        result = self.transport.request(
            url,
            self._headers(),
            timeout=CONNECT_TIMEOUT,
            max_bytes=MAX_API_BYTES,
        )
        if result.status != 200:
            raise self._http_error(result)
        try:
            value = json.loads(result.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GitHubUpdateError("invalid_response", "GitHub вернул некорректный JSON.") from exc
        if not isinstance(value, dict):
            raise GitHubUpdateError("invalid_response", "Ответ GitHub должен быть JSON-объектом.")
        return value

    @staticmethod
    def _asset_kind(name: str) -> str | None:
        for kind, expected in EXPECTED_ASSETS.items():
            if name == expected:
                return kind
        return None

    def check(self, state: dict) -> dict[str, Any]:
        config = normalize_github_settings(state)
        if not config["enabled"]:
            raise GitHubUpdateError("github_updates_disabled", "Обновления из GitHub отключены.")
        release = self._api_json(self._release_url(config))
        release_id = release.get("id")
        tag = release.get("tag_name")
        assets = release.get("assets")
        if (
            not isinstance(release_id, int)
            or release_id <= 0
            or not isinstance(tag, str)
            or TAG_RE.fullmatch(tag) is None
            or not isinstance(assets, list)
            or release.get("draft") is not False
        ):
            raise GitHubUpdateError("invalid_response", "Metadata GitHub Release неполны или release не опубликован.")
        if config["channel"] == "stable" and release.get("prerelease") is not False:
            raise GitHubUpdateError("invalid_response", "Канал stable отклонил prerelease.")
        if config["channel"] == "tag" and tag != config["tag"]:
            raise GitHubUpdateError("release_changed", "GitHub вернул release с другим тегом.")

        allowed_assets: dict[str, dict[str, Any]] = {}
        for raw_asset in assets:
            if not isinstance(raw_asset, dict):
                continue
            name = raw_asset.get("name")
            kind = self._asset_kind(name) if isinstance(name, str) else None
            if kind is None:
                continue
            asset_id = raw_asset.get("id")
            size = raw_asset.get("size")
            digest_value = raw_asset.get("digest")
            digest = digest_value.removeprefix("sha256:") if isinstance(digest_value, str) else ""
            if (
                not isinstance(asset_id, int)
                or asset_id <= 0
                or not isinstance(size, int)
                or not 1024 <= size <= ASSET_LIMITS[kind]
                or raw_asset.get("state") != "uploaded"
                or SHA256_RE.fullmatch(digest) is None
            ):
                raise GitHubUpdateError("invalid_asset", f"Asset {name} имеет небезопасные metadata.")
            if kind in allowed_assets:
                raise GitHubUpdateError("invalid_asset", f"Asset {name} опубликован более одного раза.")
            allowed_assets[kind] = {
                "id": asset_id,
                "name": name,
                "kind": kind,
                "size": size,
                "sha256": digest,
            }
        preferred = config["asset_preference"]
        selected = allowed_assets.get(preferred)
        if selected is None:
            raise GitHubUpdateError("asset_not_found", f"В release отсутствует ожидаемый {EXPECTED_ASSETS[preferred]}.")
        token_status = github_token_status(self.token_file)
        raw_notes = release.get("body", "")
        notes = CONTROL_TEXT_RE.sub("", raw_notes) if isinstance(raw_notes, str) else ""
        notes = notes.replace("\r\n", "\n").replace("\r", "\n")
        if len(notes) > 4000:
            notes = notes[:4000].rstrip() + "\n…"
        return {
            "ok": True,
            "repository": f"{GITHUB_OWNER}/{GITHUB_REPO}",
            "channel": config["channel"],
            "tag": tag,
            "release_id": release_id,
            "release_name": str(release.get("name") or tag)[:160],
            "published_at": str(release.get("published_at") or "")[:40],
            "notes": notes,
            "assets": [
                allowed_assets[kind]
                for kind in ("release", "deploy")
                if kind in allowed_assets
            ],
            "asset": selected,
            "authenticated": token_status["configured"] and token_status["secure"],
        }

    @staticmethod
    def _validate_expected(expected: dict[str, Any]) -> None:
        if set(expected) != {"release_id", "asset_id", "asset_sha256"}:
            raise GitHubUpdateError("invalid_params", "Подготовка принимает только release_id, asset_id и asset_sha256.")
        if (
            not isinstance(expected.get("release_id"), int)
            or expected["release_id"] <= 0
            or not isinstance(expected.get("asset_id"), int)
            or expected["asset_id"] <= 0
            or not isinstance(expected.get("asset_sha256"), str)
            or SHA256_RE.fullmatch(expected["asset_sha256"]) is None
        ):
            raise GitHubUpdateError("invalid_params", "Идентификаторы или SHA-256 обновления недопустимы.")

    @staticmethod
    def _redirect_target(current: str, location: str) -> str:
        target = urlsplit(urljoin(current, location))
        if (
            target.scheme != "https"
            or target.hostname not in ALLOWED_DOWNLOAD_HOSTS
            or target.username is not None
            or target.password is not None
            or target.port not in {None, 443}
        ):
            raise GitHubUpdateError("redirect_denied", "GitHub перенаправил загрузку на запрещённый адрес.")
        return target.geturl()

    def _download(self, asset: dict[str, Any], destination: BinaryIO) -> int:
        url = (
            f"{GITHUB_API_ORIGIN}/repos/{GITHUB_OWNER}/{GITHUB_REPO}"
            f"/releases/assets/{asset['id']}"
        )
        headers = self._headers(binary=True)
        for redirects in range(MAX_REDIRECTS + 1):
            result = self.transport.request(
                url,
                headers,
                timeout=DOWNLOAD_TIMEOUT,
                max_bytes=ASSET_LIMITS[asset["kind"]],
                destination=destination,
            )
            if result.status == 200:
                raw_length = result.headers.get("content-length")
                if raw_length is not None:
                    try:
                        content_length = int(raw_length)
                    except ValueError as exc:
                        raise GitHubUpdateError(
                            "invalid_response", "GitHub вернул неверный Content-Length."
                        ) from exc
                    if content_length != asset["size"]:
                        raise GitHubUpdateError(
                            "size_mismatch", "Content-Length не совпадает с metadata asset."
                        )
                if result.bytes_written != asset["size"]:
                    raise GitHubUpdateError("size_mismatch", "Размер загруженного asset не совпадает с metadata.")
                return result.bytes_written
            if result.status not in {301, 302, 303, 307, 308}:
                raise self._http_error(result)
            if redirects >= MAX_REDIRECTS:
                raise GitHubUpdateError("redirect_denied", "GitHub превысил лимит redirect.")
            location = result.headers.get("location", "")
            if not location or len(location) > 4096:
                raise GitHubUpdateError("invalid_response", "GitHub вернул redirect без допустимого Location.")
            url = self._redirect_target(url, location)
            if urlsplit(url).hostname != "api.github.com":
                headers = {key: value for key, value in headers.items() if key.lower() != "authorization"}
        raise GitHubUpdateError("redirect_denied", "GitHub превысил лимит redirect.")

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _validate_archive(path: Path, kind: str) -> dict[str, Any]:
        try:
            if kind == "release":
                manifest = validate_release(path)
                return {
                    "internal": "release-manifest.json",
                    "build_id": manifest["build_id"],
                    "source_sha256": manifest["source"]["sha256"],
                    "images_sha256": manifest["images"]["sha256"],
                }
            metadata = inspect_archive(path)
            return {
                "internal": "deploy-inspector",
                "member_count": metadata["member_count"],
            }
        except (ReleaseValidationError, ArchiveValidationError) as exc:
            raise GitHubUpdateError("invalid_archive", f"Внутренняя проверка архива не пройдена: {exc}") from exc

    def _cleanup_partials(self) -> int:
        removed = 0
        if not self.storage_root.exists():
            return removed
        for path in self.storage_root.glob(".*.part-*"):
            try:
                if path.is_file() and not path.is_symlink():
                    path.unlink()
                    removed += 1
            except OSError:
                continue
        return removed

    def prepare(self, state: dict, expected: dict[str, Any]) -> dict[str, Any]:
        self._validate_expected(expected)
        self.storage_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        cleaned = self._cleanup_partials()
        current = self.check(state)
        asset = current["asset"]
        if (
            current["release_id"] != expected["release_id"]
            or asset["id"] != expected["asset_id"]
            or not hmac.compare_digest(asset["sha256"], expected["asset_sha256"])
        ):
            raise GitHubUpdateError("release_changed", "Release изменился после проверки; выполните проверку ещё раз.")

        suffix = asset["sha256"][:12]
        local_name = asset["name"].removesuffix(".tar.gz") + f"-github-{suffix}.tar.gz"
        final_path = (self.storage_root / local_name).resolve()
        if not final_path.is_relative_to(self.storage_root):
            raise GitHubUpdateError("policy_denied", "Путь подготовленного обновления вышел за разрешённый каталог.")

        if final_path.exists() and not final_path.is_symlink():
            if final_path.stat().st_size == asset["size"] and self._sha256(final_path) == asset["sha256"]:
                try:
                    validation = self._validate_archive(final_path, asset["kind"])
                except GitHubUpdateError:
                    final_path.unlink(missing_ok=True)
                    raise
                return {
                    "ok": True,
                    "ready": True,
                    "reused": True,
                    "path": final_path,
                    "release": current,
                    "validation": {
                        "api_digest": True,
                        "download_sha256": True,
                        "internal_manifest": validation,
                    },
                    "partials_removed": cleaned,
                }
            final_path.unlink()

        temporary = self.storage_root / f".{local_name}.part-{os.getpid()}-{os.urandom(6).hex()}"
        try:
            with temporary.open("xb") as destination:
                temporary.chmod(0o600)
                self._download(asset, destination)
                destination.flush()
                os.fsync(destination.fileno())
            if self._sha256(temporary) != asset["sha256"]:
                raise GitHubUpdateError("digest_mismatch", "SHA-256 загруженного asset не совпадает с GitHub API.")
            validation = self._validate_archive(temporary, asset["kind"])
            os.replace(temporary, final_path)
            final_path.chmod(0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return {
            "ok": True,
            "ready": True,
            "reused": False,
            "path": final_path,
            "release": current,
            "validation": {
                "api_digest": True,
                "download_sha256": True,
                "internal_manifest": validation,
            },
            "partials_removed": cleaned,
        }
