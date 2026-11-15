"""Связать подписанный digest OCI с файлами docker load, не меняя теги."""

from dataclasses import dataclass
import hashlib
from pathlib import Path
import platform
import stat
import tarfile

from .manifest import MAX_IMAGE, SHA256, json_object, reject


INDEX = "application/vnd.oci.image.index.v1+json"
IMAGE = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYERS = frozenset(f"application/vnd.oci.image.layer.v1.tar{suffix}" for suffix in ("", "+gzip", "+zstd"))
_META = frozenset({"oci-layout", "index.json", "manifest.json", "repositories"})
_BLOB = "blobs/sha256/"
_MAX_JSON = 256 * 1024


@dataclass(frozen=True, slots=True)
class VerifiedImage:
    manifest_digest: str
    config_digest: str
    architecture: str


def architecture() -> str:
    result = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if result is None:
        reject("unsupported_image_architecture")
    return result


def _descriptor(value, media_types):
    if (not isinstance(value, dict) or not {"digest", "mediaType", "size"} <= value.keys()
            or not isinstance(value["mediaType"], str) or value["mediaType"] not in media_types
            or "urls" in value or "data" in value or not isinstance(value["digest"], str)
            or not value["digest"].startswith("sha256:") or not SHA256.fullmatch(value["digest"][7:])
            or type(value["size"]) is not int or not 1 <= value["size"] <= MAX_IMAGE):
        reject("invalid_oci_descriptor")
    return value["digest"][7:], value["size"]


def _read(tar, entries, name):
    info = entries.get(name)
    if info is None or not 0 < info.size <= _MAX_JSON:
        reject("invalid_oci_metadata")
    with tar.extractfile(info) as stream:
        return stream.read(_MAX_JSON + 1)


def _hash(tar, info):
    with tar.extractfile(info) as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _verify(tar, expected, arch):
    entries = {}
    directories = set()
    for item in tar:
        name = item.name
        if item.pax_headers or item.sparse is not None or name in entries or name in directories:
            reject("unsafe_oci_archive")
        if item.isdir() and name in {"blobs", "blobs/sha256"}:
            directories.add(name)
            continue
        if (item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or not 1 <= item.size <= MAX_IMAGE
                or (name not in _META and not (name.startswith(_BLOB) and SHA256.fullmatch(name[len(_BLOB):])))):
            reject("unsafe_oci_archive")
        entries[name] = item
        if len(entries) > 132:
            reject("oci_member_limit")
    if json_object(_read(tar, entries, "oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
        reject("invalid_oci_layout")
    index = json_object(_read(tar, entries, "index.json"))
    manifest_list = index.get("manifests")
    if index.get("schemaVersion") != 2 or index.get("mediaType") != INDEX or not isinstance(manifest_list, list) or len(manifest_list) != 1:
        reject("invalid_oci_index")
    manifest = _descriptor(manifest_list[0], {IMAGE})
    if manifest[0] != expected:
        reject("oci_manifest_digest_mismatch")
    image = json_object(_read(tar, entries, _BLOB + manifest[0]))
    if image.get("schemaVersion") != 2 or image.get("mediaType") != IMAGE:
        reject("invalid_oci_image")
    config = _descriptor(image.get("config"), {CONFIG})
    layers = image.get("layers")
    if not isinstance(layers, list) or not 1 <= len(layers) <= 128:
        reject("invalid_oci_layers")
    layers = [_descriptor(layer, LAYERS) for layer in layers]
    wanted = {_BLOB + digest for digest, _ in (manifest, config, *layers)}
    if set(entries) - _META != wanted:
        reject("oci_blobs_mismatch")
    for digest, size in (manifest, config, *layers):
        item = entries[_BLOB + digest]
        if item.size != size or _hash(tar, item) != digest:
            reject("oci_blob_digest_mismatch")
    platform_data = json_object(_read(tar, entries, _BLOB + config[0]))
    if platform_data.get("os") != "linux" or platform_data.get("architecture") != arch:
        reject("oci_platform_mismatch")
    docker = json_object(b'{"entry":' + _read(tar, entries, "manifest.json") + b"}")
    legacy = docker.get("entry")
    if (docker.keys() != {"entry"} or not isinstance(legacy, list) or len(legacy) != 1
            or not isinstance(legacy[0], dict) or legacy[0].keys() != {"Config", "Layers", "RepoTags"}
            or legacy[0]["RepoTags"] not in (None, []) or legacy[0]["Config"] != _BLOB + config[0]
            or legacy[0]["Layers"] != [_BLOB + digest for digest, _ in layers]
            or ("repositories" in entries and json_object(_read(tar, entries, "repositories")) != {})):
        reject("unsafe_docker_manifest")
    return VerifiedImage(manifest[0], config[0], arch)


def verify_oci(path: Path, expected: str, *, arch: str | None = None) -> VerifiedImage:
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        reject("invalid_image_digest")
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_IMAGE:
            reject("unsafe_oci_archive")
        with tarfile.open(path, "r:") as tar:
            return _verify(tar, expected, architecture() if arch is None else arch)
    except (OSError, tarfile.TarError, EOFError, RecursionError):
        reject("invalid_oci_archive")
