"""Сборщик подписанного модуля. Запускается только на стороне издателя."""

import argparse
import gzip
import hashlib
import hmac
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from v5.core.contracts import ADAPTER_API_VERSION, CORE_API_VERSION, PACKAGE_FORMAT_VERSION
from v5.core.packages.archive import BLOCK, CHUNK, header, verify_archive
from v5.core.packages.manifest import MAX_IMAGE, MAX_NOTES, canonical_json, parse_manifest, reject
from v5.core.packages.signature import Publisher, parse_publisher


def _digest(path: Path, limit: int) -> tuple[int, str]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            size += len(chunk)
            if size > limit:
                reject("resource_size")
            digest.update(chunk)
    return size, digest.hexdigest()


def _run(*args: str, capture: bool = False) -> bytes:
    return subprocess.run(
        ["/usr/bin/openssl", *args], stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL, timeout=10, check=True,
        env={"LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
    ).stdout


def build(output: Path, key: Path, *, module_id: str, version: str,
          issued_at: str, expires_at: str, image_digest: str | None = None,
          notes: Path | None = None, image: Path | None = None,
          now: datetime | None = None, publisher_pin: Path | None = None) -> str:
    """Вернуть SHA-256 полностью проверенного результата."""
    files = [(kind, name, path, *_digest(path, limit))
             for kind, name, path, limit in (
                 ("notes", "payload/notes.txt", notes, MAX_NOTES),
                 ("image", "payload/image.tar", image, MAX_IMAGE),
             ) if path is not None]
    manifest = canonical_json({
        "format": PACKAGE_FORMAT_VERSION, "core_api": CORE_API_VERSION, "adapter_api": ADAPTER_API_VERSION,
        "module_id": module_id, "version": version, "issued_at": issued_at, "expires_at": expires_at,
        "image_digest": image_digest,
        "resources": [{"kind": kind, "path": name, "size": size, "sha256": digest}
                      for kind, name, _, size, digest in files],
    })
    parse_manifest(manifest, now)
    with tempfile.TemporaryDirectory(prefix=".kvn-build-", dir=output.parent) as directory:
        root = Path(directory)
        data, signature, archive = (root / name for name in ("data", "signature", "package"))
        data.write_bytes(manifest)
        _run("pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(data), "-out", str(signature))
        public_der = _run("pkey", "-in", str(key), "-pubout", "-outform", "DER", capture=True)
        publisher = Publisher(public_der, hashlib.sha256(public_der).hexdigest())
        if publisher_pin is not None:
            with publisher_pin.open("rb") as pin_file:
                pinned = parse_publisher(pin_file.read(4097))
            if not hmac.compare_digest(publisher.public_der, pinned.public_der):
                reject("publisher_key_mismatch")
        with archive.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as tar:
            for name, body in (("manifest.json", manifest), ("manifest.sig", signature.read_bytes())):
                tar.write(header(name, len(body)))
                tar.write(body)
                tar.write(bytes(-len(body) % BLOCK))
            for _, name, path, size, _ in files:
                tar.write(header(name, size))
                with path.open("rb") as source:
                    remaining = size
                    while remaining:
                        chunk = source.read(min(remaining, CHUNK))
                        if not chunk:
                            reject("build_resource_changed")
                        tar.write(chunk)
                        remaining -= len(chunk)
                    if source.read(1):
                        reject("build_resource_changed")
                tar.write(bytes(-size % BLOCK))
            tar.write(bytes(2 * BLOCK))
        verified_path = root / "verified"
        verified_path.mkdir(mode=0o700)
        with archive.open("rb") as source:
            checked = verify_archive(source, publisher, verified_path, now=now)
        os.chmod(archive, 0o600)
        os.replace(archive, output)
        return checked.archive_sha256


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--module-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--issued-at", default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--notes", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--image-digest")
    parser.add_argument("--publisher-pin", type=Path,
                        help="Публичный пин выпуска: проверить соответствие ключу до публикации")
    args = vars(parser.parse_args())
    print(build(**args))


if __name__ == "__main__":
    main()
