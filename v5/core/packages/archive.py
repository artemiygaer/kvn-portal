"""Узкий потоковый формат USTAR+gzip, без распаковки произвольных путей."""

import hashlib
import hmac
import os
import tarfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from .manifest import (
    MAX_MANIFEST, MAX_PACKAGE, MAX_TAR, SHA256, Manifest, parse_manifest, reject,
)
from .signature import Publisher

BLOCK = 512
CHUNK = 128 * 1024
DISK_RESERVE = 32 * 1024**2
_ZERO_BLOCK = bytes(BLOCK)


def header(name: str, size: int) -> bytes:
    item = tarfile.TarInfo(name)
    item.mode, item.size = 0o600, size
    return item.tobuf(tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")


class _Compressed:
    def __init__(self, source: BinaryIO, limit: int):
        self.source = source
        self.limit = limit
        self.count = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        size = min(size if size >= 0 else CHUNK, self.limit - self.count + 1)
        block = self.source.read(size)
        self.count += len(block)
        if self.count > self.limit:
            reject("compressed_package_limit")
        self.digest.update(block)
        return block


class _GzipReader:
    """Декодировать один gzip-поток, ограничивая каждый кусок результата."""

    def __init__(self, source: _Compressed):
        self.source = source
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        self.pending = b""

    def read(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size and not self.decoder.eof:
            block = self.pending or self.source.read(CHUNK)
            data = self.decoder.decompress(block, size - len(result))
            result.extend(data)
            if self.decoder.eof:
                if self.decoder.unused_data or self.source.read(1):
                    reject("extra_gzip_data")
            elif not block and not data:
                reject("invalid_package_compression")
            self.pending = self.decoder.unconsumed_tail
        return bytes(result)


class _TarReader:
    def __init__(self, source: _GzipReader, limit: int):
        self.source = source
        self.limit = limit
        self.count = 0

    def read(self, size: int) -> bytes:
        result = self.source.read(min(size, self.limit - self.count + 1))
        self.count += len(result)
        if self.count > self.limit:
            reject("expanded_package_limit")
        return result

    def exact(self, size: int) -> bytes:
        result = self.read(size)
        if len(result) != size:
            reject("truncated_package")
        return result

    def member(self, name: str, limit: int, expected_size: int | None = None) -> int:
        raw = self.exact(BLOCK)
        # Не передаём чужие заголовки tar-парсеру: PAX, ссылки, sparse и
        # альтернативные имена не могут стать обычным членом архива.
        field = raw[124:136]
        if field[11:] != b"\0" or any(byte not in b"01234567" for byte in field[:11]):
            reject("unsupported_archive_header")
        size = int(field[:11], 8)
        if raw != header(name, size):
            reject("unsupported_archive_header")
        if not 0 < size <= limit or (expected_size is not None and size != expected_size):
            reject("archive_member_size")
        return size

    def pad(self, size: int) -> None:
        if any(self.exact(-size % BLOCK)):
            reject("invalid_archive_padding")

    def small(self, name: str, limit: int, expected_size: int | None = None) -> bytes:
        size = self.member(name, limit, expected_size)
        result = self.exact(size)
        self.pad(size)
        return result

    def finish(self) -> None:
        if self.exact(2 * BLOCK) != _ZERO_BLOCK * 2:
            reject("extra_archive_members")
        # Читаем до EOF (включая gzip CRC), но ограничиваем и пустой хвост.
        tail = self.read(10 * 1024 + 1)
        if len(tail) > 10 * 1024 or len(tail) % BLOCK or any(tail):
            reject("invalid_archive_trailer")


@dataclass(frozen=True)
class VerifiedPackage:
    manifest: Manifest
    archive_sha256: str
    manifest_sha256: str


def verify_archive(source: BinaryIO, publisher: Publisher, staging: Path, *,
                   expected_sha256: str | None = None, now: datetime | None = None,
                   compressed_limit: int = MAX_PACKAGE, expanded_limit: int = MAX_TAR) -> VerifiedPackage:
    """Писать только в новый закрытый staging; при ошибке его удаляет владелец."""
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256)
    ):
        reject("invalid_archive_digest")
    compressed = _Compressed(source, min(compressed_limit, MAX_PACKAGE))
    try:
        reader = _TarReader(_GzipReader(compressed), min(expanded_limit, MAX_TAR))
        manifest_bytes = reader.small("manifest.json", MAX_MANIFEST)
        signature = reader.small("manifest.sig", 64, 64)
        publisher.verify(manifest_bytes, signature, staging)
        manifest = parse_manifest(manifest_bytes, now)
        disk = os.statvfs(staging)
        if disk.f_bavail * disk.f_frsize < DISK_RESERVE + sum(resource.size for resource in manifest.resources):
            reject("package_disk_space")
        if manifest.resources:
            (staging / "payload").mkdir(mode=0o700)
        for resource in manifest.resources:
            size = reader.member(resource.path, resource.size, resource.size)
            resource_digest = hashlib.sha256()
            with (staging / resource.path).open("xb") as output:
                remaining = size
                while remaining:
                    block = reader.exact(min(CHUNK, remaining))
                    output.write(block)
                    resource_digest.update(block)
                    remaining -= len(block)
            reader.pad(size)
            if not hmac.compare_digest(resource_digest.hexdigest(), resource.sha256):
                reject("resource_hash_mismatch")
            if resource.kind == "notes":
                try:
                    (staging / resource.path).read_bytes().decode("utf-8")
                except UnicodeError:
                    reject("invalid_notes")
        reader.finish()
    except zlib.error:
        reject("invalid_package_compression")
    digest = compressed.digest.hexdigest()
    if expected_sha256 is not None and not hmac.compare_digest(expected_sha256, digest):
        reject("archive_hash_mismatch")
    (staging / "manifest.json").write_bytes(manifest_bytes)
    (staging / "manifest.sig").write_bytes(signature)
    return VerifiedPackage(manifest, digest, hashlib.sha256(manifest_bytes).hexdigest())
