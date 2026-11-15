"""Ed25519 через системный OpenSSL; ключ не берётся из архива."""

import hashlib
import hmac
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .manifest import json_object, reject

_ED25519_SPKI = bytes.fromhex("302a300506032b6570032100")
PIN_PATH = Path("/etc/kvn-v5/packages/publisher.json")


def parse_publisher(raw: bytes) -> "Publisher":
    if len(raw) > 4096:
        reject("invalid_publisher_pin")
    doc = json_object(raw)
    if doc.keys() != {"public_der", "sha256"}:
        reject("invalid_publisher_pin")
    public = doc["public_der"]
    if not isinstance(public, str) or not re.fullmatch(r"[0-9a-f]{88}", public):
        reject("invalid_publisher_pin")
    return Publisher(bytes.fromhex(public), doc["sha256"])


def load_publisher(path: Path = PIN_PATH):
    """Пин приходит с доверенной установкой или от root по отдельному каналу."""
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path, flags), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                reject("insecure_publisher_pin")
            raw = handle.read(4097)
    except FileNotFoundError:
        reject("publisher_not_configured")
    except OSError:
        reject("insecure_publisher_pin")
    return parse_publisher(raw)


@dataclass(frozen=True)
class Publisher:
    public_der: bytes
    fingerprint: str

    def __post_init__(self) -> None:
        if (type(self.public_der) is not bytes
                or len(self.public_der) != len(_ED25519_SPKI) + 32
                or not self.public_der.startswith(_ED25519_SPKI)
                or not isinstance(self.fingerprint, str)
                or not self.fingerprint.isascii()
                or not hmac.compare_digest(hashlib.sha256(self.public_der).hexdigest(), self.fingerprint)):
            reject("invalid_publisher_pin")

    def verify(self, manifest: bytes, signature: bytes, staging: Path) -> None:
        if len(signature) != 64:
            reject("invalid_signature_size")
        # Ed25519 в OpenSSL 3.0 требует seekable input для -rawin.
        with tempfile.TemporaryDirectory(prefix="verify-", dir=staging) as directory:
            root = Path(directory)
            key, data, sig = (root / name for name in ("publisher.der", "manifest.json", "manifest.sig"))
            key.write_bytes(self.public_der)
            data.write_bytes(manifest)
            sig.write_bytes(signature)
            try:
                result = subprocess.run(
                    ["/usr/bin/openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                     "-keyform", "DER", "-inkey", str(key), "-in", str(data), "-sigfile", str(sig)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5, check=False, env={"LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
                )
            except (OSError, subprocess.TimeoutExpired):
                reject("signature_verifier_unavailable")
            if result.returncode != 0:
                reject("invalid_package_signature")
