"""Проверка только локального пароля root; заблокированная запись запрещена."""

import ctypes
import hmac
from pathlib import Path
from threading import Lock
import time

_CRYPT_LOCK = Lock()
MAX_PASSWORD_BYTES = 1024


def _crypt(password: bytes, setting: bytes) -> bytes | None:
    with _CRYPT_LOCK:
        crypt = ctypes.CDLL("libcrypt.so.1").crypt
        crypt.argtypes = ctypes.c_char_p, ctypes.c_char_p
        crypt.restype = ctypes.c_char_p
        return crypt(password, setting)


def verify_root(password: str, *, shadow=Path("/etc/shadow"), clock=time.time, crypt=_crypt) -> bool:
    if not isinstance(password, str):
        return False
    try:
        raw = password.encode()
        if not 0 < len(raw) <= MAX_PASSWORD_BYTES or b"\0" in raw:
            return False
        with shadow.open("rb") as stream:
            content = stream.read(256 * 1024 + 1)
        if len(content) > 256 * 1024:
            return False
        rows = [line.split(b":") for line in content.splitlines() if line.startswith(b"root:")]
        if len(rows) != 1 or len(rows[0]) != 9:
            return False
        _, digest, changed, _, maximum, _, _, expires, _ = rows[0]
        if not digest.startswith(b"$") or len(digest) > 1024:
            return False
        today = int(clock()) // 86400
        if changed == b"0" or (expires and int(expires) >= 0 and today >= int(expires)):
            return False
        if changed and maximum and int(maximum) >= 0 and today > int(changed) + int(maximum):
            return False
        candidate = crypt(raw, digest)
        return isinstance(candidate, bytes) and hmac.compare_digest(candidate, digest)
    except (OSError, ValueError, UnicodeError):
        return False
