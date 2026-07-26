"""Криптографические и HTTP-защитные примитивы портала."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import secrets
import threading
import time

SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_MAXMEM = 256 * 1024 * 1024
_HASH_LIMIT = threading.BoundedSemaphore(2)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    with _HASH_LIMIT:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=SCRYPT_DKLEN,
            maxmem=SCRYPT_MAXMEM,
        )


def hash_password(password: str) -> str:
    if not isinstance(password, str) or len(password) < 12:
        raise ValueError("Пароль администратора должен содержать не менее 12 символов.")
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        base64.urlsafe_b64encode(salt).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
    )


def _decode_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n_text, r_text, p_text, salt_text, digest_text = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        n, r, p = int(n_text), int(r_text), int(p_text)
        if n < SCRYPT_N or r < SCRYPT_R or p < SCRYPT_P:
            return False
        salt = _decode_b64(salt_text)
        expected = _decode_b64(digest_text)
        actual = _scrypt(password, salt, n, r, p)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def canonical_ip(value: str) -> str:
    try:
        return ipaddress.ip_address((value or "").strip()).compressed
    except ValueError as exc:
        raise ValueError("Некорректный адрес клиента.") from exc


def opaque_token(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def login_csrf(secret: str, ip: str, now: float | None = None) -> str:
    timestamp = int(now if now is not None else time.time())
    message = f"{timestamp}:{ip}".encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"{timestamp}.{signature}"


def verify_login_csrf(token: str, secret: str, ip: str, now: float | None = None, ttl: int = 900) -> bool:
    try:
        timestamp_text, signature = token.split(".", 1)
        timestamp = int(timestamp_text)
    except (ValueError, AttributeError):
        return False
    current = int(now if now is not None else time.time())
    if timestamp > current + 30 or current - timestamp > ttl:
        return False
    expected = login_csrf(secret, ip, timestamp).split(".", 1)[1]
    return hmac.compare_digest(signature, expected)
