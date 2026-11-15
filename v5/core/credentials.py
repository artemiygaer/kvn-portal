"""Единое представление логина и хеша администратора v5."""

import hashlib
import hmac
import re
import secrets

LOGIN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z", re.ASCII)
PASSWORD_METHOD = "scrypt:32768:8:3"
MIN_PASSWORD = 12
MAX_PASSWORD = 256


def hash_admin_password(password: str) -> str:
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise ValueError("Пароль должен содержать от 12 до 256 символов")
    salt = secrets.token_bytes(16)
    return f"{PASSWORD_METHOD}${salt.hex()}${_derive(password, salt).hex()}"


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3,
                          dklen=32, maxmem=64 * 1024 * 1024)


def verify_admin_password(password: str, digest: str) -> bool:
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        return False
    try:
        method, salt_hex, expected_hex = digest.split("$")
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(expected_hex)
        if method != PASSWORD_METHOD or len(salt) != 16 or len(expected) != 32:
            return False
        return hmac.compare_digest(_derive(password, salt), expected)
    except (ValueError, TypeError, AttributeError):
        return False
