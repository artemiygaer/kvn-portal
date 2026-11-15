"""Валидация кандидата до записи в действующий TLS-каталог."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from .identity import TLSIdentity


SYSTEM_CA = Path("/etc/ssl/certs/ca-certificates.crt")
MAX_CHAIN_BYTES = 128 * 1024
MAX_KEY_BYTES = 16 * 1024
_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")
_KEY = re.compile(rb"-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY)-----\r?\n"
                  rb"[A-Za-z0-9+/=\r\n]+-----END \1-----")
_MONTH = {month: index for index, month in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


class CertificateError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    identity: TLSIdentity
    not_before: datetime
    not_after: datetime


def _openssl(*arguments: str, data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(["/usr/bin/openssl", *arguments], input=data, capture_output=True,
                                timeout=10, check=False, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CertificateError("openssl_failed", "Не удалось выполнить проверку OpenSSL") from exc
    if result.returncode:
        raise CertificateError("invalid_certificate", "OpenSSL отклонил сертификат или ключ")
    return result.stdout


def _split_chain(fullchain: bytes) -> list[bytes]:
    if not isinstance(fullchain, bytes) or len(fullchain) > MAX_CHAIN_BYTES:
        raise CertificateError("invalid_certificate", "Цепочка сертификатов слишком большая или некорректна")
    start = 0
    blocks = []
    for match in _CERT.finditer(fullchain):
        if fullchain[start:match.start()].strip():
            break
        blocks.append(match.group() + b"\n")
        start = match.end()
    if not 1 <= len(blocks) <= 8 or fullchain[start:].strip():
        raise CertificateError("invalid_certificate", "Ожидается PEM-цепочка из сертификатов")
    return blocks


def _parse_date(raw: str) -> datetime:
    month, day, clock, year, zone = raw.split()
    if zone != "GMT":
        raise ValueError("Некорректная зона OpenSSL")
    hour, minute, second = (int(item) for item in clock.split(":"))
    return datetime(int(year), _MONTH[month], int(day), hour, minute, second, tzinfo=timezone.utc)


def _read_metadata(leaf: bytes, identity: TLSIdentity) -> CertificateInfo:
    data = _openssl("x509", "-noout", "-startdate", "-enddate", "-ext", "subjectAltName", data=leaf)
    try:
        begin, end, extension, *values = data.decode("ascii").strip().splitlines()
        if not begin.startswith("notBefore=") or not end.startswith("notAfter="):
            raise ValueError("Нет срока действия")
        not_before = _parse_date(begin.removeprefix("notBefore="))
        not_after = _parse_date(end.removeprefix("notAfter="))
    except (ValueError, KeyError) as exc:
        raise CertificateError("invalid_certificate", "Не удалось прочитать свойства сертификата") from exc
    label = "IP Address:" if identity.is_ip else "DNS:"
    fields = [item.strip() for item in " ".join(values).split(",")]
    if extension.strip().startswith("X509v3 Subject Alternative Name:") and len(fields) == 1 and fields[0].startswith(label):
        try:
            candidate = TLSIdentity(fields[0].removeprefix(label), identity.is_ip)
            if candidate == identity:
                return CertificateInfo(identity, not_before, not_after)
        except ValueError:
            pass
    raise CertificateError("san_mismatch", "Сертификат должен содержать один точный SAN для этого имени или IP")


def read_certificate_info(identity: TLSIdentity, fullchain: bytes) -> CertificateInfo:
    """Прочитать SAN и даты сохранённого поколения без проверки текущего срока."""
    leaf, *_ = _split_chain(fullchain)
    return _read_metadata(leaf, identity)


def validate_pair(identity: TLSIdentity, fullchain: bytes, key: bytes, *, ca_file: Path = SYSTEM_CA) -> CertificateInfo:
    """Проверить точный SAN, срок, цепочку сервера и принадлежность ключа."""
    if not isinstance(key, bytes) or not 1 <= len(key) <= MAX_KEY_BYTES or not _KEY.fullmatch(key.strip()):
        raise CertificateError("invalid_key", "Ожидается один незашифрованный закрытый ключ PEM")
    leaf, *intermediates = _split_chain(fullchain)
    info = _read_metadata(leaf, identity)
    now = datetime.now(timezone.utc)
    if info.not_before > now:
        raise CertificateError("not_yet_valid", "Срок действия сертификата ещё не начался")
    if info.not_after <= now + timedelta(minutes=10):
        raise CertificateError("expires_too_soon", "Сертификат просрочен или истекает менее чем через 10 минут")
    try:
        key_public = _openssl("pkey", "-pubout", "-passin", "pass:", data=key)
    except CertificateError as exc:
        if exc.code == "openssl_failed":
            raise
        raise CertificateError("invalid_key", "Закрытый ключ недействителен или зашифрован") from exc
    if key_public != _openssl("x509", "-noout", "-pubkey", data=leaf):
        raise CertificateError("key_mismatch", "Сертификат и закрытый ключ не образуют пару")
    with TemporaryDirectory(prefix="kvn-v5-cert-") as directory:
        leaf_path = Path(directory) / "leaf.pem"
        leaf_path.write_bytes(leaf)
        args = ["verify", "-purpose", "sslserver", "-CAfile", str(ca_file), "-no-CApath", "-no-CAstore",
                "-verify_ip" if identity.is_ip else "-verify_hostname", identity.name]
        if intermediates:
            chain_path = Path(directory) / "chain.pem"
            chain_path.write_bytes(b"".join(intermediates))
            args.extend(("-untrusted", str(chain_path)))
        try:
            _openssl(*args, str(leaf_path))
        except CertificateError as exc:
            if exc.code == "openssl_failed":
                raise
            raise CertificateError("untrusted_chain", "Цепочка сертификата не доверена для HTTPS") from exc
    return info
