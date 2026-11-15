"""Закрытая обработка совместимого .kvn через GnuPG без записи открытого архива."""

import os
import subprocess
from tempfile import TemporaryDirectory, TemporaryFile

MAX_ENCRYPTED = 8 * 1024 * 1024
MAX_PLAINTEXT = 4 * 1024 * 1024
_MAX_STATUS = 64 * 1024
_TIMEOUT = 30
_GPG = "/usr/bin/gpg"
_GPGCONF = "/usr/bin/gpgconf"


class ArchiveError(ValueError):
    """Код для UI без фразы, материала ключей и вывода подпроцесса."""


def _phrase_bytes(phrase: str) -> bytes:
    if not isinstance(phrase, str) or not 12 <= len(phrase) <= 256 or any(ch in phrase for ch in "\x00\n\r"):
        raise ArchiveError("migration_phrase_invalid")
    try:
        value = phrase.encode("utf-8")
    except UnicodeError:
        raise ArchiveError("migration_phrase_invalid") from None
    if len(value) > 1024:
        raise ArchiveError("migration_phrase_invalid")
    return value


def _stop_agent(directory: str, env: dict) -> None:
    try:
        subprocess.run([_GPGCONF, "--homedir", directory, "--kill", "gpg-agent"], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _crypt(data: bytes, phrase: str, *, decrypt: bool) -> bytes:
    incoming, outgoing = ((MAX_ENCRYPTED, MAX_PLAINTEXT) if decrypt else (MAX_PLAINTEXT, MAX_ENCRYPTED))
    if not isinstance(data, bytes) or not 0 < len(data) <= incoming:
        raise ArchiveError("migration_archive_size")
    phrase_data = _phrase_bytes(phrase)
    with TemporaryDirectory(prefix="kvn-v5-migration-") as home:
        env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": home, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        read_fd, write_fd = os.pipe()
        try:
            # Фраза короче PIPE_BUF; GnuPG получает её по FD, не через argv или окружение.
            try:
                os.write(write_fd, phrase_data + b"\n")
            finally:
                os.close(write_fd)
            command = [_GPG, "--no-options", "--homedir", home, "--batch", "--yes", "--no-tty",
                       "--pinentry-mode", "loopback", "--no-symkey-cache", "--no-auto-key-retrieve",
                       "--passphrase-fd", str(read_fd), "--status-fd", "2", "--max-output", str(outgoing),
                       "--output", "-"]
            command.extend(["--decrypt"] if decrypt else ["--symmetric", "--cipher-algo", "AES256", "--force-mdc",
                           "--compress-algo", "none", "--s2k-mode", "3", "--s2k-count", "65011712"])
            with TemporaryFile(dir=home) as status:
                result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=status,
                                        pass_fds=(read_fd,), timeout=_TIMEOUT, check=False, env=env)
                status.seek(0)
                evidence = status.read(_MAX_STATUS + 1)
        except (OSError, subprocess.TimeoutExpired):
            raise ArchiveError("migration_crypto_unavailable") from None
        finally:
            os.close(read_fd)
            _stop_agent(home, env)
    if result.returncode or len(evidence) > _MAX_STATUS or not 0 < len(result.stdout) <= outgoing:
        raise ArchiveError("migration_archive_invalid")
    if decrypt:
        statuses = {line.partition(b" ")[2].split(b" ", 1)[0] for line in evidence.splitlines()
                    if line.startswith(b"[GNUPG:] ")}
        if not {b"DECRYPTION_OKAY", b"GOODMDC"} <= statuses:
            raise ArchiveError("migration_archive_invalid")
    return result.stdout


def decrypt_archive(data: bytes, phrase: str) -> bytes:
    """Не отдавать открытые данные до проверки целостности всего архива."""
    return _crypt(data, phrase, decrypt=True)


def encrypt_archive(data: bytes, phrase: str) -> bytes:
    return _crypt(data, phrase, decrypt=False)
