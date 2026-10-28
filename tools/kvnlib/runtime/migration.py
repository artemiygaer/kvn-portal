"""Ограниченное шифрование миграции через системный GnuPG, без crypto-самоделок."""

from __future__ import annotations

import os
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from collections.abc import Callable

from ..core.io import JsonStateStore, TransactionResult
from ..core.migration import plan_migration, validate_identity_complete

MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024
MAX_ENCRYPTED_BYTES = 8 * 1024 * 1024
MAX_STATUS_BYTES = 64 * 1024
GPG_TIMEOUT_SECONDS = 30


class MigrationCryptoError(ValueError):
    """Безопасная ошибка шифрования без включения содержимого или stderr GnuPG."""


def _passphrase_bytes(passphrase: str) -> bytes:
    if (not isinstance(passphrase, str) or len(passphrase) < 12 or len(passphrase) > 256
            or any(ch in passphrase for ch in "\x00\r\n")):
        raise MigrationCryptoError("Фраза шифрования должна содержать 12–256 символов без перевода строки.")
    encoded = passphrase.encode("utf-8")
    if len(encoded) > 1024:
        raise MigrationCryptoError("Фраза шифрования слишком длинная.")
    return encoded


def _crypt(data: bytes, passphrase: str, *, decrypt: bool) -> bytes:
    phrase = _passphrase_bytes(passphrase)
    if not isinstance(data, bytes) or not data:
        raise MigrationCryptoError("Архив миграции пуст или имеет неверный тип.")
    if len(data) > (MAX_ENCRYPTED_BYTES if decrypt else MAX_PLAINTEXT_BYTES):
        raise MigrationCryptoError("Архив миграции превышает допустимый размер.")
    executable = shutil.which("gpg")
    if os.name != "posix" or executable is None:
        raise MigrationCryptoError("Для миграции на сервере требуется GnuPG с поддержкой passphrase-fd.")

    with tempfile.TemporaryDirectory(prefix="kvn-migration-gpg-") as temporary:
        os.chmod(temporary, 0o700)
        read_fd, write_fd = os.pipe()
        try:
            # В pipe только короткая фраза, она не видна в argv/env и /proc/*/cmdline.
            os.write(write_fd, phrase + b"\n")
            os.close(write_fd)
            write_fd = -1
            command = [executable, "--no-options", "--homedir", temporary, "--batch", "--yes",
                       "--no-tty", "--pinentry-mode", "loopback", "--no-symkey-cache",
                       "--passphrase-fd", str(read_fd), "--status-fd", "2",
                       "--max-output", str(MAX_PLAINTEXT_BYTES if decrypt else MAX_ENCRYPTED_BYTES)]
            if decrypt:
                command.extend(["--decrypt", "--output", "-"])
            else:
                command.extend(["--symmetric", "--cipher-algo", "AES256", "--force-mdc",
                                "--compress-algo", "none", "--s2k-mode", "3", "--s2k-count", "65011712",
                                "--output", "-"])
            with tempfile.TemporaryFile(mode="w+b", dir=temporary) as status:
                try:
                    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=status,
                                            timeout=GPG_TIMEOUT_SECONDS, check=False,
                                            pass_fds=(read_fd,),
                                            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                                 "HOME": temporary, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise MigrationCryptoError("Не удалось выполнить GnuPG в допустимое время.") from exc
                status.seek(0)
                evidence = status.read(MAX_STATUS_BYTES + 1)
            if result.returncode or len(evidence) > MAX_STATUS_BYTES:
                raise MigrationCryptoError("Архив повреждён, пароль неверен или проверка GnuPG не пройдена.")
            if decrypt and (b"[GNUPG:] DECRYPTION_OKAY" not in evidence or b"[GNUPG:] GOODMDC" not in evidence):
                raise MigrationCryptoError("Архив не содержит подтверждённой защиты целостности.")
            limit = MAX_PLAINTEXT_BYTES if decrypt else MAX_ENCRYPTED_BYTES
            if not result.stdout or len(result.stdout) > limit:
                raise MigrationCryptoError("Результат GnuPG пуст или превышает допустимый размер.")
            return result.stdout
        finally:
            if write_fd >= 0:
                os.close(write_fd)
            os.close(read_fd)
            # Закрываем только agent с временным GNUPGHOME, не системные процессы пользователя.
            gpgconf = shutil.which("gpgconf")
            if gpgconf and Path(temporary).is_dir():
                try:
                    subprocess.run([gpgconf, "--homedir", temporary, "--kill", "gpg-agent"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=3, check=False)
                except (OSError, subprocess.TimeoutExpired):
                    pass


def encrypt_migration(data: bytes, passphrase: str) -> bytes:
    """Шифрует ограниченный JSON с AES-256 и обязательной проверкой целостности."""
    return _crypt(data, passphrase, decrypt=False)


def decrypt_migration(data: bytes, passphrase: str) -> bytes:
    """Возвращает plaintext только после успешного GPG MDC и проверки лимитов."""
    return _crypt(data, passphrase, decrypt=True)


def _private_backup(store: JsonStateStore, backup_dir: Path) -> None:
    """До замены state сохраняет исходные байты в приватный каталог владельца процесса."""
    directory = Path(backup_dir)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    details = directory.lstat()
    if not stat.S_ISDIR(details.st_mode) or stat.S_IMODE(details.st_mode) != 0o700:
        raise MigrationCryptoError("Каталог резервных копий должен быть приватным.")
    if os.name == "posix" and details.st_uid != os.geteuid():
        raise MigrationCryptoError("Неверный владелец каталога резервных копий.")
    source_fd = os.open(store.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    destination = None
    try:
        source_info = os.fstat(source_fd)
        if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > 16 * 1024 * 1024:
            raise MigrationCryptoError("Невозможно безопасно сохранить резервную копию состояния.")
        destination_fd, destination_name = tempfile.mkstemp(prefix="migration-", suffix=".json", dir=directory)
        destination = Path(destination_name)
        try:
            with os.fdopen(destination_fd, "wb") as backup, os.fdopen(os.dup(source_fd), "rb") as source:
                os.fchmod(backup.fileno(), 0o600)
                shutil.copyfileobj(source, backup, length=64 * 1024)
                backup.flush()
                os.fsync(backup.fileno())
            if os.name == "posix":
                directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            destination = None
        finally:
            if destination is not None:
                destination.unlink(missing_ok=True)
    finally:
        os.close(source_fd)


def commit_migration(store: JsonStateStore, envelope: dict, *, mode: str, revision: str,
                     backup_dir: Path, validate: Callable[[dict], None]) -> TransactionResult:
    """Атомарно применяет проверенный план при совпадении ревизии и наличии бэкапа."""
    if not isinstance(revision, str) or not revision:
        raise MigrationCryptoError("Для переноса требуется ревизия предварительного просмотра.")
    validate_identity_complete(envelope)

    def mutate(current: dict) -> dict:
        planned = plan_migration(current, envelope, mode)
        validate(planned)
        return planned

    return store.update(mutate, expected_revision=revision,
                        before_replace=lambda _candidate: _private_backup(store, backup_dir))


def restore_migration_backup(store: JsonStateStore, *, backup_dir: Path, name: str, revision: str,
                             validate: Callable[[dict], None]) -> TransactionResult:
    """Восстанавливает только приватный backup при совпадении ревизии текущего state."""
    if not isinstance(name, str) or not re.fullmatch(r"migration-[a-z0-9_]{8}\.json", name):
        raise MigrationCryptoError("Некорректное имя резервной копии.")
    if not isinstance(revision, str) or not revision:
        raise MigrationCryptoError("Для восстановления требуется текущая ревизия.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_DIRECTORY", 0)
    directory = os.open(backup_dir, flags)
    try:
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or (os.name == "posix" and info.st_uid != os.geteuid())):
            raise MigrationCryptoError("Каталог резервных копий имеет небезопасные права.")
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
        try:
            item = os.fstat(fd)
            if (not stat.S_ISREG(item.st_mode) or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) != 0o600
                    or item.st_size < 1 or item.st_size > 16 * 1024 * 1024
                    or (os.name == "posix" and item.st_uid != os.geteuid())):
                raise MigrationCryptoError("Резервная копия имеет небезопасный тип или права.")
            with os.fdopen(os.dup(fd), "rb") as handle:
                raw = handle.read(16 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    if len(raw) > 16 * 1024 * 1024:
        raise MigrationCryptoError("Резервная копия слишком велика.")
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise MigrationCryptoError("Резервная копия повреждена.") from exc
    if not isinstance(state, dict) or not isinstance(state.get("users", []), list):
        raise MigrationCryptoError("Резервная копия содержит некорректное состояние.")
    validate(state)
    return store.update(lambda _current: state, expected_revision=revision,
                        before_replace=lambda _candidate: _private_backup(store, backup_dir))
