"""Изолированные пары TLS и откат конфигурации шлюза при отказе reload."""

from collections.abc import Callable
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from tempfile import NamedTemporaryFile, mkdtemp

from .certificates import CertificateInfo, MAX_CHAIN_BYTES, MAX_KEY_BYTES, SYSTEM_CA, read_certificate_info, validate_pair
from .identity import TLSIdentity


def _private_directory(path: Path) -> None:
    attrs = path.lstat()
    if not stat.S_ISDIR(attrs.st_mode) or attrs.st_uid != os.geteuid() or attrs.st_mode & 0o077:
        raise ValueError("TLS-каталог должен принадлежать владельцу процесса и быть закрытым")


def _private_file(path: Path) -> None:
    attrs = path.lstat()
    if not stat.S_ISREG(attrs.st_mode) or attrs.st_uid != os.geteuid() or attrs.st_mode & 0o077:
        raise ValueError("Рабочий TLS-файл должен быть обычным закрытым файлом владельца процесса")


def _write_secret(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _read_secret(path: Path, maximum: int) -> bytes:
    _private_file(path)
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        raise ValueError("Недопустимый размер TLS-файла")
    return data


def read_gateway_config(path: Path) -> bytes:
    _private_directory(path.parent)
    return _read_secret(path, 256 * 1024)


def _pair_digest(fullchain: bytes, key: bytes) -> str:
    return hashlib.sha256(fullchain + b"\0" + key).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredPair:
    metadata: CertificateInfo
    chain: Path
    key: Path


class CertificateStore:
    """Путь поколения неизменяем: nginx читает оба файла из одной версии."""

    def __init__(self, directory: Path, *, ca_file: Path = SYSTEM_CA):
        self.directory = directory
        self.ca_file = ca_file

    def stage(self, identity: TLSIdentity, fullchain: bytes, key: bytes) -> StoredPair:
        _private_directory(self.directory)
        info = validate_pair(identity, fullchain, key, ca_file=self.ca_file)
        slot = self.directory / identity.slot
        slot.mkdir(mode=0o700, exist_ok=True)
        _private_directory(slot)
        generation = slot / _pair_digest(fullchain, key)
        chain, key_file = generation / "fullchain.pem", generation / "privkey.pem"
        if not generation.exists():
            temporary = Path(mkdtemp(prefix=".stage-", dir=slot))
            try:
                _write_secret(temporary / chain.name, fullchain)
                _write_secret(temporary / key_file.name, key)
                try:
                    temporary.rename(generation)
                except OSError:
                    if not generation.is_dir():
                        raise
            finally:
                if temporary.exists():
                    (temporary / chain.name).unlink(missing_ok=True)
                    (temporary / key_file.name).unlink(missing_ok=True)
                    temporary.rmdir()
        _private_directory(generation)
        for path in (chain, key_file):
            _private_file(path)
        if (chain.stat().st_size != len(fullchain) or key_file.stat().st_size != len(key)
                or chain.read_bytes() != fullchain or key_file.read_bytes() != key):
            raise ValueError("Содержимое сохранённого поколения TLS изменилось")
        return StoredPair(info, chain, key_file)

    def load(self, identity: TLSIdentity, digest: str) -> StoredPair:
        """Загрузить уже применённую пару, включая просроченную, не меняя её на диске."""
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Некорректное поколение TLS")
        _private_directory(self.directory)
        slot = self.directory / identity.slot
        _private_directory(slot)
        generation = slot / digest
        _private_directory(generation)
        chain, key = generation / "fullchain.pem", generation / "privkey.pem"
        fullchain = _read_secret(chain, MAX_CHAIN_BYTES)
        if _pair_digest(fullchain, _read_secret(key, MAX_KEY_BYTES)) != digest:
            raise ValueError("Содержимое сохранённого поколения TLS изменилось")
        return StoredPair(read_certificate_info(identity, fullchain), chain, key)


class GatewayApplyError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _temp_config(parent: Path, contents: bytes) -> Path:
    path: Path | None = None
    try:
        with NamedTemporaryFile(mode="wb", prefix=".nginx-", dir=parent, delete=False) as stream:
            path = Path(stream.name)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except BaseException:
        if path is not None:
            path.unlink(missing_ok=True)
        raise


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_gateway(config: Path, candidate: bytes, *, check: Callable[[Path], None],
                    reload: Callable[[], None], verify_live: Callable[[], None],
                    verify_restored: Callable[[], None], expected: bytes | None = None) -> None:
    """Проверить nginx -t, заменить конфиг, дождаться активной версии или откатить."""
    if not isinstance(candidate, bytes) or not 1 <= len(candidate) <= 256 * 1024:
        raise ValueError("Некорректный размер конфигурации шлюза")
    _private_directory(config.parent)
    descriptor = os.open(config.parent / ".gateway.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _private_file(config)
        if config.stat().st_size > 256 * 1024:
            raise ValueError("Действующая конфигурация шлюза слишком большая")
        previous = config.read_bytes()
        if expected is not None and expected != previous:
            raise GatewayApplyError("revision_changed", "Конфигурация шлюза уже изменилась; повторите операцию")
        stage = _temp_config(config.parent, candidate)
        saved = None
        try:
            try:
                check(stage)
            except Exception as exc:
                raise GatewayApplyError("config_invalid", "Новая конфигурация шлюза не прошла проверку") from exc
            saved = _temp_config(config.parent, previous)
            os.replace(stage, config)
            try:
                _sync_directory(config.parent)
                reload()
                verify_live()
            except BaseException as exc:
                try:
                    os.replace(saved, config)
                    _sync_directory(config.parent)
                    reload()
                    verify_restored()
                except Exception as failure:
                    raise GatewayApplyError("rollback_unconfirmed", "Откат шлюза не подтверждён") from failure
                if not isinstance(exc, Exception):
                    raise
                raise GatewayApplyError("apply_rolled_back", "Новая версия шлюза не ответила; прежняя восстановлена") from exc
        finally:
            stage.unlink(missing_ok=True)
            if saved is not None:
                saved.unlink(missing_ok=True)
