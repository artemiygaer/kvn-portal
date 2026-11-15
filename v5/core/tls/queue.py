"""Короткий RPC ставит одну задачу; долгий ACME выполняет отдельная служба."""

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from .acme import ACME_ROOT, AcmeMode, AcmePlan
from .identity import TLSIdentity


GATEWAY_ROOT = Path("/etc/kvn-v5/gateway")
TLS_QUEUE = ACME_ROOT.parent / "tls"
MAX_JSON = 16384


def read_json(path: Path, default=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(MAX_JSON + 1)
    except FileNotFoundError:
        if default is not None:
            return default
        raise
    if not 1 <= len(data) <= MAX_JSON:
        raise ValueError("Некорректный размер состояния TLS")
    return json.loads(data)


def _write_json(path: Path, value) -> None:
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    if len(payload) > MAX_JSON:
        raise ValueError("Состояние TLS слишком большое")
    temporary = None
    try:
        with NamedTemporaryFile(mode="wb", prefix=".tls-", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def registry(path: Path = GATEWAY_ROOT / "identities.json") -> tuple[tuple[TLSIdentity, ...], bool]:
    data = read_json(path)
    if (not isinstance(data, dict) or set(data) != {"ip", "names", "ipv6"} or type(data["ipv6"]) is not bool
            or not isinstance(data["names"], list) or len(data["names"]) > 16):
        raise ValueError("Некорректный реестр TLS")
    names = (TLSIdentity(data["ip"], True), *(TLSIdentity(name, False) for name in data["names"]))
    if len(set(names)) != len(names):
        raise ValueError("В реестре TLS есть дубликаты")
    return names, data["ipv6"]


@dataclass(frozen=True, slots=True)
class TLSJob:
    identity: TLSIdentity
    mode: AcmeMode
    email: str

    @classmethod
    def parse(cls, data, identities: tuple[TLSIdentity, ...]):
        if (not isinstance(data, dict) or set(data) != {"name", "mode", "email"}
                or not all(isinstance(value, str) for value in data.values())):
            raise ValueError("Некорректные параметры выпуска TLS")
        identity = next((item for item in identities if item.name == data["name"]), None)
        if identity is None:
            raise ValueError("Имя не зарегистрировано на шлюзе")
        mode = AcmeMode(data["mode"])
        AcmePlan(identity, mode).issue(data["email"])
        return cls(identity, mode, data["email"])


class QueueBusy(RuntimeError):
    pass


class TLSQueue:
    def __init__(self, directory: Path = TLS_QUEUE):
        self.directory = directory
        self.pending = directory / "pending.json"
        self.results = directory / "results.json"

    @contextmanager
    def exclusive(self):
        fd = os.open(self.directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise QueueBusy from exc
            yield

    def submit(self, job: TLSJob) -> None:
        with self.exclusive():
            if self.pending.exists() or self.pending.is_symlink():
                raise QueueBusy
            _write_json(self.pending, {"name": job.identity.name, "mode": job.mode.value, "email": job.email})

    def take(self, identities: tuple[TLSIdentity, ...]) -> TLSJob | None:
        """Вызывать только внутри exclusive, убрать сигнал .path до сетевых операций."""
        try:
            data = read_json(self.pending)
        except FileNotFoundError:
            return None
        finally:
            self.pending.unlink(missing_ok=True)
        return TLSJob.parse(data, identities)

    def snapshot(self) -> dict:
        results = read_json(self.results, {})
        if not isinstance(results, dict):
            raise ValueError("Не читается отчёт TLS")
        try:
            with self.exclusive():
                busy = self.pending.exists()
        except QueueBusy:
            busy = True
        return {"busy": busy, "results": results}

    def record(self, records: dict) -> None:
        """Вызывать под exclusive, сохраняются только публичные статусы и сроки."""
        _write_json(self.results, records)
