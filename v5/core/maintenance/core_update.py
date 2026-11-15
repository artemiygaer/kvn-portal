"""Атомарное переключение кода ядра и восстановление по локальному журналу."""

import ctypes
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile

from v5.core.console import AGENT_UNIT, SOCKET_UNIT, WEB_SOCKET_UNIT, WEB_UNIT
from v5.core.private_files import private_directory, read_private, write_private
from v5.core.release import LIVE, TRIGGERS, UNIT_FILES, installed_version, stable_version, verified_release

from .access import SYSTEMCTL, _sync_dir, wait_login
from .backup import read_owned
from .core_stage import stage_archive

_WEB = ("kvn-v5-agent.service", "kvn-v5-web.service")
_TRIGGERS = tuple(item for item in TRIGGERS if item.endswith((".socket", ".path", ".timer"))) + (
    SOCKET_UNIT, WEB_SOCKET_UNIT, "kvn-v5-observer.service")
_NEW_UNITS = frozenset((AGENT_UNIT, SOCKET_UNIT, WEB_UNIT, WEB_SOCKET_UNIT, "kvn-v5-observer.service",
                        "kvn-v5-socket-observer.socket", "kvn-v5-socket-observer@.service",
                        "kvn-v5-core-update.socket", "kvn-v5-core-update@.service", "kvn-v5-core-apply@.service",
                        "kvn-v5-provision@.service", "kvn-v5-forwarding.service"))
_BUSY = ("kvn-v5-package@*.service", "kvn-v5-lifecycle@*.service", "kvn-v5-migration@*.service",
         "kvn-v5-socket-observer@*.service", "kvn-v5-core-update@*.service",
         "kvn-v5-tls.service", "kvn-v5-tls-renew.service", "kvn-v5-module-tls-sync.service",
         "kvn-v5-provision@*.service", "kvn-v5-forwarding.service")


class UpdateError(RuntimeError):
    """Причина сформирована ядром, без вывода внешней команды."""


def _sync_tree(path: Path) -> None:
    if path.is_dir():
        for child in path.iterdir():
            _sync_tree(child)
        _sync_dir(path)
    else:
        with path.open("rb") as handle:
            os.fsync(handle.fileno())


def _atomic_unit(path: Path, data: bytes) -> None:
    stage = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".kvn-unit-", delete=False) as stream:
            stage = Path(stream.name)
            stream.write(data)
            os.fchmod(stream.fileno(), 0o644)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(stage, path)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


def exchange(left: Path, right: Path) -> None:
    # На Debian 12/13 атомарно меняем деревья местами без пустого live-пути.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(left), -100, os.fsencode(right), 2):
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    _sync_dir(left.parent)
    _sync_dir(right.parent)


def _identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("Недопустимое дерево ядра")
    return info.st_dev, info.st_ino


class Systemd:
    def __init__(self, config=Path("/etc/kvn-v5")):
        self.config = config

    @staticmethod
    def run(*args, check=True, capture=False, timeout=60, cwd=None, **identity):
        return subprocess.run(args, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=check, timeout=timeout, cwd=cwd, **identity)

    def validate(self, directory):
        self.run("/usr/bin/systemd-analyze", "verify", *(str(directory / unit) for unit in UNIT_FILES))

    def triggers(self):
        return tuple(unit for unit in _TRIGGERS if self.run(
            SYSTEMCTL, "is-active", "--quiet", unit, check=False).returncode == 0)

    def quiesce(self):
        active = self.triggers()
        if active:
            self.run(SYSTEMCTL, "stop", *active)
        jobs = self.run(SYSTEMCTL, "list-units", "--no-legend", "--plain",
                        "--state=active,activating,deactivating", *_BUSY, capture=True)
        if jobs.stdout.strip():
            raise UpdateError("Дождитесь завершения TLS, операций модулей и переноса.")
        self.run(SYSTEMCTL, "stop", *_WEB)

    def reload(self):
        self.run(SYSTEMCTL, "daemon-reload")

    def activate(self, triggers):
        self.run(SYSTEMCTL, "reset-failed", *_WEB, check=False)
        self.run(SYSTEMCTL, "start", *_WEB)
        wait_login(self.config)
        # Отдельная проверка RPC от настоящего UID веб-процесса.
        web = pwd.getpwnam("kvn-v5-web")
        try:
            self.run("/usr/bin/python3", "-c",
                     "import sys; from pathlib import Path; from v5.portal.rpc import HostClient; "
                     "state=HostClient(Path('/run/kvn-v5-agent/control.sock'))._request('health', {}); "
                     "sys.exit(0 if state.get('status') == 'ready' else 1)",
                     timeout=25, cwd=LIVE, user=web.pw_uid, group=web.pw_gid, extra_groups=())
        except subprocess.SubprocessError as exc:
            raise UpdateError("HTTPS отвечает, но локальный RPC веб-службы не подтвердился.") from exc
        if triggers:
            self.run(SYSTEMCTL, "start", *triggers)


class CoreUpdate:
    def __init__(self, live=LIVE, units=Path("/etc/systemd/system"), *, system=None):
        self.live, self.units = live, units
        self.root = live.parent / ".kvn-v5-core"
        self.pending, self.previous = self.root / "pending", self.root / "previous"
        self.system = system if system is not None else Systemd()

    def _journal(self, directory):
        private_directory(directory)
        row = json.loads(read_private(directory / "journal.json", 4096))
        if (not isinstance(row, dict) or set(row) != {"old", "new", "triggers", "version"}
                or any(not isinstance(row[k], list) or len(row[k]) != 2
                       or any(type(n) is not int or n <= 0 for n in row[k]) for k in ("old", "new"))
                or not isinstance(row["triggers"], list) or any(x not in _TRIGGERS for x in row["triggers"])):
            raise ValueError("Не читается журнал обновления")
        stable_version(row["version"])
        return row

    @staticmethod
    def _read_unit(directory, unit, *, allow_absent=False):
        path = directory / unit
        try:
            return read_owned(path, 0o644, maximum=16 * 1024)
        except FileNotFoundError:
            if not allow_absent or path.is_symlink() or path.exists():
                raise
            return None

    def _copy_units(self, directory, *, restoring=False):
        entries = {unit: self._read_unit(directory, unit, allow_absent=restoring and unit in _NEW_UNITS)
                   for unit in UNIT_FILES}
        current = {unit: self._read_unit(self.units, unit, allow_absent=unit in _NEW_UNITS) for unit in UNIT_FILES}
        changed = False
        for unit, data in entries.items():
            path = self.units / unit
            if current[unit] != data:
                if data is None:
                    # Не ломать пользовательское состояние и при недоступном systemd.
                    # Самостоятельная служба не зависит от версии кода портала.
                    if unit == "kvn-v5-forwarding.service":
                        continue
                    path.unlink()
                else:
                    _atomic_unit(path, data)
                changed = True
        if changed:
            _sync_dir(self.units)
        # Даже если файлы совпали, PID1 мог не получить daemon-reload до сбоя.
        self.system.reload()

    def _restore(self):
        row = self._journal(self.pending)
        old, new = tuple(row["old"]), tuple(row["new"])
        tree = self.pending / "tree"
        current, saved = _identity(self.live), _identity(tree)
        if (current, saved) not in ((old, new), (new, old)):
            raise ValueError("Текущее дерево не соответствует журналу; автоматический откат запрещён")
        try:
            self.system.quiesce()
        except BaseException:
            self.system.activate(row["triggers"])
            raise
        if current == new:
            exchange(self.live, tree)
        self._copy_units(self.pending / "old-units", restoring=True)
        self.system.activate(row["triggers"])
        self._finish_pending()

    def _finish_pending(self):
        # Сначала убрать маркер атомарно; прерванная очистка не блокирует восстановление.
        with tempfile.TemporaryDirectory(prefix="clean-", dir=self.root) as directory:
            self.pending.rename(Path(directory) / "transaction")
            _sync_dir(self.root)

    def apply(self, source, publisher, uid):
        old = _identity(self.live)
        self.root.mkdir(mode=0o700, exist_ok=True)
        private_directory(self.root)
        if self.pending.exists() or self.pending.is_symlink():
            raise UpdateError("Найдено прерванное обновление. Сначала выполните core-recover.")
        with tempfile.TemporaryDirectory(prefix="prepare-", dir=self.root) as directory:
            stage = Path(directory) / "transaction"
            stage.mkdir(mode=0o700)
            release, raw = verified_release(source, publisher, stage)
            version = installed_version(self.live)
            if version is not None and stable_version(release.version) <= stable_version(version):
                raise UpdateError("Повторная установка или понижение версии не разрешены.")
            stage_archive(raw, release.version, stage, uid)
            del raw
            self.system.validate(stage / "new-units")
            saved = stage / "old-units"
            saved.mkdir(mode=0o700)
            for unit in UNIT_FILES:
                body = self._read_unit(self.units, unit, allow_absent=unit in _NEW_UNITS)
                if body is not None:
                    path = saved / unit
                    path.write_bytes(body)
                    path.chmod(0o644)
            row = {"old": old, "new": _identity(stage / "tree"), "triggers": self.system.triggers(),
                   "version": release.version}
            write_private(stage / "journal.json", json.dumps(row).encode(), replace=False)
            _sync_tree(stage)
            stage.rename(self.pending)
            _sync_dir(self.root)
        try:
            self.system.quiesce()
        except BaseException:
            self.system.activate(row["triggers"])
            self._finish_pending()
            raise
        try:
            exchange(self.live, self.pending / "tree")
            self._copy_units(self.pending / "new-units")
            self.system.activate(row["triggers"])
        except BaseException as failure:
            try:
                self._restore()
            except Exception as recovery:
                raise UpdateError("Откат не подтверждён. Журнал сохранён; выполните core-recover по SSH.") from recovery
            if isinstance(failure, Exception):
                raise UpdateError("Новая версия не прошла проверку. Прежнее ядро восстановлено.") from failure
            raise
        if self.previous.exists() or self.previous.is_symlink():
            private_directory(self.previous)
            shutil.rmtree(self.previous)
        self.pending.rename(self.previous)
        _sync_dir(self.root)
        return release.version

    def recover(self, *, previous=False):
        private_directory(self.root)
        if previous:
            if self.pending.exists() or self.pending.is_symlink():
                raise UpdateError("Сначала завершите прерванное обновление без --previous.")
            row = self._journal(self.previous)
            if _identity(self.live) != tuple(row["new"]):
                raise ValueError("Сохранённая версия не соответствует текущему дереву")
            self.previous.rename(self.pending)
            _sync_dir(self.root)
        self._restore()
