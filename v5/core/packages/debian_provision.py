"""Фиксированный план зависимостей Debian; никаких команд из браузера."""

from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
from contextlib import contextmanager


class ProvisionError(ValueError):
    """Код отказа без вывода конфигурации хоста."""


@dataclass(frozen=True, slots=True)
class Debian:
    version: str
    codename: str


_RELEASES = {'12': 'bookworm', '13': 'trixie'}
_CONTAINER_MODULES = frozenset({'xray', 'hysteria', 'telemt', 'mtg'})
_WG_TOOLS = ('wireguard-tools', 'nftables')
# Общедоступный sticky-каталог нужен, чтобы APT мог сбросить права до _apt.
# Его содержимое не содержит секретов; подкаталог создаёт root с непредсказуемым именем.
WORK_ROOT = Path('/var/tmp')
LOCK_FILE = Path('/run/lock/kvn-v5-debian-apt.lock')


def parse_os_release(raw: str) -> Debian:
    """Принять только штатные Debian 12/13 без исполнения shell-содержимого."""
    if not isinstance(raw, str) or len(raw) > 8192 or '\x00' in raw:
        raise ProvisionError('unsupported_debian')
    fields = {}
    for line in raw.splitlines():
        if not line or line.startswith('#'):
            continue
        name, separator, value = line.partition('=')
        if not separator or name not in ('ID', 'VERSION_ID', 'VERSION_CODENAME'):
            continue
        if name in fields:
            raise ProvisionError('unsupported_debian')
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if not re.fullmatch(r'[a-zA-Z0-9._-]{1,32}', value, re.ASCII):
            raise ProvisionError('unsupported_debian')
        fields[name] = value
    version = fields.get('VERSION_ID')
    if fields.get('ID') != 'debian' or version not in _RELEASES or fields.get('VERSION_CODENAME') != _RELEASES[version]:
        raise ProvisionError('unsupported_debian')
    return Debian(version, _RELEASES[version])


def debian_sources(system: Debian) -> str:
    """Только подписанные архивным ключом Debian источники текущего выпуска."""
    if (not isinstance(system, Debian) or not isinstance(system.version, str)
            or not isinstance(system.codename, str) or _RELEASES.get(system.version) != system.codename):
        raise ProvisionError('unsupported_debian')
    key = '/usr/share/keyrings/debian-archive-keyring.gpg'
    return (f'deb [signed-by={key}] https://deb.debian.org/debian {system.codename} main\n'
            f'deb [signed-by={key}] https://deb.debian.org/debian {system.codename}-updates main\n'
            f'deb [signed-by={key}] https://security.debian.org/debian-security {system.codename}-security main\n')


def package_plan(module: object, *, docker_present: bool, wg_present: bool, nft_present: bool,
                 system: Debian | None = None, debian_docker_daemon: bool = False) -> tuple[str, ...]:
    """Вернуть только недостающие фиксированные пакеты, не изменяя систему."""
    if any(type(value) is not bool for value in (docker_present, wg_present, nft_present, debian_docker_daemon)):
        raise ProvisionError('invalid_provision_request')
    if not isinstance(module, str):
        raise ProvisionError('invalid_provision_request')
    if module in _CONTAINER_MODULES:
        if docker_present:
            return ()
        if system is not None:
            debian_sources(system)
        if debian_docker_daemon:
            if system != Debian('13', 'trixie'):
                raise ProvisionError('provision_existing_tools')
            return ('docker-cli',)
        return ('docker.io', 'docker-cli') if system == Debian('13', 'trixie') else ('docker.io',)
    if module == 'wireguard':
        return tuple(name for name, present in zip(_WG_TOOLS, (wg_present, nft_present)) if not present)
    if module == 'amneziawg':
        # Отдельный проверяемый путь upstream 3.1 требует реализации и E2E.
        raise ProvisionError('amneziawg_provision_unavailable')
    raise ProvisionError('invalid_provision_request')


def apt_commands(stage: Path, packages: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Сформировать ограниченные argv; подготовка каталога и запуск выполняются отдельно."""
    if (not isinstance(stage, Path) or stage.parent != WORK_ROOT
            or not re.fullmatch(r'apt-[a-f0-9]{32}', stage.name, re.ASCII)):
        raise ProvisionError('invalid_provision_stage')
    allowed = {'docker.io', 'docker-cli', 'wireguard-tools', 'nftables'}
    if (not isinstance(packages, tuple) or not packages
            or any(not isinstance(name, str) or name not in allowed for name in packages)
            or len(packages) != len(set(packages))
            or (set(packages) & {'docker.io', 'docker-cli'} and set(packages) - {'docker.io', 'docker-cli'})):
        raise ProvisionError('invalid_provision_request')
    options = ('-o', f'Dir::Etc::sourcelist={stage / "sources.list"}',
               '-o', f'Dir::Etc::sourceparts={stage / "empty"}', '-o', f'Dir::State::lists={stage / "lists"}',
               '-o', 'Dir::Etc::preferences=-', '-o', f'Dir::Etc::preferencesparts={stage / "empty"}',
               '-o', 'Dir::Etc::trusted=-', '-o', f'Dir::Etc::trustedparts={stage / "empty"}',
               '-o', f'Dir::Cache::archives={stage / "archives"}',
               '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::AllowInsecureRepositories=false',
               '-o', 'Acquire::http::Timeout=30', '-o', 'Acquire::https::Timeout=30',
               '-o', 'Acquire::Retries=1', '-o', 'DPkg::Lock::Timeout=15')
    apt = ('/usr/bin/apt-get', *options)
    return (apt + ('update', '--error-on=any'),
            apt + ('install', '-y', '--no-install-recommends', '--no-remove', '--no-upgrade', *packages))


@contextmanager
def apt_stage(system: Debian):
    """Создать и убрать только собственный APT-каталог с публичными метаданными."""
    info = WORK_ROOT.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)):
        raise ProvisionError('invalid_provision_stage')
    sources = debian_sources(system)
    stage = WORK_ROOT / ('apt-' + secrets.token_hex(16))
    stage.mkdir(mode=0o755)
    try:
        stage.chmod(0o755)
        (stage / 'empty').mkdir(mode=0o755)
        (stage / 'empty').chmod(0o755)
        for name in ('lists', 'archives'):
            folder = stage / name
            folder.mkdir(mode=0o755)
            folder.chmod(0o755)
            (folder / 'partial').mkdir(mode=0o700)
        for name, content in (('sources.list', sources),
                              ('apt.conf', f'Dir::Etc::main "-";\nDir::Etc::parts "{stage / "empty"}";\n')):
            path = stage / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'w', encoding='ascii') as stream:
                stream.write(content)
            path.chmod(0o644)
        yield stage
    finally:
        info = stage.lstat()
        if (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stage.parent == WORK_ROOT
                and re.fullmatch(r'apt-[a-f0-9]{32}', stage.name, re.ASCII)):
            shutil.rmtree(stage)
        else:
            raise ProvisionError('invalid_provision_stage')


@contextmanager
def provision_lock(path: Path = LOCK_FILE):
    """Не запускать одновременно две установки; штатную блокировку dpkg не обходить."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ProvisionError('invalid_provision_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProvisionError('provision_busy') from exc
        yield
    finally:
        os.close(fd)


def run_apt_transaction(system: Debian, packages: tuple[str, ...], *, run=subprocess.run,
                        lock_path: Path = LOCK_FILE) -> None:
    """Выполнить фиксированный APT-план; вызывающий отдельно проверяет готовность сервиса."""
    if os.geteuid() != 0:
        raise ProvisionError('provision_requires_root')
    # До блокировки и записи проверяем типы и допускаемые имена пакетов.
    apt_commands(WORK_ROOT / ('apt-' + '0' * 32), packages)
    with provision_lock(lock_path), apt_stage(system) as stage:
        commands = apt_commands(stage, packages)
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
               'DEBIAN_FRONTEND': 'noninteractive', 'APT_CONFIG': str(stage / 'apt.conf')}
        for index, command in enumerate(commands):
            try:
                result = run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=300 if index == 0 else None, check=False, env=env)
            except subprocess.TimeoutExpired as exc:
                raise ProvisionError('provision_timeout_check_dpkg') from exc
            except OSError as exc:
                raise ProvisionError('provision_apt_unavailable') from exc
            if result.returncode:
                raise ProvisionError('provision_index_failed' if index == 0 else 'provision_install_incomplete')
