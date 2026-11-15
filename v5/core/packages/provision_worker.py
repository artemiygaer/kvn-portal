"""Фоновая подготовка зависимостей только проверенного выключенного модуля."""

from pathlib import Path
import os
import subprocess

from v5.core import audit
from v5.modules.host_tunnel.config import AWG, WG
from v5.modules.host_tunnel.platform import capability, trusted_tool

from .debian_provision import ProvisionError, package_plan, parse_os_release, run_apt_transaction
from .awg_repository import run_transaction as run_awg_transaction
from .manifest import PackageError
from .provision_state import CODES, MODULES, ProvisionJournal, TICKET
from .registry import PackageRegistry
from .signature import load_publisher
from .status import PACKAGE_STATE

_CONTAINER = frozenset({'xray', 'hysteria', 'telemt', 'mtg'})
_DOCKER_CLI = ('/usr/bin/docker', '/usr/local/bin/docker')
_DOCKER_ENGINE = ('/usr/bin/dockerd', '/usr/sbin/dockerd', '/usr/local/bin/dockerd')
_WG = ('/usr/bin/wg',)
_NFT = ('/usr/sbin/nft', '/usr/bin/nft')
_AWG = ('/usr/local/bin/awg', '/usr/bin/awg', '/usr/local/sbin/awg', '/usr/sbin/awg')


def _existing(paths):
    return any(os.path.lexists(path) for path in paths)


def _debian_docker_daemon():
    try:
        result = subprocess.run(['/usr/bin/dpkg-query', '-S', '/usr/sbin/dockerd'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        return result.returncode == 0 and result.stdout.strip() == b'docker.io: /usr/sbin/dockerd'
    except (OSError, subprocess.SubprocessError):
        return False


def _awg_package_present():
    try:
        result = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\n',
                                 'amneziawg-tools', 'amneziawg-dkms', 'amneziawg'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        if result.returncode not in (0, 1):
            raise ProvisionError('provision_apt_unavailable')
        return any(line not in (b'not-installed', b'unknown') for line in result.stdout.splitlines())
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError('provision_apt_unavailable') from exc


def _docker_ready(binary):
    if binary is None:
        return False
    try:
        result = subprocess.run([binary, 'info', '--format', '{{.ServerVersion}}'], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        return result.returncode == 0 and bool(result.stdout.strip()) and len(result.stdout) < 256
    except (OSError, subprocess.SubprocessError):
        return False


def prepare(module):
    if not isinstance(module, str) or module not in MODULES:
        raise ProvisionError('invalid_provision_request')
    if not (PACKAGE_STATE / 'registry.sqlite3').is_file():
        raise ProvisionError('module_not_installed')
    system = parse_os_release(Path('/etc/os-release').read_text(encoding='utf-8'))
    packages = PackageRegistry(PACKAGE_STATE, load_publisher())
    with packages.runtime_guard():
        packages.require_network_idle()
        row = next((item for item in packages.installed() if item['module'] == module), None)
        if row is None:
            raise ProvisionError('module_not_installed')
        if row['enabled'] or row.get('updating'):
            raise ProvisionError('module_must_be_disabled')
        packages.verified_install(module)
        if module == 'amneziawg':
            host = capability(AWG)
            if host.issue is None and '3.1' in host.profiles:
                return
            if _existing(_AWG) or host.module_available or _awg_package_present():
                raise ProvisionError('provision_existing_tools')
            run_awg_transaction(system, os.uname().release)
            host = capability(AWG)
            if host.issue:
                raise ProvisionError(host.issue)
            if '3.1' not in host.profiles:
                raise ProvisionError('amneziawg_profile_unsupported')
            return
        docker = trusted_tool(_DOCKER_CLI)
        wg, nft = trusted_tool(_WG), trusted_tool(_NFT)
        debian_daemon = False
        if module in _CONTAINER and _existing(_DOCKER_CLI + _DOCKER_ENGINE) and docker is None:
            debian_daemon = (not _existing(_DOCKER_CLI) and _debian_docker_daemon()
                             and system.version == '13')
            if not debian_daemon:
                raise ProvisionError('provision_existing_tools')
        if module == 'wireguard' and ((_existing(('/usr/local/bin/wg',)) and wg is None)
                                      or (_existing(('/usr/local/sbin/nft',)) and nft is None)):
            raise ProvisionError('provision_existing_tools')
        plan = package_plan(module, docker_present=docker is not None, wg_present=wg is not None,
                            nft_present=nft is not None, system=system, debian_docker_daemon=debian_daemon)
        if plan:
            run_apt_transaction(system, plan)
        if module in _CONTAINER and not _docker_ready(trusted_tool(_DOCKER_CLI)):
            raise ProvisionError('docker_unavailable')
        if module == 'wireguard':
            if trusted_tool(_WG) is None or trusted_tool(_NFT) is None:
                raise ProvisionError('wireguard_tools_missing')
            issue = capability(WG).issue
            if issue:
                raise ProvisionError(issue)


def perform(ticket, journal: ProvisionJournal, *, executor=prepare):
    if not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None:
        raise ProvisionError('invalid_provision_request')
    record = journal.transition(ticket, 'queued', 'running', 'ok')
    try:
        executor(record['module'])
    except (ProvisionError, PackageError, OSError, ValueError, subprocess.SubprocessError) as exc:
        code = str(exc)
        code = code if code in CODES and code != 'ok' else 'provision_failed'
        journal.transition(ticket, 'running', 'failed', code)
        audit.record('provision.prepare', False, record['module'])
        return False
    except Exception:
        # Не раскрываем внутренние ошибки или данные системы в журнале портала.
        journal.transition(ticket, 'running', 'failed', 'provision_failed')
        audit.record('provision.prepare', False, record['module'])
        return False
    journal.transition(ticket, 'running', 'ready', 'ok')
    audit.record('provision.prepare', True, record['module'])
    return True


def main():
    import sys

    if len(sys.argv) != 2 or TICKET.fullmatch(sys.argv[1]) is None:
        return 2
    try:
        return 0 if perform(sys.argv[1], ProvisionJournal()) else 1
    except (ProvisionError, OSError, ValueError):
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
