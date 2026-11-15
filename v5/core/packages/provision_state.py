"""Root-only журнал отдельной задачи подготовки зависимостей."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from v5.core.private_files import private_directory, read_private, write_private

from .debian_provision import ProvisionError

ROOT = Path('/var/lib/kvn-v5/provision')
TICKET = re.compile(r'[a-f0-9]{64}\Z', re.ASCII)
MODULES = frozenset({'xray', 'hysteria', 'telemt', 'mtg', 'wireguard', 'amneziawg'})
CODES = frozenset({'ok', 'provision_busy', 'invalid_provision_request', 'unsupported_debian',
                   'amneziawg_provision_unavailable', 'provision_requires_root', 'provision_index_failed',
                   'provision_install_incomplete', 'provision_timeout_check_dpkg', 'provision_apt_unavailable',
                   'docker_unavailable', 'wireguard_tools_missing', 'wireguard_kernel_missing',
                   'module_not_installed', 'module_must_be_disabled', 'provision_existing_tools',
                   'provision_unconfirmed', 'provision_simulation_failed', 'amneziawg_profile_unsupported',
                   'amneziawg_kernel_missing', 'amneziawg_kernel_headers_missing', 'amneziawg_tools_missing',
                   'provision_failed'})


class ProvisionJournal:
    def __init__(self, root=ROOT, *, clock=time.time):
        self.root, self.clock = Path(root), clock

    @contextmanager
    def locked(self):
        private_directory(self.root)
        if self.root.resolve(strict=True) != self.root:
            raise ProvisionError('provision_failed')
        fd = os.open(self.root / '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ProvisionError('provision_failed')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ProvisionError('provision_busy') from exc
            yield
        finally:
            os.close(fd)

    def get(self):
        try:
            record = json.loads(read_private(self.root / 'job.json', 4096))
        except FileNotFoundError:
            return None
        if (not isinstance(record, dict) or set(record) != {'ticket', 'module', 'status', 'code', 'updated'}
                or not isinstance(record['ticket'], str) or TICKET.fullmatch(record['ticket']) is None
                or not isinstance(record['module'], str) or record['module'] not in MODULES
                or record['status'] not in ('queued', 'running', 'ready', 'failed')
                or not isinstance(record['code'], str) or record['code'] not in CODES
                or type(record['updated']) is not int or record['updated'] < 0
                or (record['status'] != 'failed' and record['code'] != 'ok')
                or (record['status'] == 'failed' and record['code'] == 'ok')):
            raise ProvisionError('provision_failed')
        return record

    def _write(self, record):
        write_private(self.root / 'job.json', json.dumps(record, separators=(',', ':')).encode('ascii'))

    def queue(self, module):
        if not isinstance(module, str) or module not in MODULES:
            raise ProvisionError('invalid_provision_request')
        with self.locked():
            current = self.get()
            if current and current['status'] in ('queued', 'running'):
                raise ProvisionError('provision_busy')
            record = {'ticket': secrets.token_hex(32), 'module': module, 'status': 'queued',
                      'code': 'ok', 'updated': int(self.clock())}
            self._write(record)
            return record

    def transition(self, ticket, expected, status, code):
        if (not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None
                or expected not in ('queued', 'running') or status not in ('running', 'ready', 'failed')
                or not isinstance(code, str) or code not in CODES or (status != 'failed' and code != 'ok')
                or (status == 'failed' and code == 'ok')):
            raise ProvisionError('invalid_provision_request')
        allowed = {('queued', 'running'), ('queued', 'failed'), ('running', 'ready'), ('running', 'failed')}
        if (expected, status) not in allowed:
            raise ProvisionError('invalid_provision_request')
        with self.locked():
            record = self.get()
            if not record or record['ticket'] != ticket or record['status'] != expected:
                raise ProvisionError('provision_busy')
            record.update(status=status, code=code, updated=int(self.clock()))
            self._write(record)
            return record
