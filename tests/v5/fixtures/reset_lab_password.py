"""Сменить синтетический пароль исключительно в изолированной Debian VM."""

import grp
import os
from pathlib import Path
import sys

from v5.core.maintenance import access


assert os.geteuid() == 0
assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
password = sys.stdin.read().strip()
assert len(password) >= 24
config = Path('/etc/kvn-v5')
access.change(config, grp.getgrnam('kvn-v5-web').gr_gid, 'admin', password,
              activate=lambda: access.restart_and_check(config))
print('Тестовый пароль изменён без вывода в журнал.', flush=True)
