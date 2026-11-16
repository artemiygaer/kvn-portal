"""Восстановить старый тестовый updater с увеличенным тайм-аутом только в этой VM."""

from pathlib import Path
from v5.core.maintenance import core_update

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
original = core_update.wait_login
core_update.wait_login = lambda config: original(config, timeout=180)
core_update.CoreUpdate().recover()
print('Лабораторный core-recover подтверждён с увеличенным тайм-аутом.', flush=True)
