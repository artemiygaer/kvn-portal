"""Проверить, что нагрузка измеряется на пустом ядре учебной VM."""

import os
from pathlib import Path
import sqlite3
import subprocess

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
assert os.cpu_count() == 1
mem_total = next(line for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:'))
assert 850000 <= int(mem_total.split()[1]) <= 1100000
database = Path('/var/lib/kvn-v5/packages/registry.sqlite3')
if database.exists():
    with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as db:
        assert db.execute('select count(*) from modules where current is not null').fetchone()[0] == 0
for unit in ('kvn-v5-agent.service', 'kvn-v5-web.service', 'kvn-v5-gateway.service'):
    subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', unit], check=True, timeout=30)
assert not Path('/run/docker.sock').exists()
print('Изолированная VM: 1 vCPU, 1 ГБ, установленных модулей и Docker нет.', flush=True)
