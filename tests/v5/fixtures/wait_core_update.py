"""Дождаться подтверждённого завершения, а не только записи номера версии."""

import json
from pathlib import Path
import subprocess
import sys
import time

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
deadline = time.monotonic() + 600
version = sys.argv[1] if len(sys.argv) > 1 else '5.0.1'
expected = sys.argv[2] if len(sys.argv) > 2 else 'applied'
installed = sys.argv[3] if len(sys.argv) > 3 else version
assert expected in ('applied', 'failed')
while time.monotonic() < deadline:
    records = list(Path('/var/lib/kvn-v5/core-updates').glob('*/state.json'))
    states = [json.loads(path.read_text()) for path in records]
    current = sorted((item for item in states if item['version'] == version),
                     key=lambda item: item['created'], reverse=True)
    if current and current[0]['status'] == 'failed' and expected != 'failed':
        raise RuntimeError('Фоновое обновление завершилось ошибкой')
    if current and current[0]['status'] == expected:
        subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
        assert Path('/usr/local/lib/kvn-v5/core-version').read_text().strip() == installed
        assert not Path('/usr/local/lib/.kvn-v5-core/pending').exists()
        print(f'Состояние {expected} подтверждено; службы активны, версия {installed}.', flush=True)
        break
    time.sleep(3)
else:
    raise RuntimeError('Состояние applied не подтверждено за 10 минут')
