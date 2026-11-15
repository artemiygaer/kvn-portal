"""Обновить шаблон чистой учебной VM до состояния новой установки."""

import json
from pathlib import Path
import subprocess

from v5.core.tls.gateway import render_gateway
from v5.core.tls.identity import TLSIdentity

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
assert json.loads(Path('/root/portal/modules.json').read_text())['installed'] == []
config = Path('/etc/kvn-v5/gateway/nginx.conf')
state = json.loads(Path('/etc/kvn-v5/gateway/identities.json').read_text())
identities = [TLSIdentity(state['ip'], True), *(TLSIdentity(name, False) for name in state['names'])]
previous = config.read_bytes()
try:
    config.write_text(render_gateway(identities, ipv6=state['ipv6']))
    subprocess.run(['/usr/sbin/nginx', '-t', '-c', str(config)], check=True, capture_output=True)
    subprocess.run(['systemctl', 'reload', 'kvn-v5-gateway.service'], check=True, capture_output=True)
except Exception:
    config.write_bytes(previous)
    raise
