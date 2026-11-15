"""Повторно проверить результат установки AWG в изолированной учебной VM."""

from pathlib import Path
import subprocess

from v5.modules.host_tunnel.config import AWG
from v5.modules.host_tunnel.platform import capability

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
host = capability(AWG)
assert host.issue is None and '3.1' in host.profiles
assert not Path('/sys/class/net/awg0').exists()
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('ABI AWG 3.1 проверен; awg0 выключен, портал и шлюз активны.', flush=True)
