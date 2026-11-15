"""Реальная установка двух зависимостей только в учебной Debian VM."""

import importlib.util
from pathlib import Path
import subprocess
import sys

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
assert Path('/etc/hostname').read_text().strip() == 'kvn-v5-isolated'
assert not Path('/usr/bin/wg').exists(), 'Нужен стенд без wireguard-tools'
spec = importlib.util.spec_from_file_location('kvn_apt_probe', '/root/kvn-apt-probe.py')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
system = module.parse_os_release(Path('/etc/os-release').read_text())
apt_lists = Path('/var/lib/apt/lists')


def inventory():
    return sorted((entry.name, entry.stat().st_mtime_ns, entry.stat().st_size)
                  for entry in apt_lists.iterdir() if entry.is_file())


before = inventory()
module.run_apt_transaction(system, ('wireguard-tools', 'nftables'))
assert Path('/usr/bin/wg').is_file()
assert Path('/usr/sbin/nft').is_file()
assert inventory() == before
subprocess.run(['systemctl', 'is-active', '--quiet', 'kvn-v5-agent', 'kvn-v5-web', 'kvn-v5-gateway'], check=True)
print('Debian', system.version, ': wireguard-tools и nftables установлены, APT-индексы и службы портала сохранены.', flush=True)
