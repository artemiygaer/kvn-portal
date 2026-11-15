"""Изолированная проверка только обновления временных APT-индексов."""

import importlib.util
from pathlib import Path
import subprocess
import sys

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
assert Path('/etc/hostname').read_text().strip() == 'kvn-v5-isolated'
spec = importlib.util.spec_from_file_location('kvn_apt_probe', '/root/kvn-apt-probe.py')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
system = module.parse_os_release(Path('/etc/os-release').read_text())


def inventory():
    root = Path('/var/lib/apt/lists')
    return sorted((entry.name, entry.stat().st_mtime_ns, entry.stat().st_size)
                  for entry in root.iterdir() if entry.is_file())


before = inventory()
with module.apt_stage(system) as stage:
    update, install = module.apt_commands(stage, ('wireguard-tools',))
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
           'DEBIAN_FRONTEND': 'noninteractive', 'APT_CONFIG': str(stage / 'apt.conf')}
    result = subprocess.run(update, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=300, check=False, env=env)
    if result.returncode:
        print('APT: ошибка обновления временных индексов, код', result.returncode, file=sys.stderr)
        print(result.stderr.decode('utf-8', 'replace')[-2000:], file=sys.stderr)
        raise SystemExit(1)
    if b'unsandboxed as root' in result.stderr:
        print('APT: загрузка не прошла под _apt', file=sys.stderr)
        raise SystemExit(1)
    assert any(path.is_file() and path.name.endswith('_InRelease') for path in (stage / 'lists').iterdir())
    simulated = subprocess.run((*install, '--simulate'), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=180, check=False,
                               env=env)
    if simulated.returncode:
        print('APT: симуляция установки завершилась с кодом', simulated.returncode, file=sys.stderr)
        print(simulated.stderr.decode('utf-8', 'replace')[-2000:], file=sys.stderr)
        raise SystemExit(1)
    assert b'Inst wireguard-tools ' in simulated.stdout
assert inventory() == before, 'Общие индексы APT были изменены'
print('Debian', system.version, ': индексы под _apt и симуляция установки проверены; общие индексы не изменены.', flush=True)
