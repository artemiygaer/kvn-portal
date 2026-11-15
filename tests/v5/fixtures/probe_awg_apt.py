"""Проверить изолированный индекс и симуляцию AWG только на учебной VM."""

import os
from pathlib import Path
import subprocess

from v5.core.packages.awg_repository import PPA_KEY, commands, preferences, sources
from v5.core.packages.debian_provision import apt_commands, apt_stage, parse_os_release

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
system = parse_os_release(Path('/etc/os-release').read_text())
with apt_stage(system) as stage:
    (stage / 'amnezia-ppa.asc').write_bytes(PPA_KEY)
    (stage / 'amnezia-ppa.asc').chmod(0o644)
    (stage / 'sources.list').write_text(sources(system, stage), encoding='ascii')
    (stage / 'preferences').write_text(preferences(), encoding='ascii')
    (stage / 'preferences').chmod(0o644)
    update, _ = apt_commands(stage, ('wireguard-tools',))
    update = tuple(f'Dir::Etc::preferences={stage}/preferences' if item == 'Dir::Etc::preferences=-' else item
                   for item in update)
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive',
           'APT_CONFIG': str(stage / 'apt.conf')}
    subprocess.run(update, check=True, stdin=subprocess.DEVNULL, timeout=600, env=env)
    simulate = commands(stage, os.uname().release)[1]
    result = subprocess.run(simulate, check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=300, env=env)
    print('Симуляция APT:', result.returncode, flush=True)
    print(result.stdout.decode('utf-8', 'replace')[-5000:], flush=True)
    print(result.stderr.decode('utf-8', 'replace')[-1000:], flush=True)
    if result.returncode:
        raise SystemExit(result.returncode)
    assert b'ppa.launchpadcontent.net' not in result.stderr
    print('Подпись репозитория и симуляция установки проверены; пакеты не изменялись.', flush=True)
