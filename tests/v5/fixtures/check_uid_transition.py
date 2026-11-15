"""Проверка перехода на UID web внутри учебной systemd-службы."""

from pathlib import Path
import pwd
import subprocess
import traceback

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
web = pwd.getpwnam('kvn-v5-web')
try:
    subprocess.run(['/usr/bin/true'], check=True, cwd='/usr/local/lib/kvn-v5',
                   user=web.pw_uid, group=web.pw_gid, extra_groups=())
    print('Переход на UID web успешен', flush=True)
except PermissionError as exc:
    print('Переход запрещён: errno', exc.errno, flush=True)
    for frame in traceback.extract_tb(exc.__traceback__):
        print(Path(frame.filename).name, frame.name, frame.lineno, flush=True)
