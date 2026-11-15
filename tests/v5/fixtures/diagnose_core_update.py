"""Диагностика операции только в учебной VM, без вывода приватных данных."""

from pathlib import Path
import json
import pwd
import traceback

from v5.core.maintenance.core_update import CoreUpdate, UpdateError
from v5.core.packages.signature import load_publisher

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
records = list(Path('/var/lib/kvn-v5/core-updates').glob('*/state.json'))
records.sort(key=lambda path: json.loads(path.read_text())['created'], reverse=True)
try:
    updater = CoreUpdate()
    run = updater.system.run

    def checked_run(*args, **kwargs):
        try:
            return run(*args, **kwargs)
        except PermissionError as exc:
            print('Проверка прав: errno=', exc.errno, 'cwd=', kwargs.get('cwd') is not None,
                  'uid=', kwargs.get('user') is not None, 'filename=',
                  'python' if exc.filename == '/usr/bin/python3' else 'другое/нет', flush=True)
            raise

    updater.system.run = checked_run
    if updater.pending.exists():
        updater.recover()
    else:
        assert records
        updater.apply(records[0].parent / 'payload', load_publisher(Path('/etc/kvn-v5/core/publisher.json')),
                      pwd.getpwnam('kvn-v5-web').pw_uid)
    print('Тестовая операция успешна.')
except Exception as exc:
    while exc is not None:
        print(type(exc).__name__, str(exc) if isinstance(exc, UpdateError) else '', flush=True)
        if isinstance(exc, PermissionError):
            for frame in traceback.extract_tb(exc.__traceback__):
                print(Path(frame.filename).name, frame.name, frame.lineno, flush=True)
        exc = exc.__cause__
