"""Вернуть учебную VM к исходной версии и удалить только записи этого теста."""

from pathlib import Path
import pwd

from v5.core.maintenance.core_update import CoreUpdate
from v5.core.maintenance.portal_store import PortalUpdateStore

assert Path('/var/lib/cloud/data/instance-id').read_text().strip() == 'kvn-v5-isolated-001'
assert Path('/etc/hostname').read_text().strip() == 'kvn-v5-isolated'
updater = CoreUpdate()
assert not updater.pending.exists()
if updater.previous.exists():
    assert (updater.live / 'core-version').read_text().strip() == '5.0.1'
    updater.recover(previous=True)
assert not (updater.live / 'core-version').exists()
store = PortalUpdateStore(pwd.getpwnam('kvn-v5-web').pw_uid)
for record in store.records():
    assert record['version'] == '5.0.1' and record['status'] == 'failed'
    store.discard(record['ticket'])
print('Учебная VM возвращена к исходной версии; записи теста удалены.', flush=True)
