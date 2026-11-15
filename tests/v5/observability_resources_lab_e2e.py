"""Оценить стоимость включённой истории в изолированной Debian VM."""

import time

from tests.v5.debian_core_e2e import Lab
from tests.v5.observability_history_lab_e2e import history, lifecycle
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    assert lifecycle(lab, "history_configure(False)") == {"enabled": False, "active": False}
    try:
        assert lifecycle(lab, "history_configure(True)") == {"enabled": True, "active": True}
        start = time.monotonic()
        while time.monotonic() - start < 75:
            time.sleep(5)
        data = history(lab)
        assert data["captured_count"] >= 2
        result = lab.run("systemctl show kvn-v5-observer.service -p MemoryCurrent -p CPUUsageNSec; "
                         "stat -c 'DatabaseBytes=%s' /var/lib/kvn-v5/observability/history.sqlite3")
        print("История: после двух снимков, учебная VM:", flush=True)
        print(result.stdout.decode("ascii"), end="", flush=True)
        print(f"ElapsedSeconds={time.monotonic() - start:.1f}", flush=True)
    finally:
        assert lifecycle(lab, "history_configure(False)") == {"enabled": False, "active": False}


if __name__ == "__main__":
    main()
