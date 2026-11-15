"""Включение истории через настоящий RPC в учебной Debian VM."""

import json
import shlex
import time

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def call(lab, code):
    command = f"cd {INSTALLED}; runuser -u kvn-v5-web -- python3 -c " + shlex.quote(code)
    result = lab.run(command, check=False, timeout=80)
    if result.returncode:
        raise RuntimeError("Учебный RPC не выполнен: " + result.stderr.decode("utf-8", "replace")[-1000:])
    return json.loads(result.stdout)


def lifecycle(lab, operation):
    code = ("import json; from v5.core.lifecycle import LIFECYCLE_SOCKET; from v5.portal.rpc import LifecycleClient; "
            f"print(json.dumps(LifecycleClient(LIFECYCLE_SOCKET).{operation}))")
    return call(lab, code)


def history(lab):
    code = ("import json; from pathlib import Path; from v5.portal.rpc import HostClient; "
            "print(json.dumps(HostClient(Path('/run/kvn-v5-agent/control.sock')).observe_history(1)))")
    return call(lab, code)


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    stage_candidate(lab)
    lab.run(f"set -eu; for unit in kvn-v5-agent.service kvn-v5-observer.service kvn-v5-lifecycle@.service "
            f"kvn-v5-socket-observer.socket kvn-v5-socket-observer@.service; do "
            f"tar -xOf {STAGE}/candidate.tar.gz v5/install/systemd/$unit "
            "| sed \"s/@WEB_UID@/$(id -u kvn-v5-web)/g\" > /etc/systemd/system/$unit; done; "
            "systemctl daemon-reload; systemctl enable --now kvn-v5-socket-observer.socket; "
            "systemctl restart kvn-v5-agent.service")
    lifecycle(lab, "history_configure(False)")
    assert lifecycle(lab, "history_status()") == {"enabled": False, "active": False}
    assert history(lab)["captured_count"] == 0
    try:
        assert lifecycle(lab, "history_configure(True)") == {"enabled": True, "active": True}
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and history(lab)["captured_count"] < 1:
            time.sleep(3)
        assert history(lab)["captured_count"] >= 1
        print("История: включение через RPC и сохранение снимка проверены.", flush=True)
    finally:
        assert lifecycle(lab, "history_configure(False)") == {"enabled": False, "active": False}
    assert history(lab)["captured_count"] == 0
    lab.run("test ! -e /var/lib/kvn-v5/observability/history.sqlite3")
    print("История: сборщик остановлен, собственная база удалена.", flush=True)


if __name__ == "__main__":
    main()
