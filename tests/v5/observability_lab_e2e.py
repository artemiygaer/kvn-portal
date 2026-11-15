"""Проверка SSH и процессов только на выделенном Debian/QEMU внутри WSL."""

import json
import shlex
import subprocess
import time

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def snapshot(lab, session=None):
    code = ("import json; from pathlib import Path; from v5.portal.rpc import HostClient; "
            "print(json.dumps(HostClient(Path('/run/kvn-v5-agent/control.sock')).observe_live(" +
            repr(session) + ")))" )
    command = f"cd {INSTALLED}; runuser -u kvn-v5-web -- python3 -c " + shlex.quote(code)
    return json.loads(lab.run(command, timeout=30).stdout)


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    print("Подтверждена изолированная учебная VM.", flush=True)
    stage_candidate(lab)
    lab.run(f"set -eu; for unit in kvn-v5-agent.service kvn-v5-socket-observer.socket "
            f"kvn-v5-socket-observer@.service; do tar -xOf {STAGE}/candidate.tar.gz v5/install/systemd/$unit "
            "| sed \"s/@WEB_UID@/$(id -u kvn-v5-web)/g\" > /etc/systemd/system/$unit; done; "
            "systemctl daemon-reload; systemctl enable --now kvn-v5-socket-observer.socket; "
            "systemctl restart kvn-v5-agent.service")
    with subprocess.Popen([*lab.ssh, "-tt", lab.host, "exec cat"], stdin=subprocess.PIPE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as connection:
        try:
            connection.stdin.write(b"fixture-start\n")
            connection.stdin.flush()
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                live = snapshot(lab)
                for row in live["ssh"]:
                    if row["user"] != "kvnlab":
                        continue
                    filtered = snapshot(lab, row["id"])
                    if filtered["session_filter_confirmed"] and any(
                            proc["name"] == "cat" for proc in filtered["processes"]):
                        assert row["ip"] and row["started_at"]
                        print("SSH: подтверждены пользователь, адрес, время и дочерний процесс cat.", flush=True)
                        assert row["rx_bytes"] is not None and row["tx_bytes"] is not None, "Нет TCP-счётчиков"
                        connection.stdin.write(b"fixture-bidirectional-traffic\n" * 100)
                        connection.stdin.flush()
                        time.sleep(4)
                        later = snapshot(lab)
                        current = next(item for item in later["ssh"] if item["id"] == row["id"])
                        assert current["rx_bytes"] is not None and current["tx_bytes"] is not None, \
                            f"TCP источник неполон: {later['tcp_partial']}"
                        assert current["rx_bytes"] > row["rx_bytes"] and current["tx_bytes"] > row["tx_bytes"]
                        assert current["rx_per_second"] is not None and current["tx_per_second"] is not None
                        print("TCP-счётчики и скорости RX/TX: подтверждён рост при двусторонней передаче.", flush=True)
                        return
                if connection.poll() is not None:
                    raise RuntimeError("Учебная SSH-сессия завершилась раньше проверки")
                time.sleep(3)
            raise RuntimeError("SSH-сессия или её процесс не отобразились")
        finally:
            connection.terminate()
            connection.wait(timeout=10)


if __name__ == "__main__":
    main()
