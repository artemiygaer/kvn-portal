"""Проверить строгий fallback who на SSH с TTY в изолированной VM."""

import json
import argparse
import shlex
import subprocess
import time

from tests.v5.audit_lab_e2e import INSTALLED, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared", action="store_true", help="Использовать уже проверенный кандидат в VM")
    args = parser.parse_args()
    lab = Lab(22062, ROOT)
    lab.wait()
    if not args.prepared:
        stage_candidate(lab)
    code = ("import json\nfrom v5.core.observability.live import Observer\n"
            "def failed(): raise OSError('fixture')\n"
            "print(json.dumps(Observer(session_source=failed).snapshot()))")
    command = f"cd {INSTALLED}; python3 -c " + shlex.quote(code)
    with subprocess.Popen([*lab.ssh, "-tt", lab.host, "sleep 120"], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as connection:
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                result = lab.run(command, timeout=40)
                data = json.loads(result.stdout)
                if data["ssh_partial"] and any(row["user"] == "kvnlab" and row["port"] is not None
                                               for row in data["ssh"]):
                    print("Fallback who: SSH с TTY и TCP-сокетом подтверждён; результат помечен неполным.", flush=True)
                    return
                if connection.poll() is not None:
                    raise RuntimeError("Тестовая SSH-сессия завершилась")
                time.sleep(3)
            who = lab.run("who", check=False, timeout=30)
            lines = who.stdout.decode("utf-8", "replace").splitlines()
            raise RuntimeError(f"Fallback не подтвердил учебную SSH-сессию: who_exit={who.returncode}, "
                               f"who_lines={len(lines)}, ssh_partial={data['ssh_partial']}, "
                               f"tcp_partial={data['tcp_partial']}")
        finally:
            connection.terminate()
            connection.wait(timeout=10)


if __name__ == "__main__":
    main()
