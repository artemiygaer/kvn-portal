"""Подготовить только изолированный Debian для браузерного E2E консоли."""

import argparse
from pathlib import Path
import shlex
import subprocess
from tempfile import TemporaryDirectory
import time

from tests.v5.audit_lab_e2e import stage_candidate
from tests.v5.console_gateway_lab_e2e import STAGE, UNITS
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT

STATE = ROOT / "console-browser-state.json"
CA = ROOT / "console-browser-ca.pem"
FIXTURE = Path(__file__).parent / "fixtures/check_console_browser_vm.py"
SOCKETS = ("kvn-v5-console-web.socket", "kvn-v5-console-agent.socket")
SERVICES = ("kvn-v5-console-web.service", "kvn-v5-console-agent.service")
PROBE = f"cd /usr/local/lib/kvn-v5 && PYTHONPATH=. python3 {STAGE}/{FIXTURE.name}"


def prepare(lab):
    units = shlex.join(UNITS)
    lab.run("set -eu; "
            "if ! /usr/bin/python3 -c 'import websockets' 2>/dev/null || ! command -v mc || ! command -v htop; then "
            "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=15 "
            "install -y --no-install-recommends python3-websockets mc htop; fi",
            timeout=180, capture=False)
    stage_candidate(lab)
    lab.upload(FIXTURE, f"{STAGE}/{FIXTURE.name}")
    lab.run(f"set -eu; cd {STAGE}; "
            "test -f nginx.conf; "
            "if grep -Eq '^# kvn-v5-(tls-index|network)' /etc/kvn-v5/gateway/nginx.conf; then exit 1; fi; "
            f"for name in {units}; do install -m 0644 -- \"$name\" /etc/systemd/system/; done; "
            "test -f nginx.original || cp -p /etc/kvn-v5/gateway/nginx.conf nginx.original; "
            f"/usr/sbin/nginx -t -c {STAGE}/nginx.conf; "
            "install -m 0600 nginx.conf /etc/kvn-v5/gateway/nginx.conf; "
            f"{PROBE} mount; systemctl daemon-reload; systemctl reload kvn-v5-gateway.service",
            timeout=120)
    stop(lab)
    lab.run(PROBE + " disabled", timeout=60, capture=False)
    from v5.core.private_files import write_private
    write_private(STATE, lab.run(PROBE + " cookie", timeout=60).stdout)
    write_private(CA, lab.run("cat /etc/kvn-v5/gateway/bootstrap.crt").stdout)
    print("Подготовлен выключенный стенд; cookie и CA сохранены в закрытом каталоге WSL.", flush=True)


def stop(lab):
    lab.run("systemctl stop " + SOCKETS[0], timeout=90)
    lab.run("set -eu; "
            "test ! -S /run/kvn-v5-console-web.sock; test ! -S /run/kvn-v5-console-agent.sock; "
            f"for unit in {shlex.join(SERVICES)}; do if systemctl is-active --quiet \"$unit\"; then exit 1; fi; done",
            timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "enable", "disable", "cleanup"))
    args = parser.parse_args()
    with TemporaryDirectory(dir=ROOT, prefix="console-browser-ssh-") as directory:
        lab = Lab(22062, ROOT)
        lab.ssh[1:1] = ["-o", "ControlMaster=auto", "-o", f"ControlPath={directory}/socket",
                        "-o", "ControlPersist=20s"]
        try:
            until = time.monotonic() + 240
            while time.monotonic() < until:
                result = lab.run("cat /var/lib/cloud/data/instance-id; hostname", timeout=40, check=False)
                if result.returncode == 0:
                    if result.stdout.splitlines() != [b"kvn-v5-isolated-001", b"kvn-v5-isolated"]:
                        raise RuntimeError("SSH ответил не выделенный учебный экземпляр")
                    break
                time.sleep(3)
            else:
                raise RuntimeError("Учебная VM не ответила по SSH")
            if args.action == "prepare":
                prepare(lab)
            elif args.action == "enable":
                lab.run(f"systemctl start {SOCKETS[0]} && test -S /run/kvn-v5-console-agent.sock")
                print("Консоль включена на учебной VM.", flush=True)
            elif args.action == "disable":
                stop(lab)
                lab.run(PROBE + " disabled", timeout=60, capture=False)
            else:
                stop(lab)
                lab.run(f"set -eu; {PROBE} cleanup; "
                        f"install -m 0600 {STAGE}/nginx.original /etc/kvn-v5/gateway/nginx.conf; "
                        "systemctl daemon-reload; systemctl reload kvn-v5-gateway.service",
                        timeout=90)
                STATE.unlink(missing_ok=True)
                CA.unlink(missing_ok=True)
        finally:
            if (Path(directory) / "socket").exists():
                subprocess.run([*lab.ssh, "-O", "exit", lab.host], check=False, timeout=8,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
