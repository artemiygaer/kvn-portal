"""Поднять копию панели v4.2 только в отдельном Debian-стенде WSL."""

from pathlib import Path
import subprocess
import time

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT

FIXTURE = Path(__file__).parent / "fixtures/prepare_v42_ui_vm.py"


def main():
    lab = Lab(22052, ROOT)
    known = Path(__file__).resolve().parents[2] / "output/v5-lab/known_hosts_wsl"
    lab.ssh[lab.ssh.index("StrictHostKeyChecking=accept-new")] = "StrictHostKeyChecking=yes"
    index = next(i for i, item in enumerate(lab.ssh) if item.startswith("UserKnownHostsFile="))
    lab.ssh[index] = f"UserKnownHostsFile={known}"
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        result = lab.run("cat /var/lib/cloud/data/instance-id; hostname", check=False, timeout=35)
        if result.returncode == 0:
            assert result.stdout.splitlines() == [b"kvn-v5-isolated-001", b"kvn-v5-isolated"]
            break
        time.sleep(4)
    else:
        raise RuntimeError("Учебная копия v4.2 не ответила")
    lab.upload(FIXTURE, "/var/tmp/kvn-v5-prepare-v42-ui.py")
    lab.run("set -eu; test -f /home/kvnlab/v42/VERSION; python3 /var/tmp/kvn-v5-prepare-v42-ui.py; "
            "systemctl start docker.service kvn-portal-agent.service; cd /home/kvnlab/v42; "
            "docker-compose up -d --no-build portal portal-gateway nginx",
            data=b"overview-lab-only-fixture\n", timeout=180, capture=False)
    print("Учебная v4.2 подготовлена в отдельном overlay.", flush=True)
    command = [*lab.ssh, "-N", "-o", "ExitOnForwardFailure=yes",
               "-L", "127.0.0.1:18443:127.0.0.1:8443", lab.host]
    raise SystemExit(subprocess.call(command))


if __name__ == "__main__":
    main()
