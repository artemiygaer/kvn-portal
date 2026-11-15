"""nginx и systemd проверяют консольные конфиги только в учебном Debian."""

from pathlib import Path
import shlex
import subprocess
from tempfile import TemporaryDirectory
import time

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT
from v5.core.console import AGENT_UNIT, SOCKET_UNIT, WEB_SOCKET_UNIT, WEB_UNIT
from v5.core.tls.gateway import render_gateway
from v5.core.tls.identity import TLSIdentity

UNITS = (SOCKET_UNIT, AGENT_UNIT, WEB_SOCKET_UNIT, WEB_UNIT)
SOURCE = Path(__file__).resolve().parents[2] / "v5/install/systemd"
STAGE = "/var/tmp/kvn-v5-console-config"


def verify(lab):
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        result = lab.run("cat /var/lib/cloud/data/instance-id; hostname", timeout=40, check=False)
        if result.returncode == 0:
            if result.stdout.splitlines() != [b"kvn-v5-isolated-001", b"kvn-v5-isolated"]:
                raise RuntimeError("SSH ответил не учебный экземпляр")
            break
        time.sleep(4)
    else:
        raise RuntimeError("Учебный Debian не ответил по SSH")
    print("SSH: подтверждён Debian-стенд 22062.", flush=True)
    lab.run(f"install -d -m 0700 {STAGE}")
    uid = lab.run("id -u kvn-v5-web").stdout.strip()
    if not uid.isdigit():
        raise ValueError("Нет системного пользователя учебной панели")
    with TemporaryDirectory(dir=ROOT, prefix="console-nginx-") as directory:
        root = Path(directory)
        config = root / "nginx.conf"
        config.write_text(render_gateway((TLSIdentity("192.0.2.8", True), TLSIdentity("portal.example", False)),
                                         ipv6=False), encoding="utf-8")
        lab.upload(config, f"{STAGE}/nginx.conf")
        for unit in UNITS:
            local = root / unit
            local.write_bytes((SOURCE / unit).read_bytes().replace(b"@WEB_UID@", uid))
            lab.upload(local, f"{STAGE}/{unit}")
    paths = shlex.join(tuple(f"{STAGE}/{name}" for name in UNITS))
    lab.run(f"set -eu; /usr/sbin/nginx -t -c {STAGE}/nginx.conf; /usr/bin/systemd-analyze verify {paths}",
            timeout=100, capture=False)
    print("Debian 13: nginx -t и systemd-analyze verify приняли консольные конфиги; рабочие службы не изменены.")


def main():
    with TemporaryDirectory(dir=ROOT, prefix="console-ssh-") as directory:
        lab = Lab(22062, ROOT)
        lab.ssh[1:1] = ["-o", "ControlMaster=auto", "-o", f"ControlPath={directory}/socket",
                        "-o", "ControlPersist=20s"]
        try:
            verify(lab)
        finally:
            if (Path(directory) / "socket").exists():
                subprocess.run([*lab.ssh, "-O", "exit", lab.host], check=False, timeout=8,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
