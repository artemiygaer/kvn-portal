"""Одноразовый SSH-сервер и root-сессия только на loopback учебной VM."""

import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time


def snapshot():
    code = ("import json; from pathlib import Path; from v5.portal.rpc import HostClient; "
            "print(json.dumps(HostClient(Path('/run/kvn-v5-agent/control.sock')).observe_live()))")
    result = subprocess.run(["/usr/sbin/runuser", "-u", "kvn-v5-web", "--", "/usr/bin/python3", "-c", code],
                            check=True, capture_output=True, timeout=20, cwd="/usr/local/lib/kvn-v5")
    return json.loads(result.stdout)


def main():
    if os.geteuid() != 0 or Path("/var/lib/cloud/data/instance-id").read_text().strip() != "kvn-v5-isolated-001":
        raise RuntimeError("Допускается только изолированная учебная VM")
    with TemporaryDirectory(prefix="kvn-v5-ipv6-", dir="/var/tmp") as temporary:
        root = Path(temporary)
        key = root / "key"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, check=True)
        authorized = root / "authorized_keys"
        authorized.write_bytes(key.with_suffix(".pub").read_bytes())
        authorized.chmod(0o600)
        config = root / "sshd_config"
        config.write_text("\n".join(("Port 22222", "ListenAddress ::1", "AddressFamily inet6",
                                    "HostKey /etc/ssh/ssh_host_ed25519_key", f"PidFile {root / 'sshd.pid'}",
                                    f"AuthorizedKeysFile {authorized}", "PermitRootLogin yes", "UsePAM yes",
                                    "PubkeyAuthentication yes", "PasswordAuthentication no", "UseDNS no",
                                    "StrictModes no")) + "\n")
        unit = "kvn-v5-lab-ipv6-sshd.service"
        existing = subprocess.run(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"],
                                  capture_output=True, text=True, check=True, timeout=15)
        if existing.stdout.strip() != "not-found":
            raise RuntimeError("Имя учебной службы занято")
        subprocess.run(["/usr/bin/systemd-run", "--unit", unit, "--collect", "--property=RuntimeMaxSec=150",
                        "/usr/sbin/sshd", "-D", "-e", "-f", str(config)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=30)
        try:
                time.sleep(2)
                command = ["/usr/bin/ssh", "-6", "-tt", "-i", str(key), "-p", "22222", "-o", "BatchMode=yes",
                           "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o",
                           "UserKnownHostsFile=/dev/null", "root@::1", "sleep 120"]
                with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL) as client:
                    try:
                        deadline = time.monotonic() + 45
                        while time.monotonic() < deadline:
                            data = snapshot()
                            if any(row["user"] == "root" and row["ip"] == "::1" and row["port"] is not None
                                   for row in data["ssh"]):
                                print("IPv6: подтверждена root SSH-сессия с реальным TCP-портом.", flush=True)
                                return
                            active = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", unit],
                                                    stdin=subprocess.DEVNULL, check=False, timeout=10)
                            if client.poll() is not None or active.returncode:
                                raise RuntimeError("Учебный SSH завершился до проверки")
                            time.sleep(3)
                        roots = [row for row in data["ssh"] if row["user"] == "root"]
                        raise RuntimeError(f"Не найдена сессия IPv6 root: root={len(roots)}, "
                                           f"ipv6={sum(row['ip'] == '::1' for row in roots)}, "
                                           f"port={sum(row['port'] is not None for row in roots)}, "
                                           f"ssh_partial={data['ssh_partial']}, tcp_partial={data['tcp_partial']}")
                    finally:
                        client.terminate()
                        client.wait(timeout=10)
        finally:
            subprocess.run(["/usr/bin/systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30)


if __name__ == "__main__":
    main()
