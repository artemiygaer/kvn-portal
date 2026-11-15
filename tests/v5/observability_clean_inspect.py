"""Безопасно определить стадию чистой установки после прерывания WSL."""

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    for path in ("/root/portal/install.json", "/etc/kvn-v5/web/config.json",
                 "/var/tmp/kvn-v5-phase2/v5/install/install.sh", "/var/tmp/kvn-v5-clean/installer.tar.gz"):
        result = lab.run("test -f " + path, check=False)
        print(path, "есть" if result.returncode == 0 else "нет", flush=True)
    for unit in ("kvn-v5-agent.service", "kvn-v5-observer.service"):
        result = lab.run("systemctl is-active " + unit, check=False)
        print(unit, result.stdout.decode("ascii", "replace").strip(), flush=True)
    result = lab.run("python3 -c \"import json; from pathlib import Path; "
                     "p=Path('/root/portal/install.json'); "
                     "print(json.loads(p.read_text()).get('status','unknown') if p.is_file() else 'absent')\"",
                     check=False)
    print("Состояние установки:", result.stdout.decode("ascii", "replace").strip() or "недоступно", flush=True)


if __name__ == "__main__":
    main()
