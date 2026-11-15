"""Проверка журнала на выделенном снимке Debian внутри WSL (22062)."""

from pathlib import Path
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.migration_lab_e2e import upload
from tests.v5.prepare_tunnel_lab import ROOT
from v5.tools.build_installer import build

STAGE = "/var/tmp/kvn-v5-phase12"
INSTALLED = "/usr/local/lib/kvn-v5"
FIXTURE = Path(__file__).with_name("fixtures") / "check_audit_vm.py"


def stage_candidate(lab):
    lab.run(f"test -f /root/portal/install.json && install -d -m 0700 {STAGE}")
    with TemporaryDirectory(dir=ROOT, prefix="phase12-audit-") as directory:
        candidate = Path(directory) / "candidate.tar.gz"
        build(candidate)
        print(f"Учебный Debian: SHA-256 кандидата {upload(lab, candidate, STAGE)}.", flush=True)
    lab.run(f"set -eu; cd {INSTALLED}; "
            f"tar -xzf {STAGE}/candidate.tar.gz --no-same-owner --no-same-permissions v5/core v5/portal; "
            "systemctl restart kvn-v5-agent.service kvn-v5-web.service")


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    stage_candidate(lab)
    lab.upload(FIXTURE, f"{STAGE}/{FIXTURE.name}")
    result = lab.run(f"cd {INSTALLED}; PYTHONPATH=. python3 -u {STAGE}/{FIXTURE.name}",
                     check=False, timeout=60, capture=False)
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
