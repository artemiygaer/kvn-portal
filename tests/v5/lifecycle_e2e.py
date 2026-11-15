"""Живой systemd lifecycle, reboot и пакеты на выделенной Debian VM в WSL."""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import tempfile

from tests.v5.debian_core_e2e import Lab
from tests.v5.network_gateway_e2e import DIRECTORY, upload_candidate
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build


def upload_packages(lab):
    with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="kvn-v5-lifecycle-") as folder:
        root = Path(folder)
        key = root / "fixture.pem"
        publisher = new_key(key)
        pin = root / "lifecycle-publisher.json"
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        lab.upload(pin, f"{DIRECTORY}/{pin.name}")
        now = datetime.now(timezone.utc)
        for version in ("1.0.0", "1.0.1"):
            package = root / f"lifecycle-{version}.tar.gz"
            build(package, key, module_id="wireguard", version=version,
                  issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            lab.upload(package, f"{DIRECTORY}/{package.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()
    lab = Lab(22058, Path("/var/tmp/kvn-v5-lab"))
    lab.wait()
    stage = upload_candidate(lab, args.archive, "lifecycle")
    for name in ("check_tls_gateway.py", "check_network_gateway.py", "check_network_nft.py", "check_lifecycle_vm.py"):
        lab.upload(Path(__file__).with_name("fixtures") / name, f"{DIRECTORY}/{name}")
    upload_packages(lab)
    for phase in ("initial", "after-reboot"):
        if phase == "after-reboot":
            lab.reboot()
        result = lab.run(f"PYTHONPATH={stage} python3 -u {DIRECTORY}/check_lifecycle_vm.py {phase}",
                         timeout=540, check=False)
        print(result.stdout.decode(), end="", flush=True)
        if result.returncode:
            print(result.stderr.decode(), file=sys.stderr, end="")
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode(errors="replace"), file=sys.stderr, end="")
        raise SystemExit(exc.returncode)
