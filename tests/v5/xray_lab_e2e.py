"""Подготовить подписанные Xray-пакеты и проверить модуль на выделенной Debian VM."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

from tests.v5.debian_core_e2e import Lab
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build

BASE = "/var/tmp/kvn-v5-phase6"
DIGEST = "db94b52238af7311f30044a1ef64e77b0edf285a302c276a7f4d7b368e6a17ab"
FIXTURES = Path(__file__).with_name("fixtures")


def stage_core(lab, archive):
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.upload(archive, f"{BASE}/candidate.tar.gz")
    lab.run(f"set -eu; umask 077; cd {BASE}; sha256sum --check --strict; "
            'stage=$(mktemp -d candidate.XXXXXX); tar -xzf candidate.tar.gz -C "$stage"; '
            'cp -a "$stage"/v5/core/. /usr/local/lib/kvn-v5/v5/core/; '
            'install -d -m 0755 /usr/local/lib/kvn-v5/v5/modules; '
            'cp -a "$stage"/v5/modules/. /usr/local/lib/kvn-v5/v5/modules/; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type d -exec chmod 0755 {} +; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type f -exec chmod 0644 {} +; '
            'install -m 0644 "$stage"/v5/install/systemd/kvn-v5-module-xray.service /etc/systemd/system/; '
            'systemd-analyze verify /etc/systemd/system/kvn-v5-module-xray.service; systemctl daemon-reload',
            data=f"{digest}  candidate.tar.gz\n".encode(), timeout=120)
    print(f"Debian: SHA-256 ядра {digest}, адаптер и неактивный unit подготовлены", flush=True)


def stage_packages(lab, image):
    with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="kvn-v5-xray-signed-") as folder:
        root = Path(folder)
        key = root / "signer.pem"
        publisher = new_key(key)
        pin = root / "publisher.json"
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        lab.upload(pin, f"{BASE}/publisher.json")
        now = datetime.now(timezone.utc)
        for version, offline in (("26.10.31", True), ("26.10.32", False)):
            name = f"kvn-module-xray-{version}.tar.gz"
            package = root / name
            sha = build(package, key, module_id="xray", version=version, image_digest=DIGEST,
                        image=image if offline else None,
                        issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            lab.run(f"umask 077; cat > {BASE}/{name}", data=package.read_bytes(), timeout=420)
            lab.run(f"cd {BASE}; sha256sum --check --strict",
                    data=f"{sha}  {name}\n".encode(), timeout=120)
            print(f"Подписанный пакет {version}: SHA-256 {sha}, проверен в Debian", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--image", type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args()
    lab = Lab(22058, Path("/var/tmp/kvn-v5-lab"))
    lab.wait()
    lab.run(f"install -d -m 0700 {BASE}")
    stage_core(lab, args.archive)
    if args.image:
        stage_packages(lab, args.image)
    if args.prepare_only:
        return
    for name in ("check_tls_gateway.py", "check_network_gateway.py", "check_network_nft.py", "check_xray_vm.py"):
        lab.upload(FIXTURES / name, f"{BASE}/{name}")
    remote = f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_xray_vm.py"
    result = subprocess.run([*lab.ssh, lab.host, "sudo -n bash -c " + shlex.quote(remote)],
                            timeout=720, check=False)
    if result.returncode:
        journal = lab.run("journalctl -u kvn-v5-module-xray.service -n 16 --no-pager", check=False)
        print(journal.stdout.decode(), file=sys.stderr, end="")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode(errors="replace"), file=sys.stderr, end="")
        raise SystemExit(exc.returncode)
