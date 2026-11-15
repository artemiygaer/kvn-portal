"""Подготовить и проверить два MTProto-модуля на изолированном Debian."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT, call
from tests.v5.test_packages import new_key
from tests.v5.tunnel_lab_e2e import wait_guest
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build

BASE = "/var/tmp/kvn-v5-phase9"
CLIENT = "/var/tmp/kvn-v5-mtproto-client"
FIXTURES = Path(__file__).with_name("fixtures")
REVISION = "80224c93c47242575107c83eb603d675e49226e8"
SOURCE = ROOT / "mtproxychecker-src"
IMAGES = {
    "telemt": ("3.5.17", "b2054b7b179b23e8ec3f90ad2bf69781879519860383b938260ee8d47291f014"),
    "mtg": ("2.3.0", "15028cdbe0b8561d319ebf63b5827f85c8dd2e48d3eba7e7e7df161db69d99e9"),
}


def stage(lab, archive, image_dir):
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.run(f"install -d -m 0700 {BASE}; test ! -e {BASE}/fixture; test ! -e {CLIENT}")
    lab.upload(archive, f"{BASE}/candidate.tar.gz")
    lab.run(f"set -eu; umask 077; cd {BASE}; sha256sum --check --strict; "
            'stage=$(mktemp -d candidate.XXXXXX); tar -xzf candidate.tar.gz -C "$stage"; '
            'cp -a "$stage"/v5/core/. /usr/local/lib/kvn-v5/v5/core/; '
            'cp -a "$stage"/v5/modules/. /usr/local/lib/kvn-v5/v5/modules/; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type d -exec chmod 0755 {} +; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type f -exec chmod 0644 {} +; '
            'for unit in kvn-v5-module-telemt.service kvn-v5-module-mtg.service; do '
            'install -m 0644 "$stage/v5/install/systemd/$unit" /etc/systemd/system/; '
            'systemd-analyze verify "/etc/systemd/system/$unit"; done; systemctl daemon-reload',
            data=f"{digest}  candidate.tar.gz\n".encode(), timeout=300)
    print(f"Debian {lab.port}: SHA-256 ядра {digest}; unit установлены выключенными.", flush=True)
    with TemporaryDirectory(dir=ROOT, prefix="phase9-signed-") as folder:
        root = Path(folder)
        key = root / "signer.pem"
        publisher = new_key(key)
        pin = root / "publisher.json"
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        lab.upload(pin, f"{BASE}/publisher.json")
        now = datetime.now(timezone.utc)
        for module, (version, image_digest) in IMAGES.items():
            package = root / f"kvn-module-{module}-{version}.tar.gz"
            image = image_dir / f"{module}-{version}-amd64-verified.tar"
            checksum = build(package, key, module_id=module, version=version, image_digest=image_digest, image=image,
                             issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                             expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            lab.upload(package, f"{BASE}/{package.name}")
            lab.run(f"cd {BASE}; sha256sum --check --strict",
                    data=f"{checksum}  {package.name}\n".encode(), timeout=180)
            print(f"{module}: подписанный offline пакет SHA-256 {checksum}.", flush=True)
        client = root / "client.tar"
        with client.open("wb") as output:
            subprocess.run(["git", "-C", str(SOURCE), "archive", "--format=tar", REVISION, "mtproxy_checker"],
                           stdout=output, check=True, timeout=30)
        client_digest = hashlib.sha256(client.read_bytes()).hexdigest()
        lab.upload(client, f"{BASE}/client.tar")
        lab.run(f"set -eu; cd {BASE}; sha256sum --check --strict; install -d -m 0755 {CLIENT}; "
                f"tar -xf client.tar -C {CLIENT}; find {CLIENT} -type d -exec chmod 0755 {{}} +; "
                f"find {CLIENT} -type f -exec chmod 0644 {{}} +; python3 -c 'import cryptography'",
                data=f"{client_digest}  client.tar\n".encode(), timeout=120)
    for name in ("check_tls_gateway.py", "check_network_gateway.py", "check_network_nft.py",
                 "check_mtproto_client.py", "check_mtproto_vm.py"):
        lab.upload(FIXTURES / name, f"{BASE}/{name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", choices=(22058, 22059), type=int)
    parser.add_argument("archive", type=Path, nargs="?")
    parser.add_argument("--image-dir", type=Path, default=Path("/var/tmp/kvn-v5-regctl"))
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--after-reboot", action="store_true")
    parser.add_argument("--archive-failed", action="store_true")
    parser.add_argument("--diagnose-mtg", action="store_true")
    parser.add_argument("--doctor-mtg", action="store_true")
    parser.add_argument("--diagnose-mtg-ipv4", action="store_true")
    args = parser.parse_args()
    lab = Lab(args.port, ROOT)
    wait_guest(lab)
    if args.diagnose_mtg_ipv4:
        lab.upload(FIXTURES / "check_mtproto_vm.py", f"{BASE}/check_mtproto_vm.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py diagnose-mtg-ipv4", 600)
        return
    if args.doctor_mtg:
        lab.upload(FIXTURES / "check_mtproto_vm.py", f"{BASE}/check_mtproto_vm.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py doctor-mtg", 300)
        return
    if args.diagnose_mtg:
        for name in ("check_mtproto_client.py", "check_mtproto_vm.py"):
            lab.upload(FIXTURES / name, f"{BASE}/{name}")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py diagnose-mtg", 300)
        return
    if args.archive_failed:
        lab.upload(FIXTURES / "check_mtproto_vm.py", f"{BASE}/check_mtproto_vm.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py archive-failed", 300)
        return
    if args.after_reboot:
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py after-reboot", 800)
        return
    if args.archive is None:
        parser.error("Нужен архив ядра")
    stage(lab, args.archive, args.image_dir)
    if args.prepare_only:
        return
    call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py initial", 1200)
    lab.reboot()
    call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_mtproto_vm.py after-reboot", 800)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        if exc.stderr:
            print(exc.stderr.decode(errors="replace"), end="")
        raise SystemExit(exc.returncode)
