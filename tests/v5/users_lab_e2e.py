"""Развернуть сценарий выдачи и отзыва только на изолированном Debian 13."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.hysteria_lab_e2e import DIGEST as HY_DIGEST, IMAGE as HY_IMAGE, VERSION as HY_VERSION
from tests.v5.prepare_tunnel_lab import ROOT, call
from tests.v5.test_packages import new_key
from tests.v5.xray_lab_e2e import DIGEST as XRAY_DIGEST
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build

BASE = "/var/tmp/kvn-v5-phase10"
FIXTURES = Path(__file__).with_name("fixtures")
MODULES = (("xray", "26.10.31", XRAY_DIGEST), ("hysteria", HY_VERSION, HY_DIGEST))
XRAY_IMAGE = f"ghcr.io/xtls/xray-core@sha256:{XRAY_DIGEST}"


def stage(lab, archive):
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.run(f"set -eu; install -d -m 0700 {BASE}; test ! -e {BASE}/started; "
            "test ! -e /var/lib/kvn-v5/packages/registry.sqlite3; "
            "test ! -e /var/lib/kvn-v5/modules/xray; test ! -e /var/lib/kvn-v5/modules/hysteria; "
            "test ! -e /etc/kvn-v5/packages/publisher.json; systemctl is-active docker.service")
    lab.upload(archive, f"{BASE}/candidate.tar.gz")
    lab.run(f"set -eu; umask 077; cd {BASE}; sha256sum --check --strict; "
            'stage=$(mktemp -d candidate.XXXXXX); tar -xzf candidate.tar.gz -C "$stage"; '
            'for part in core modules portal; do cp -a "$stage/v5/$part/." "/usr/local/lib/kvn-v5/v5/$part/"; '
            'find "/usr/local/lib/kvn-v5/v5/$part" -type d -exec chmod 0755 {} +; '
            'find "/usr/local/lib/kvn-v5/v5/$part" -type f -exec chmod 0644 {} +; done; '
            'for unit in kvn-v5-lifecycle.socket kvn-v5-lifecycle@.service kvn-v5-reconcile.service kvn-v5-module-tls-sync.service '
            'kvn-v5-module-xray.service kvn-v5-module-hysteria.service; do '
            'sed "s/@WEB_UID@/$(id -u kvn-v5-web)/g" "$stage/v5/install/systemd/$unit" > "/etc/systemd/system/$unit"; '
            'chmod 0644 "/etc/systemd/system/$unit"; done; '
            'install -d -m 0700 /var/lib/kvn-v5/users; '
            'systemd-analyze verify kvn-v5-lifecycle.socket kvn-v5-lifecycle@.service kvn-v5-reconcile.service; '
            'systemctl daemon-reload; systemctl start kvn-v5-lifecycle.socket; '
            'test -S /run/kvn-v5-lifecycle.sock; systemctl restart kvn-v5-web.service',
            data=f"{digest}  candidate.tar.gz\n".encode(), timeout=210)
    print(f"Debian: SHA-256 кандидата фазы 10 {digest}; web и unit готовы.", flush=True)
    with TemporaryDirectory(dir=ROOT, prefix="phase10-signed-") as directory:
        root = Path(directory)
        signer = root / "signer.pem"
        publisher = new_key(signer)
        pin = root / "publisher.json"
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        lab.upload(pin, f"{BASE}/publisher.json")
        now = datetime.now(timezone.utc)
        for name, version, image in MODULES:
            package = root / f"kvn-module-{name}-{version}.tar.gz"
            sha = build(package, signer, module_id=name, version=version, image_digest=image,
                        issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            lab.upload(package, f"{BASE}/{package.name}")
            lab.run(f"cd {BASE}; sha256sum --check --strict", data=f"{sha}  {package.name}\n".encode())
    for name in ("check_tls_gateway.py", "check_network_gateway.py", "check_network_nft.py",
                 "check_debian_core.py", "check_hysteria_vm.py", "check_users_vm.py"):
        lab.upload(FIXTURES / name, f"{BASE}/{name}")
    call(lab, "command -v qrencode >/dev/null || (apt-get update && apt-get install -y --no-install-recommends qrencode)", 420)
    for name, image in (("hysteria", HY_IMAGE), ("xray", XRAY_IMAGE)):
        call(lab, f'docker image inspect "{image}" >/dev/null || docker pull --platform linux/amd64 "{image}"', 300)
        call(lab, f'set -eu; id=$(docker create --network none --pull=never "{image}"); '
             "trap 'docker rm -- \"$id\" >/dev/null' EXIT; "
             f'docker cp "$id":/usr/local/bin/{name} {BASE}/{name}; chmod 0700 {BASE}/{name}', 160)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--stage-only", action="store_true")
    parser.add_argument("--preserve-old-fixture", action="store_true")
    parser.add_argument("--retire-interrupted", action="store_true")
    parser.add_argument("--resume-staging", action="store_true")
    args = parser.parse_args()
    if args.resume_staging and (args.preserve_old_fixture or args.retire_interrupted or args.stage_only):
        parser.error("Возобновление подготовки требует полного прогона без повторного перемещения fixture")
    lab = Lab(22058, ROOT)
    lab.wait()
    if args.retire_interrupted:
        lab.upload(FIXTURES / "check_users_vm.py", f"{BASE}/check_users_vm.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_users_vm.py retire", 180)
    if args.preserve_old_fixture:
        lab.run(f"install -d -m 0700 {BASE}")
        lab.upload(FIXTURES / "check_users_vm.py", f"{BASE}/check_users_vm.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_users_vm.py preserve", 120)
    if args.resume_staging:
        lab.upload(FIXTURES / "check_users_vm.py", f"{BASE}/check_users_vm.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_users_vm.py resume-staging", 120)
    stage(lab, args.archive)
    if not args.stage_only:
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_users_vm.py", 1200)
        if args.preserve_old_fixture or args.resume_staging:
            call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_users_vm.py retire", 120)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        if exc.stderr:
            print(exc.stderr.decode(errors="replace"), end="")
        raise SystemExit(exc.returncode)
