"""Подготовить подписанный Hysteria2 и проверить только на изолированной VM."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shlex
import subprocess
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT, call
from tests.v5.test_packages import new_key
from tests.v5.tunnel_lab_e2e import wait_guest
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build

BASE = "/var/tmp/kvn-v5-phase8"
VERSION = "2.13.0"
DIGEST = "5ed85e7f01de4ea6b8ce66ed6e69527e59c29784138f3f9d933d81024fc5c69f"
IMAGE = f"docker.io/tobyxdd/hysteria@sha256:{DIGEST}"
FIXTURES = Path(__file__).with_name("fixtures")


def stage(lab, archive):
    lab.run(f"install -d -m 0700 {BASE}; test ! -e {BASE}/fixture")
    lab.upload(archive, f"{BASE}/candidate.tar.gz")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.run(f"set -eu; umask 077; cd {BASE}; sha256sum --check --strict; "
            'stage=$(mktemp -d candidate.XXXXXX); tar -xzf candidate.tar.gz -C "$stage"; '
            'cp -a "$stage"/v5/core/. /usr/local/lib/kvn-v5/v5/core/; '
            'install -d -m 0755 /usr/local/lib/kvn-v5/v5/modules; '
            'cp -a "$stage"/v5/modules/. /usr/local/lib/kvn-v5/v5/modules/; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type d -exec chmod 0755 {} +; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type f -exec chmod 0644 {} +; '
            'for unit in kvn-v5-module-hysteria.service kvn-v5-module-tls-sync.service '
            'kvn-v5-tls.service kvn-v5-tls-renew.service; do '
            'source="$stage/v5/install/systemd/$unit"; [ ! -f "$source" ] || install -m 0644 "$source" /etc/systemd/system/; '
            'done; systemd-analyze verify /etc/systemd/system/kvn-v5-module-hysteria.service; systemctl daemon-reload',
            data=f"{digest}  candidate.tar.gz\n".encode(), timeout=210)
    print(f"Debian {lab.port}: SHA-256 ядра {digest}, unit не запускался.", flush=True)
    with TemporaryDirectory(dir=ROOT, prefix="kvn-v5-hy-signed-") as directory:
        root = Path(directory)
        key = root / "signer.pem"
        publisher = new_key(key)
        pin = root / "publisher.json"
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        lab.upload(pin, f"{BASE}/{pin.name}")
        package = root / f"kvn-module-hysteria-{VERSION}.tar.gz"
        now = datetime.now(timezone.utc)
        sha = build(package, key, module_id="hysteria", version=VERSION, image_digest=DIGEST,
                    issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        lab.upload(package, f"{BASE}/{package.name}")
        lab.run(f"cd {BASE}; sha256sum --check --strict", data=f"{sha}  {package.name}\n".encode())
        print(f"Подписанный тестовый модуль: SHA-256 {sha}.", flush=True)
    for name in ("check_tls_gateway.py", "check_network_gateway.py", "check_network_nft.py", "check_hysteria_vm.py"):
        lab.upload(FIXTURES / name, f"{BASE}/{name}")


def stage_binary(lab):
    # Бинарник клиента извлекается из того же неизменяемого образа, что и сервер.
    image = shlex.quote(IMAGE)
    call(lab, f"systemctl is-active docker.service && docker pull --platform linux/amd64 {image}", 300)
    script = ('set -eu; id=$(docker create --network none --pull=never ' + image + '); '
              "trap 'docker rm -- \"$id\" >/dev/null' EXIT; "
              f'docker cp "$id":/usr/local/bin/hysteria {BASE}/hysteria; '
              f'chown root:root {BASE}/hysteria; chmod 0700 {BASE}/hysteria; {BASE}/hysteria version')
    call(lab, script, 140)


def fixture(lab, mode):
    call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {BASE}/check_hysteria_vm.py {mode}", 500)


def stage_readiness_fix(lab, archive):
    """Обновить только код пробника после подтверждения выключенного состояния."""
    name = "readiness-fix.tar.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.upload(archive, f"{BASE}/{name}")
    files = ("v5/modules/hysteria/adapter.py", "v5/modules/hysteria/runtime.py")
    listed = shlex.join(files)
    lab.run(f"set -eu; umask 077; cd {BASE}; sha256sum --check --strict; "
            'stage=$(mktemp -d readiness.XXXXXX); '
            f'tar -xzf {name} -C "$stage" -- {listed}; '
            'test "$(systemctl show --property=ActiveState --value kvn-v5-module-hysteria.service)" = inactive; '
            f'for file in {listed}; do install -m 0644 "$stage/$file" "/usr/local/lib/kvn-v5/$file"; done',
            data=f"{digest}  {name}\n".encode(), timeout=180)
    print(f"Debian {lab.port}: SHA-256 кандидата {digest}; изменён только код пробника, состояние прежнее.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, choices=(22058, 22059))
    parser.add_argument("archive", type=Path, nargs="?")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--after-reboot", action="store_true")
    mode.add_argument("--retry-after-reboot", action="store_true")
    mode.add_argument("--resume-disabled", action="store_true")
    mode.add_argument("--prepare-only", action="store_true")
    mode.add_argument("--fixture-only", action="store_true")
    parser.add_argument("--preserve-fixture", action="store_true")
    args = parser.parse_args()
    lab = Lab(args.port, ROOT)
    wait_guest(lab)
    if args.retry_after_reboot:
        if args.preserve_fixture or not args.archive:
            parser.error("Нужен архив исправления; стенд после reboot сохраняется")
        lab.upload(FIXTURES / "check_hysteria_vm.py", f"{BASE}/check_hysteria_vm.py")
        fixture(lab, "check-disabled-after-reboot")
        stage_readiness_fix(lab, args.archive)
        fixture(lab, "after-reboot")
        return
    if args.after_reboot:
        if args.preserve_fixture:
            parser.error("Нельзя архивировать ещё не проверенный reboot")
        fixture(lab, "after-reboot")
        return
    if args.resume_disabled:
        if args.preserve_fixture or args.archive:
            parser.error("Продолжение требует прежнего тестового состояния, без переустановки")
        lab.upload(FIXTURES / "check_hysteria_vm.py", f"{BASE}/check_hysteria_vm.py")
        fixture(lab, "resume-disabled")
        lab.reboot()
        fixture(lab, "after-reboot")
        return
    if args.preserve_fixture:
        lab.upload(FIXTURES / "check_hysteria_vm.py", f"{BASE}/preserve_fixture.py")
        call(lab, f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 {BASE}/preserve_fixture.py preserve", 120)
    if not args.fixture_only:
        if args.archive is None:
            parser.error("Нужен архив ядра")
        stage(lab, args.archive)
        stage_binary(lab)
    if args.prepare_only:
        return
    fixture(lab, "initial")
    lab.reboot()
    fixture(lab, "after-reboot")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        if exc.stderr:
            print(exc.stderr.decode(errors="replace"), end="")
        raise SystemExit(exc.returncode)
