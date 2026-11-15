"""Установить чистое ядро и проверить перенос через HTTPS в отдельной Debian VM."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.fixtures.make_v42_fixture import build_fixture
from tests.v5.prepare_tunnel_lab import ROOT
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build as build_module
from v5.tools.build_installer import build as build_installer

BASE = "/var/tmp/kvn-v5-phase11"
INSTALL = "/var/tmp/kvn-v5-phase2"
FIXTURES = Path(__file__).with_name("fixtures")


def upload(lab, path, target):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lab.upload(path, f"{target}/{path.name}")
    lab.run(f"cd {target} && sha256sum --check --strict", data=f"{digest}  {path.name}\n".encode())
    return digest


def install(lab):
    lab.run(f"set -eu; test ! -e /root/portal; test ! -e /etc/kvn-v5; install -d -m 0700 {BASE} {INSTALL}")
    with TemporaryDirectory(dir=ROOT, prefix="phase11-signed-") as directory:
        root = Path(directory)
        signer, pin = root / "signer.pem", root / "publisher.json"
        publisher = new_key(signer)
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        candidate = root / "installer.tar.gz"
        build_installer(candidate, pin)
        digest = upload(lab, candidate, INSTALL)
        print(f"Чистая Debian 13 VM: проверен SHA-256 установщика {digest}", flush=True)
        lab.run(f"umask 077; cd {INSTALL} && tar -xzf installer.tar.gz --no-same-owner --no-same-permissions")
        archive = root / "fixture.kvn"
        archive.write_bytes(build_fixture())
        upload(lab, archive, BASE)
        now = datetime.now(timezone.utc)
        package = root / "kvn-module-wireguard-1.0.0.tar.gz"
        build_module(package, signer, module_id="wireguard", version="1.0.0",
                     issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                     expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        upload(lab, package, BASE)
    lab.password = secrets.token_urlsafe(24)
    lab.install([("Каталог установки", ""), ("IP сервера", "192.0.2.8"), ("Имена DNS", "portal.example"),
                 ("Логин администратора", ""), ("Пароль администратора", lab.password),
                 ("Повторите пароль", lab.password), ("Начать установку?", "да")], 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--resume-http", action="store_true", help="Повторить HTTP после сбоя теста до создания БД")
    modes.add_argument("--retry-ports", action="store_true", help="Повторить после безопасного отката точного fixture")
    args = parser.parse_args()
    lab = Lab(22061, ROOT)
    lab.wait()
    if args.resume_http or args.retry_ports:
        db = "test -f" if args.retry_ports else "test ! -e"
        lab.run(f"test -f /root/portal/install.json && test -f {BASE}/fixture.kvn && "
                f"{db} /var/lib/kvn-v5/users/users.sqlite3 && test ! -e /var/lib/kvn-v5/packages/registry.sqlite3")
    else:
        install(lab)
    for name in ("check_debian_core.py", "check_network_nft.py", "check_tunnel_vm.py", "check_migration_vm.py"):
        upload(lab, FIXTURES / name, BASE)
    flag = " --retry-ports" if args.retry_ports else " --fixture-session" if args.resume_http else ""
    result = lab.run(f"cd /usr/local/lib/kvn-v5 && PYTHONPATH=. python3 -u {BASE}/check_migration_vm.py{flag}",
                     data=b"" if flag else lab.password.encode(), check=False, timeout=1300, capture=False)
    if result.returncode:
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
