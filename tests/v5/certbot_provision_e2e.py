"""Установить закреплённый Certbot offline только на учебном Debian в QEMU."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, choices=(22056, 22057))
    parser.add_argument("--candidate", nargs=2, metavar=("ARCHIVE", "SHA256"))
    args = parser.parse_args()
    directory = Path("/var/tmp/kvn-v5-lab")
    tag = "311" if args.port == 22056 else "313"
    source = directory / f"verify-acme-{tag}"
    code = "/var/tmp/kvn-v5-phase3-candidate" if args.port == 22056 else "/usr/local/lib/kvn-v5"
    lab = Lab(args.port, directory)
    lab.wait()
    if args.candidate:
        archive, digest = Path(args.candidate[0]), args.candidate[1].lower()
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            parser.error("Неверный SHA-256 учебного архива")
        code = "/var/tmp/kvn-v5-acme-candidate"
        lab.run(f"install -d -m 0700 {code}")
        lab.upload(archive, f"{code}/candidate.tar.gz")
        lab.run(f"set -eu; umask 077; cd {code}; sha256sum --check --strict; tar -xzf candidate.tar.gz --no-same-owner",
                data=f"{digest}  candidate.tar.gz\n".encode())
    scratch = "/var/tmp/kvn-v5-acme-fixture"
    lab.run(f"test -r {code}/v5/core/tls/requirements-acme.lock && install -d -m 0700 {scratch} {scratch}/wheels")
    with TemporaryDirectory(prefix="kvn-v5-test-wheels-") as temporary:
        archive = Path(temporary) / "wheels.tar"
        wheel_files = sorted(source.glob("*.whl"))
        assert len(wheel_files) == 18 and all(item.is_file() and not item.is_symlink() for item in wheel_files)
        with tarfile.open(archive, "w") as bundle:
            for item in wheel_files:
                bundle.add(item, arcname=item.name)
        lab.upload(archive, f"{scratch}/wheels.tar")
    lab.run(f"tar -xf {scratch}/wheels.tar --no-same-owner -C {scratch}/wheels")
    lab.run("apt-get install -y --no-install-recommends python3-venv", timeout=450)
    command = f"cd {code} && /usr/bin/python3 -m v5.core.tls.provision --wheels {scratch}/wheels"
    result = lab.run(command, timeout=850)
    print(result.stdout.decode().strip(), flush=True)
    link_before = lab.run("readlink /usr/local/lib/kvn-v5-acme").stdout
    version = lab.run("/usr/local/lib/kvn-v5-acme/bin/certbot --version").stdout.decode().strip()
    assert version == "certbot 5.9.0"
    lab.run(command, timeout=90)
    assert lab.run("readlink /usr/local/lib/kvn-v5-acme").stdout == link_before
    print(f"Debian/Python {tag}: {version}, wheels с SHA-256, повтор без переключения: OK", flush=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stderr.decode(errors="replace"), file=sys.stderr)
        raise SystemExit(exc.returncode)
