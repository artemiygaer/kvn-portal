"""Собрать инструменты и модуль AWG из закреплённых upstream-ревизий на учебной Debian VM."""

import argparse
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from tests.v5.debian_core_e2e import Lab


ROOT = Path("/var/tmp/kvn-v5-lab")
SOURCES = ROOT / "phase7-sources"
REMOTE = "/var/tmp/kvn-v5-phase7"
PINS = {"kernel": "4569c4c67f3a57414969260cafbbd04694fbaae0",
        "tools": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843"}


def call(lab, script, timeout):
    subprocess.run([*lab.ssh, lab.host, "sudo -n bash -ec " + shlex.quote(script)], timeout=timeout, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, choices=(22058, 22059))
    parser.add_argument("--skip-apt", action="store_true")
    args = parser.parse_args()
    lab = Lab(args.port, ROOT)
    lab.wait()
    release = lab.run("uname -r").stdout.decode().strip()
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~-]{0,79}", release):
        raise ValueError("Неожиданная версия учебного ядра")
    lab.run(f"install -d -m 0700 {REMOTE}")
    if not args.skip_apt:
        call(lab, "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
             f"wireguard-tools build-essential linux-headers-{release} pkg-config libmnl-dev libelf-dev nftables", 1200)
    print(f"Debian VM {args.port}, ядро {release}; готовим закреплённые исходники AWG", flush=True)
    with tempfile.TemporaryDirectory(dir=ROOT, prefix="awg-source-") as directory:
        for name, commit in PINS.items():
            repo = SOURCES / name
            head = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, check=True).stdout.decode()
            if head.strip() != commit:
                raise ValueError(f"Ревизия учебных исходников {name} не совпадает с закреплённой")
            artifact = Path(directory) / f"{name}.tar.gz"
            subprocess.run(["git", "-C", repo, "archive", "--format=tar.gz", "-o", artifact, commit], check=True)
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            lab.upload(artifact, f"{REMOTE}/{artifact.name}")
            lab.run(f"cd {REMOTE}; sha256sum --check --strict", data=f"{digest}  {artifact.name}\n".encode())

    call(lab, f"cd {REMOTE}; umask 077; stage=$(mktemp -d build.XXXXXX); "
         'mkdir "$stage/kernel" "$stage/tools"; '
         'tar -xzf kernel.tar.gz -C "$stage/kernel"; tar -xzf tools.tar.gz -C "$stage/tools"; '
         'make -C "$stage/tools/src" -j1; install -m 0755 "$stage/tools/src/wg" /usr/local/bin/awg; '
         'make -C "$stage/kernel/src" -j1; make -C "$stage/kernel/src" -j1 install; '
         'modprobe wireguard; modprobe amneziawg; modinfo -F version amneziawg; /usr/local/bin/awg --version; '
         '/usr/bin/wg --version; test -d /sys/module/amneziawg; test -d /sys/module/wireguard', 2100)


if __name__ == "__main__":
    main()
