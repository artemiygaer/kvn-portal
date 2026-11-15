"""Прогон TCP/443, SNI и TLS только в изолированной Debian VM под WSL."""

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys

from tests.v5.debian_core_e2e import Lab


DIRECTORY = "/var/tmp/kvn-v5-phase5"


def upload_candidate(lab, archive, label):
    if label not in {"nft", "gateway", "lifecycle"}:
        raise ValueError("Неизвестный сценарий")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.run(f"install -d -m 0700 {DIRECTORY}")
    asset = f"candidate-{label}.tar.gz"
    lab.upload(archive, f"{DIRECTORY}/{asset}")
    stage = lab.run(f"set -eu; umask 077; cd {DIRECTORY}; sha256sum --check --strict >&2; "
                    "stage=$(mktemp -d candidate.XXXXXX); "
                    f'tar -xzf {asset} --no-same-owner -C "$stage"; printf "%s" "$stage"',
                    data=f"{digest}  {asset}\n".encode()).stdout.decode()
    assert stage.startswith("candidate.") and stage.removeprefix("candidate.").isalnum()
    print(f"Debian: кандидат SHA-256 {digest}", flush=True)
    return f"{DIRECTORY}/{stage}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--nft", action="store_true", help="Отдельный прогон nftables с veth-клиентом")
    parser.add_argument("--stock-reconcile", action="store_true", help="Проверить штатный oneshot без активных модулей")
    args = parser.parse_args()
    lab = Lab(22058, Path("/var/tmp/kvn-v5-lab"))
    lab.wait()
    stage = upload_candidate(lab, args.archive, "nft" if args.nft else "gateway")
    if args.stock_reconcile:
        lab.run(f"systemd-analyze verify {stage}/v5/install/systemd/kvn-v5-reconcile.service")
        lab.run("systemd-run --wait --collect --pipe --unit=kvn-v5-phase5-stock --service-type=oneshot "
                "--property=ProtectSystem=strict --property=ProtectHome=yes "
                "--property='ReadWritePaths=/etc/kvn-v5/gateway /run/kvn-v5-gateway /var/lib/kvn-v5/packages' "
                "--property=CapabilityBoundingSet=CAP_NET_ADMIN "
                "--property='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' "
                f"--setenv=PYTHONPATH={stage} /usr/bin/python3 -m v5.core.lifecycle.boot", timeout=90)
        print("Штатный reconcile: unit проверен, вызов под systemd sandbox завершился без запуска модулей.", flush=True)
    base = Path(__file__).with_name("fixtures")
    script = "check_network_nft.py" if args.nft else "check_network_gateway.py"
    for name in (script,) if args.nft else ("check_tls_gateway.py", script):
        lab.upload(base / name, f"{DIRECTORY}/{name}")
    result = lab.run(f"PYTHONPATH={stage} python3 -u {DIRECTORY}/{script}",
                     timeout=480, check=False)
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
