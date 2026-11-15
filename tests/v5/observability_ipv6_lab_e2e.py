"""Запустить root/IPv6 проверку в учебной Debian VM, не на сервере."""

from pathlib import Path

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    fixture = Path(__file__).with_name("fixtures") / "observability_ipv6_guest.py"
    destination = "/var/tmp/kvn-v5-phase12/observability_ipv6_guest.py"
    lab.upload(fixture, destination)
    result = lab.run(f"python3 -u {destination}", check=False, timeout=150)
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", "replace")[-2000:])
    print(result.stdout.decode("utf-8"), end="", flush=True)


if __name__ == "__main__":
    main()
