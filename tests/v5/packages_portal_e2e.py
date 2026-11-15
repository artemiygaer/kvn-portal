"""Подписать синтетические пакеты в WSL и проверить портал на изолированном Debian."""

import argparse
import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.v5.debian_core_e2e import Lab
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build


def refresh_candidate(lab, candidate):
    """Проверить исправленную сборку поверх начальной только в выделенных VM."""
    if lab.port not in (22058, 22059):
        raise ValueError("Обновление допустимо только для пакетных fixture")
    destination = "/var/tmp/kvn-v5-phase2/candidate.tar.gz"
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    lab.upload(candidate, destination)
    result = lab.run(
        "set -eu; test -f /root/portal/install.json; cd /var/tmp/kvn-v5-phase2; "
        "if test -e /etc/kvn-v5/packages/publisher.json; then "
        "cmp /etc/kvn-v5/packages/publisher.json fixture-publisher.json; fi; "
        "sha256sum --check --strict; stage=$(mktemp -d candidate.XXXXXX); "
        "tar -xzf candidate.tar.gz --no-same-owner --no-same-permissions -C \"$stage\"; "
        "install -m 0644 \"$stage\"/v5/core/packages/*.py /usr/local/lib/kvn-v5/v5/core/packages/; "
        "install -m 0644 \"$stage\"/v5/core/agent.py /usr/local/lib/kvn-v5/v5/core/; "
        "install -m 0644 \"$stage\"/v5/portal/app.py \"$stage\"/v5/portal/rpc.py /usr/local/lib/kvn-v5/v5/portal/; "
        "install -m 0644 \"$stage\"/v5/portal/templates/modules.html /usr/local/lib/kvn-v5/v5/portal/templates/; "
        "uid=$(id -u kvn-v5-web); sed \"s/@WEB_UID@/$uid/g\" "
        "\"$stage\"/v5/install/systemd/kvn-v5-package@.service > /etc/systemd/system/kvn-v5-package@.service; "
        "systemd-analyze verify /etc/systemd/system/kvn-v5-package.socket "
        "/etc/systemd/system/kvn-v5-package@.service; systemctl daemon-reload; "
        "systemctl restart kvn-v5-agent.service kvn-v5-web.service; "
        "script --quiet --return --command \"bash $stage/v5/install/install.sh --target /root/portal\" /dev/null; "
        "sha256sum --status --check private.checks",
        data=f"{digest}  candidate.tar.gz\n".encode(), timeout=120, check=False,
    )
    print(f"Кандидат SHA-256: {digest}, повтор мастера exit={result.returncode}", flush=True)
    if result.returncode:
        print(result.stdout.decode(), end="")
        print(result.stderr.decode(), end="")
        raise SystemExit(result.returncode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, choices=(22058, 22059))
    parser.add_argument("--candidate", type=Path, help="Только повтор на уже установленной лабораторной VM")
    parser.add_argument("--reuse-fixtures", action="store_true", help="Повтор с прежним тестовым пином")
    args = parser.parse_args()
    lab = Lab(args.port, Path("/var/tmp/kvn-v5-lab"))
    lab.wait()
    if args.candidate:
        refresh_candidate(lab, args.candidate)
    guest = "/var/tmp/kvn-v5-phase2/"
    now = datetime.now(timezone.utc)
    times = {"issued_at": (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "expires_at": (now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")}
    if not args.reuse_fixtures:
        lab.run("test ! -e /etc/kvn-v5/packages/publisher.json")
        with tempfile.TemporaryDirectory(dir="/var/tmp", prefix="kvn-v5-package-lab-") as folder:
            root = Path(folder)
            key = root / "fixture.pem"
            trust = new_key(key)
            pin = root / "fixture-publisher.json"
            pin.write_bytes(canonical_json({"public_der": trust.public_der.hex(), "sha256": trust.fingerprint}))
            lab.upload(pin, guest + pin.name)
            image = root / "image.bin"
            image.write_bytes(os.urandom(800 * 1024))
            for name, module, version in (("fixture-xray.tar.gz", "xray", "1.0.0"),
                                          ("fixture-wg-v1.tar.gz", "wireguard", "1.0.0"),
                                          ("fixture-wg-v2.tar.gz", "wireguard", "1.0.1")):
                package = root / name
                extra = {"image": image, "image_digest": "1" * 64} if module == "xray" else {}
                digest = build(package, key, module_id=module, version=version, **times, **extra)
                lab.upload(package, guest + name)
                print(f"SHA-256 {name}: {digest}", flush=True)
    for name in ("check_debian_core.py", "check_packages_portal.py"):
        source = Path(__file__).with_name("fixtures") / name
        lab.upload(source, guest + name)
    result = lab.run("python3 /var/tmp/kvn-v5-phase2/check_packages_portal.py", timeout=180, check=False)
    print(result.stdout.decode(), end="")
    if result.returncode:
        print(result.stderr.decode(), end="")
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
