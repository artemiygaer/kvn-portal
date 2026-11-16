"""Проверка обновления ядра через панель только изолированной VM."""

import argparse
from pathlib import Path

from tests.v5.audit_lab_e2e import INSTALLED, STAGE
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT
from v5.core.maintenance.core_bundle import NAME


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, choices=(22068, 22069, 22070), default=22070)
    parser.add_argument('--directory', type=Path, default=Path('output/v5-release-candidate-5.0.3'))
    parser.add_argument('--from-version', default='5.0.2', choices=('5.0.2', '5.0.3'))
    parser.add_argument('--to-version', default='5.0.3', choices=('5.0.3', '5.0.4'))
    args = parser.parse_args()
    lab = Lab(args.port, ROOT)
    lab.wait()
    assert lab.run(f"cat {INSTALLED}/core-version").stdout.strip() == args.from_version.encode('ascii')
    lab.run(f"install -d -m 0700 {STAGE}")
    lab.upload(args.directory / NAME, f"{STAGE}/{NAME}")
    for name in ("check_debian_core.py", "check_core_update_web.py", "wait_core_update.py", "check_tls_import_limit.py",
                 "check_listeners_web.py"):
        lab.upload(Path("tests/v5/fixtures") / name, f"{STAGE}/{name}")
    before = lab.run("sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json").stdout
    lab.run(f"cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_core_update_web.py "
            f"{STAGE}/{NAME} {args.to_version}", timeout=300, capture=False)
    lab.run(f"python3 -u {STAGE}/wait_core_update.py {args.to_version}", timeout=630, capture=False)
    assert lab.run("sha256sum /etc/kvn-v5/web/config.json /root/portal/modules.json").stdout == before
    lab.run(f"cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_tls_import_limit.py",
            timeout=390, capture=False)
    lab.run(f"cd {INSTALLED}; PYTHONPATH=.:{STAGE} python3 -u {STAGE}/check_listeners_web.py",
            timeout=120, capture=False)
    print(f"Обновление {args.from_version} → {args.to_version} через HTTPS: настройки сохранены.", flush=True)


if __name__ == "__main__":
    main()
