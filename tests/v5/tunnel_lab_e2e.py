"""Подписать учебные WG/AWG пакеты и проверить их на изолированных Debian VM."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import REMOTE, ROOT, call
from tests.v5.test_packages import new_key
from v5.core.packages.manifest import canonical_json
from v5.packaging.build_module import build


FIXTURES = Path(__file__).with_name("fixtures")


def stage_core(lab, archive):
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    lab.upload(archive, f"{REMOTE}/core.tar.gz")
    lab.run(f"set -eu; umask 077; cd {REMOTE}; sha256sum --check --strict; "
            'stage=$(mktemp -d core.XXXXXX); tar -xzf core.tar.gz -C "$stage"; '
            'cp -a "$stage"/v5/core/. /usr/local/lib/kvn-v5/v5/core/; '
            'install -d -m 0755 /usr/local/lib/kvn-v5/v5/modules; '
            'cp -a "$stage"/v5/modules/. /usr/local/lib/kvn-v5/v5/modules/; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type d -exec chmod 0755 {} +; '
            'find /usr/local/lib/kvn-v5/v5/core /usr/local/lib/kvn-v5/v5/modules -type f -exec chmod 0644 {} +; '
            'for module in xray wireguard amneziawg; do '
            'unit="kvn-v5-module-$module.service"; install -m 0644 "$stage/v5/install/systemd/$unit" /etc/systemd/system/; '
            'systemd-analyze verify "/etc/systemd/system/$unit"; done; systemctl daemon-reload',
            data=f"{digest}  core.tar.gz\n".encode(), timeout=210)
    print(f"Debian {lab.port}: ядро {digest}, unit туннелей установлены без старта", flush=True)


def stage_packages(lab):
    with tempfile.TemporaryDirectory(prefix="kvn-v5-tunnel-signed-", dir=ROOT) as directory:
        root = Path(directory)
        signer = root / "signer.pem"
        publisher = new_key(signer)
        pin = root / "publisher.json"
        pin.write_bytes(canonical_json({"public_der": publisher.public_der.hex(), "sha256": publisher.fingerprint}))
        lab.upload(pin, f"{REMOTE}/publisher.json")
        now = datetime.now(timezone.utc)
        for module in ("wireguard", "amneziawg"):
            artifact = root / f"kvn-module-{module}-1.0.0.tar.gz"
            digest = build(artifact, signer, module_id=module, version="1.0.0",
                           issued_at=(now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                           expires_at=(now + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            lab.upload(artifact, f"{REMOTE}/{artifact.name}")
            lab.run(f"cd {REMOTE}; sha256sum --check --strict", data=f"{digest}  {artifact.name}\n".encode())


def fixture(lab, *mode):
    script = f"PYTHONPATH=/usr/local/lib/kvn-v5 python3 -u {REMOTE}/check_tunnel_vm.py"
    if mode:
        script += " " + shlex.join(mode)
    call(lab, script, 1200)


def egress(lab):
    for module in ('wireguard', 'amneziawg'):
        call(lab, 'PYTHONPATH=/usr/local/lib/kvn-v5 unshare --mount --net --propagation private '
             f'python3 -u {REMOTE}/tunnel_egress_e2e.py {module}', 360)


def candidate_egress(lab, module, *, with_v42=False):
    # Подмена кода только в PYTHONPATH этого прогона. Установленное ядро,
    # unit и настройки учебной VM не перезаписываются.
    path = lab.run('umask 077; mktemp -d /var/tmp/kvn-v5-tunnel-candidate.XXXXXX').stdout.decode().strip()
    if not re.fullmatch(r'/var/tmp/kvn-v5-tunnel-candidate\.[A-Za-z0-9]{6}', path):
        raise ValueError('Неожиданный путь учебного кандидата')
    project = Path(__file__).resolve().parents[2]
    client_archive = ''
    with tempfile.TemporaryDirectory(prefix='kvn-v5-tunnel-candidate-', dir=ROOT) as directory:
        archive = Path(directory) / 'candidate.tar.gz'
        subprocess.run(['tar', '--exclude=__pycache__', '-czf', archive, '-C', project,
                        'v5/core', 'v5/modules', 'tests/v5/tunnel_egress_e2e.py'], check=True, timeout=30)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        lab.upload(archive, f'{path}/candidate.tar.gz')
        lab.run(f'cd {path} && sha256sum --check --strict && tar -xzf candidate.tar.gz',
                data=f'{digest}  candidate.tar.gz\n'.encode())
        if with_v42:
            from tests.v5.fixtures.make_v42_fixture import build_fixture
            fixture = Path(directory) / 'synthetic-v42.kvn'
            fixture.write_bytes(build_fixture())
            lab.upload(fixture, f'{path}/{fixture.name}')
            lab.run(f'cd {path} && sha256sum --check --strict',
                    data=f'{hashlib.sha256(fixture.read_bytes()).hexdigest()}  {fixture.name}\n'.encode())
            client_archive = f' {fixture.name}'
    print(f'Debian {lab.port}: кандидат SHA-256 {digest}; {module}', flush=True)
    call(lab, f'cd {path} && PYTHONPATH={path} unshare --mount --net --propagation private '
         f'python3 -u tests/v5/tunnel_egress_e2e.py {module}{client_archive}', 360)


def abi_probe(lab):
    # Повторная проверка диагностического файла без замены файлов и units активного прогона.
    path = Path(__file__).resolve().parents[2] / 'v5/modules/host_tunnel/platform.py'
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    remote_name = f'platform-probe-{digest}.py'
    target = f'{REMOTE}/{remote_name}'
    lab.upload(path, target)
    lab.run(f'cd {REMOTE}; sha256sum --check --strict', data=f'{digest}  {remote_name}\n'.encode())
    source = ('import runpy; from v5.modules.host_tunnel.config import AWG; '
              f'probe=runpy.run_path({target!r}, '
              'run_name="v5.modules.host_tunnel._candidate_probe"); '
              'result=probe["capability"](AWG); assert "3.1" in result.profiles; '
              'print(result.kernel, result.module_version, result.tools_version, ",".join(result.profiles))')
    call(lab, 'systemd-run --quiet --wait --pipe --collect '
         '--setenv=PYTHONPATH=/usr/local/lib/kvn-v5 -p NoNewPrivileges=yes -p ProtectSystem=strict '
         '-p ProtectKernelTunables=yes -p CapabilityBoundingSet=CAP_NET_ADMIN -p SystemCallFilter=~@module '
         '-p "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" '
         f'/usr/bin/python3 -c {shlex.quote(source)}', 240)
    print(f'Debian {lab.port}: проверены setconf и чтение параметров AWG 3.1; SHA-256 диагностики {digest}.', flush=True)


def wait_dependencies(lab):
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        try:
            ready = lab.run('test -d /sys/module/amneziawg && test -x /usr/local/bin/awg && test -x /usr/bin/wg',
                            check=False, timeout=45)
        except subprocess.TimeoutExpired:
            continue
        if ready.returncode == 0:
            return
        time.sleep(5)
    raise RuntimeError('На учебной VM не появилась готовая связка AWG kernel/tools')


def wait_guest(lab):
    # Не перечислять все unit-файлы на однопроцессорной VM во время сборки модуля.
    deadline = time.monotonic() + 420
    while time.monotonic() < deadline:
        try:
            result = lab.run('test -f /var/lib/cloud/instance/boot-finished && '
                             'cat /var/lib/cloud/data/instance-id && hostname', check=False, timeout=60)
        except subprocess.TimeoutExpired:
            continue
        if result.returncode == 0:
            if result.stdout.splitlines() != [b'kvn-v5-isolated-001', b'kvn-v5-isolated']:
                raise RuntimeError('SSH ответил не учебный экземпляр; остановлено')
            return
        time.sleep(5)
    raise RuntimeError('Изолированная VM не ответила через SSH')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, choices=(22058, 22059))
    parser.add_argument("archive", type=Path, nargs="?")
    parser.add_argument("--reboot", action="store_true")
    parser.add_argument("--wait-dependencies", action="store_true")
    parser.add_argument("--retry-initial", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--after-reboot", action="store_true", help="Проверить уже выполненную перезагрузку")
    mode.add_argument("--stage-only", action="store_true")
    mode.add_argument("--fixture-only", action="store_true")
    mode.add_argument("--abi-only", action="store_true")
    mode.add_argument("--candidate-egress", choices=("wireguard", "amneziawg"),
                      help="Проверить трафик текущего кода без замены установленных файлов")
    parser.add_argument("--with-v42", action="store_true", help="Добавить синтетический архив v4.2 к candidate-egress")
    args = parser.parse_args()
    if args.with_v42 and not args.candidate_egress:
        parser.error("--with-v42 требует --candidate-egress")
    lab = Lab(args.port, ROOT)
    wait_guest(lab)
    if args.candidate_egress:
        candidate_egress(lab, args.candidate_egress, with_v42=args.with_v42)
        return
    if args.abi_only:
        abi_probe(lab)
        return
    if not (args.after_reboot or args.stage_only) and args.wait_dependencies:
        print(f'Debian {lab.port}: ожидаю готовую связку AWG kernel/tools до установки fixture', flush=True)
        wait_dependencies(lab)
    if not (args.after_reboot or args.fixture_only):
        if not args.archive:
            parser.error("Нужен проверяемый архив ядра")
        lab.run(f"install -d -m 0700 {REMOTE}")
        stage_core(lab, args.archive)
        for name in ("check_network_nft.py", "check_tunnel_vm.py"):
            lab.upload(FIXTURES / name, f"{REMOTE}/{name}")
        lab.upload(Path(__file__).with_name('tunnel_egress_e2e.py'), f'{REMOTE}/tunnel_egress_e2e.py')
        if args.retry_initial:
            fixture(lab, 'preserve-failed')
        stage_packages(lab)
        if args.stage_only:
            return
    if not args.after_reboot:
        fixture(lab)
        egress(lab)
    if args.reboot:
        lab.reboot()
    if args.reboot or args.after_reboot:
        fixture(lab, "after-reboot")


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        if exc.stderr:
            print(exc.stderr.decode(errors="replace"), file=sys.stderr, end="")
        raise SystemExit(exc.returncode)
