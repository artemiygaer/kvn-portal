"""Реальное обновление и оба отката на выделенном Debian 13 (WSL)."""

from pathlib import Path
import shlex
import subprocess
from tempfile import TemporaryDirectory

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.maintenance_lab_e2e import CLI, FIXTURE
from tests.v5.migration_lab_e2e import upload
from tests.v5.prepare_tunnel_lab import ROOT
from tests.v5.test_core_update import artifact, publisher
from v5.core.release import ARCHIVE, MANIFEST, SIGNATURE

CORE_TRUST = "/etc/kvn-v5/core"
STASH = "/usr/local/lib/.kvn-v5-core"


def verify(lab):
    identity = lab.run("cat /var/lib/cloud/data/instance-id; hostname", timeout=60).stdout.splitlines()
    if identity != [b"kvn-v5-isolated-001", b"kvn-v5-isolated"]:
        raise RuntimeError("SSH ответил не учебный экземпляр")
    print("SSH: подтверждена отдельная учебная VM на loopback 22062.", flush=True)
    stage_candidate(lab)
    lab.upload(FIXTURE, f"{STAGE}/{FIXTURE.name}")
    lab.run(f"test ! -e {INSTALLED}/core-version && test ! -e {STASH}/pending")
    with TemporaryDirectory(dir=ROOT, prefix="core-update-") as directory:
        root = Path(directory)
        _, key, pin = publisher(root)
        # Выделенный доверенный ключ учебного ядра; ключ VPN-модулей не меняется.
        lab.run(f"install -d -m 0700 {CORE_TRUST}")
        lab.upload(pin, f"{CORE_TRUST}/publisher.json")
        for version, broken in (("5.0.1", False), ("5.0.2", True)):
            source = artifact(root / version, key, pin, version, break_web=broken)
            target = f"{STAGE}/core-{version}"
            lab.run(f"install -d -m 0700 {target}")
            for name in (ARCHIVE, MANIFEST, SIGNATURE):
                upload(lab, source / name, target)
        # Создаём отказ подписи в отдельном каталоге, не меняя подписанный выпуск.
        lab.run(f"install -d -m 0700 {STAGE}/bad-signature; cp {STAGE}/core-5.0.1/{ARCHIVE} "
                f"{STAGE}/core-5.0.1/{MANIFEST} {STAGE}/bad-signature/; "
                f"dd if=/dev/zero of={STAGE}/bad-signature/{SIGNATURE} bs=64 count=1 status=none")

    def run_update(directory, expected):
        result = lab.run(CLI + "core-update " + shlex.quote(f"{STAGE}/{directory}"), check=False, timeout=200)
        if result.returncode != expected:
            raise AssertionError(f"{directory}: exit={result.returncode}; "
                                 f"{result.stdout.decode(errors='replace')}{result.stderr.decode(errors='replace')}")
        return result

    def fixed_state():
        return lab.run(f"python3 {STAGE}/{FIXTURE.name} snapshot; "
                       "sha256sum /etc/kvn-v5/web/config.json /etc/kvn-v5/packages/publisher.json; "
                       "systemctl show -p MainPID --value kvn-v5-gateway.service").stdout

    before = fixed_state()
    web_pid = lab.run("systemctl show -p MainPID --value kvn-v5-web.service").stdout
    assert "Подпись выпуска".encode() in run_update("bad-signature", 1).stderr
    assert web_pid == lab.run("systemctl show -p MainPID --value kvn-v5-web.service").stdout
    assert fixed_state() == before
    print("Неверная подпись: web не перезапущен, конфигурация не изменена.", flush=True)
    assert "v5.0.1 применено".encode() in run_update("core-5.0.1", 0).stdout
    assert lab.run(f"cat {INSTALLED}/core-version").stdout.strip() == b"5.0.1"
    assert fixed_state() == before
    assert "понижение версии".encode() in run_update("core-5.0.1", 1).stderr
    print("Подписанное v5.0.1 запущено; повторная установка отклонена.", flush=True)
    web_pid = lab.run("systemctl show -p MainPID --value kvn-v5-web.service").stdout
    assert "Прежнее ядро восстановлено".encode() in run_update("core-5.0.2", 1).stderr
    assert web_pid != lab.run("systemctl show -p MainPID --value kvn-v5-web.service").stdout
    assert lab.run(f"test ! -e {STASH}/pending && cat {INSTALLED}/core-version").stdout.strip() == b"5.0.1"
    assert fixed_state() == before
    print("Подписанное v5.0.2 с отказом запуска: автоматический откат к v5.0.1.", flush=True)
    lab.run(CLI + "core-recover --previous", timeout=200)
    lab.run(f"test ! -e {INSTALLED}/core-version && test ! -e {STASH}/pending && test ! -e {STASH}/previous")
    assert fixed_state() == before
    print("Ручной откат вернул исходное ядро; nginx PID, слушатели и приватное состояние неизменны.", flush=True)


def main():
    with TemporaryDirectory(dir=ROOT, prefix="core-ssh-") as directory:
        lab = Lab(22062, ROOT)
        lab.ssh[1:1] = ["-o", "ControlMaster=auto", "-o", f"ControlPath={directory}/socket",
                        "-o", "ControlPersist=20s"]
        try:
            verify(lab)
        finally:
            if (Path(directory) / "socket").exists():
                subprocess.run([*lab.ssh, "-O", "exit", lab.host], check=False, timeout=8,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
