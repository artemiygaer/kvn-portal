"""SSH и приватная копия на выделенном снимке Debian (WSL, loopback 22062)."""

import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import subprocess
import time

from tests.v5.audit_lab_e2e import INSTALLED, STAGE, stage_candidate
from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT

FIXTURE = Path(__file__).with_name("fixtures") / "check_maintenance_vm.py"
CLI = "cd " + INSTALLED + " && python3 -m v5.core.maintenance "


def reset(lab, arguments, password):
    command = "stty rows 30 cols 100; exec sudo -n bash -c " + shlex.quote(CLI + "reset-admin " + shlex.join(arguments))
    with subprocess.Popen([*lab.ssh, "-tt", lab.host, command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT) as child:
        prompts = iter(("Новый пароль администратора: ".encode(), "Повторите пароль: ".encode()))
        prompt = next(prompts)
        scanned = b""
        secret = password.encode()
        deadline = time.monotonic() + 125
        try:
            while time.monotonic() < deadline:
                if not select.select([child.stdout], [], [], 1)[0]:
                    continue
                data = os.read(child.stdout.fileno(), 4096)
                if not data:
                    break
                scanned += data
                if secret in scanned:
                    raise AssertionError("Пароль выведен учебным терминалом")
                if prompt and prompt in scanned:
                    child.stdin.write(secret + b"\n")
                    child.stdin.flush()
                    scanned = b""
                    prompt = next(prompts, None)
            else:
                raise TimeoutError("SSH-восстановление не завершилось")
            code = child.wait(timeout=5)
            if code or prompt is not None or "Доступ восстановлен".encode() not in scanned:
                raise AssertionError(f"SSH-восстановление: exit={code}, результат не подтверждён")
        finally:
            if child.poll() is None:
                child.kill()


def main():
    lab = Lab(22062, ROOT)
    lab.wait()
    stage_candidate(lab)
    lab.upload(FIXTURE, f"{STAGE}/{FIXTURE.name}")

    def probe(mode, fields=None):
        result = lab.run(f"python3 {STAGE}/{FIXTURE.name} {mode}",
                         data=None if fields is None else json.dumps(fields).encode(), timeout=80)
        return result.stdout

    before = probe("snapshot")
    old, new = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    reset(lab, ("--login", "fixture-admin"), old)
    session = json.loads(probe("first", {"password": old}))["cookie"]
    archive = lab.run(CLI + "backup", timeout=90).stdout.decode()
    name = re.search(r"/root/portal/backups/(core-[0-9A-Z-]+[a-f0-9]{12}\.tar\.gz)", archive)[1]
    digest = re.search(r"SHA-256: ([a-f0-9]{64})", archive)[1]
    lab.run(CLI + "verify " + shlex.join((name, digest)), timeout=80)
    lab.run(f"set -eu; test \"$(stat -c %a /root/portal/backups/{name})\" = 600; "
            f"! runuser -u kvn-v5-web -- test -r /root/portal/backups/{name}")
    assert lab.run(CLI + "verify " + shlex.join((name, "0" * 64)), check=False).returncode == 1
    print("Копия проверена, файл 0600 недоступен web UID; неверный SHA-256 отклонён.", flush=True)
    reset(lab, ("--from-backup", name, digest), new)
    print(probe("check", {"cookie": session, "old": old, "new": new}).decode().strip(), flush=True)
    assert probe("snapshot") == before
    print("Смена доступа не изменила привязки, сертификат, конфиг шлюза и реестр пакетов.", flush=True)


if __name__ == "__main__":
    main()
