"""Проверить чистую установку только на изолированной QEMU VM в WSL."""

import argparse
import hashlib
import http.client
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import socket
import ssl
import subprocess
import sys
import time

UNIT_LIST = "systemctl list-unit-files --type=service --no-legend --no-pager"
ASSET = "kvn-portal-v5-installer.tar.gz"
RELEASES = "https://github.com/artemiygaer/kvn-portal/releases/download"
VM_NAMES = {22053: "phase2-debian12", 22054: "phase2-debian13", 22055: "phase3-debian13", 22056: "phase3-debian12",
            22057: "phase3-debian13-full", 22058: "phase4-debian13", 22059: "phase4-debian12",
            22060: "phase10-debian13-clean", 22061: "phase11-debian13-clean",
            22068: "phase14-debian12-fresh", 22069: "phase14-debian13-fresh",
            22070: "phase14-debian12-github"}
HTTP_FORWARD = {22055: 22880, 22056: 22881, 22057: 22882, 22058: 22883, 22059: 22884, 22060: 22885,
                22061: 22886}
TLS_FORWARD = {22056: (22443, 22444)}


def release_asset(tag):
    if not re.fullmatch(r"v5\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", tag, flags=re.ASCII):
        raise ValueError("Нужен точный тег v5 (не URL и не ветка)")
    return f"{RELEASES}/{tag}/{ASSET}"


class Lab:
    def __init__(self, port, directory):
        self.port = port
        self.directory = directory
        self.ssh = ["ssh", "-i", str(directory / "lab_ed25519"), "-o", "BatchMode=yes",
                    "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
                    "-o", "StrictHostKeyChecking=accept-new", "-o",
                    f"UserKnownHostsFile={directory}/phase2-{port}-known-hosts", "-p", str(port)]
        self.host = "kvnlab@127.0.0.1"

    def run(self, script, *, data=None, check=True, timeout=90, capture=True):
        return subprocess.run([*self.ssh, self.host, "sudo -n bash -c " + shlex.quote(script)],
                              input=data, capture_output=capture, check=check, timeout=timeout)

    def wait(self):
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            result = self.run("cat /var/lib/cloud/data/instance-id; hostname", check=False)
            if result.returncode == 0:
                if result.stdout.splitlines() != [b"kvn-v5-isolated-001", b"kvn-v5-isolated"]:
                    raise RuntimeError("SSH ответил не учебный экземпляр; остановлено")
                readiness = self.run("test -f /var/lib/cloud/instance/boot-finished && "
                                     f"{UNIT_LIST} >/dev/null", check=False)
                if readiness.returncode == 0:
                    return
            time.sleep(5)
        raise RuntimeError("Изолированная VM не ответила через SSH")

    def upload(self, path, destination):
        self.run(f"umask 077; cat > {shlex.quote(destination)}", data=path.read_bytes())

    def probe(self, password=""):
        source = Path(__file__).with_name("fixtures") / "check_debian_core.py"
        self.upload(source, "/var/tmp/kvn-v5-phase2/check_debian_core.py")
        flags = " --http01" if self.port in HTTP_FORWARD or self.port in (22068, 22069, 22070) else ""
        if self.port == 22057:
            flags += " --phase3-app"
            if not password:
                flags += " --fixture-session"
        result = self.run("python3 /var/tmp/kvn-v5-phase2/check_debian_core.py" + flags, data=password.encode(),
                          timeout=150 if self.port == 22057 else 90)
        print(result.stdout.decode(), flush=True)
        self.probe_tunnel()

    def probe_tunnel(self):
        cert = self.run("cat /etc/kvn-v5/gateway/bootstrap.crt").stdout.decode()
        context = ssl.create_default_context(cadata=cert)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            local_port = listener.getsockname()[1]
        with subprocess.Popen([*self.ssh, "-o", "ExitOnForwardFailure=yes", "-N", "-L",
                               f"127.0.0.1:{local_port}:127.0.0.1:8443", self.host],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as tunnel:
            try:
                for _ in range(30):
                    with socket.socket() as local:
                        if local.connect_ex(("127.0.0.1", local_port)) == 0:
                            break
                    if tunnel.poll() is not None:
                        raise RuntimeError("SSH-туннель завершился до HTTP-проверки")
                    time.sleep(1)
                else:
                    raise RuntimeError("Не дождались SSH-туннеля")
                connection = http.client.HTTPSConnection("127.0.0.1", local_port, timeout=25, context=context)
                try:
                    connection.request("GET", "/login", headers={"Host": "127.0.0.1:8443"})
                    assert connection.getresponse().status == 200
                finally:
                    connection.close()
                print("Из WSL через SSH-туннель: HTTPS 200, сертификат проверен.", flush=True)
            finally:
                if tunnel.poll() is None:
                    tunnel.terminate()

    def reboot(self):
        before = self.run("cat /proc/sys/kernel/random/boot_id").stdout
        self.run("systemctl --no-wall reboot", check=False)
        deadline = time.monotonic() + 100
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=2):
                    pass
            except OSError:
                break
            time.sleep(2)
        else:
            raise RuntimeError("Гостевая VM не завершила первый запуск после reboot")
        name = VM_NAMES[self.port]
        image = self.directory / f"{name}.qcow2"
        serial = self.directory / f"{name}-reboot.log"
        pid = self.directory / f"{name}.pid"
        network = f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.port}-:22"
        if self.port in HTTP_FORWARD:
            network += f",hostfwd=tcp:127.0.0.1:{HTTP_FORWARD[self.port]}-:80"
        if self.port in TLS_FORWARD:
            tls, admin = TLS_FORWARD[self.port]
            network += f",hostfwd=tcp:127.0.0.1:{tls}-:443,hostfwd=tcp:127.0.0.1:{admin}-:8443"
        subprocess.run(["qemu-system-x86_64", "-machine", "accel=tcg", "-cpu", "max", "-m", "1024", "-smp", "1",
                        "-drive", f"file={image},format=qcow2,if=virtio", "-cdrom", str(self.directory / "seed.iso"),
                        "-nic", network,
                        "-display", "none", "-monitor", "none", "-serial", f"file:{serial}",
                        "-no-reboot", "-pidfile", str(pid), "-daemonize"], check=True, timeout=25)
        self.wait()
        assert self.run("cat /proc/sys/kernel/random/boot_id").stdout != before
        self.run("cd /var/tmp/kvn-v5-phase2 && sha256sum --status --check private.checks")
        print("Reboot: новый boot ID; администратор, состояние и TLS-ключ не изменились.", flush=True)

    def install(self, prompts, expected):
        cmd = "stty rows 30 cols 100; exec sudo -n sh -c 'umask 077; exec bash /var/tmp/kvn-v5-phase2/v5/install/install.sh'"
        with subprocess.Popen([*self.ssh, "-tt", self.host, cmd], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True) as proc:
            buffer = b""
            captured = b""
            deadline = time.monotonic() + 1200
            prompts = iter(prompts)
            prompt = next(prompts, None)
            try:
                while time.monotonic() < deadline:
                    if not select.select([proc.stdout], [], [], 3)[0]:
                        continue
                    chunk = os.read(proc.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    captured += chunk
                    buffer = (buffer + chunk)[-8192:]
                    if prompt and prompt[0].encode() in buffer:
                        proc.stdin.write((prompt[1] + "\n").encode())
                        proc.stdin.flush()
                        buffer = b""
                        prompt = next(prompts, None)
                else:
                    raise TimeoutError("Не дождались завершения установщика")
                code = proc.wait(timeout=10)
                # Даже если терминал ошибочно включил эхо, тестовый секрет не попадёт в журнал.
                echo = self.password.encode() in captured
                captured = captured.replace(self.password.encode(), b"[redacted]")
                print(captured.decode(errors="replace"), flush=True)
                assert not echo, "Пароль ошибочно выведен терминалом"
                assert prompt is None, f"Не получен следующий диалог, exit={code}"
                assert code == expected, f"Ожидался exit={expected}, получен exit={code}"
            finally:
                if proc.poll() is None:
                    proc.kill()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, choices=tuple(VM_NAMES))
    parser.add_argument("archive", type=Path, nargs="?")
    parser.add_argument("sha256", nargs="?")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--probe-only", action="store_true")
    operation.add_argument("--reboot-only", action="store_true")
    operation.add_argument("--reboot", action="store_true")
    parser.add_argument("--github-tag", help="Загрузить тот же архив из GitHub напрямую внутри VM")
    args = parser.parse_args()
    lab = Lab(args.port, Path("/var/tmp/kvn-v5-lab"))
    lab.password = secrets.token_urlsafe(24)
    if args.reboot_only or args.probe_only:
        lab.wait()
        if args.reboot_only:
            lab.reboot()
        lab.probe()
        return
    if not (args.archive and args.sha256):
        parser.error("Для чистой установки нужны архив и SHA-256")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.sha256):
        parser.error("Некорректный SHA-256")
    digest = args.sha256.lower()
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != digest:
        parser.error("Локальный файл не совпадает с ожидаемым SHA-256")
    url = release_asset(args.github_tag) if args.github_tag else None
    lab.wait()
    print(lab.run("grep VERSION_ID /etc/os-release; stat -c '/root: %a %u %g' /root").stdout.decode(), flush=True)
    lab.run("test ! -e /root/portal && test ! -e /etc/kvn-v5 && install -d -m 0700 /var/tmp/kvn-v5-phase2")
    if url:
        lab.run("cd /var/tmp/kvn-v5-phase2 && curl --disable --fail --location --proto '=https' "
                "--proto-redir '=https' --max-time 60 --output installer.tar.gz " + shlex.quote(url))
    else:
        lab.upload(args.archive, "/var/tmp/kvn-v5-phase2/installer.tar.gz")
    lab.run("set -eu; umask 077; cd /var/tmp/kvn-v5-phase2; sha256sum --check --strict; "
            "tar -xzf installer.tar.gz --no-same-owner --no-same-permissions; "
            "dpkg-query -W > packages.before; ss -H -lntu > ports.before; "
            f"{UNIT_LIST} > units.before; stat -c '%a %u %g' /root > root.before",
            data=f"{digest}  installer.tar.gz\n".encode())
    lab.run("set -eu; test ! -e /root/deploy; test ! -L /root/deploy; "
            "install -d -m 0700 /root/deploy; touch /root/deploy/setup.sh /root/deploy/docker-compose.yml")
    lab.install([("Каталог установки", "")], 1)
    lab.run("set -eu; test -f /root/deploy/setup.sh; test -f /root/deploy/docker-compose.yml; "
            "unlink /root/deploy/setup.sh; unlink /root/deploy/docker-compose.yml; rmdir /root/deploy; test ! -e /root/portal")
    basic = [("Каталог установки", ""), ("IP сервера", "192.0.2.8"), ("Имена DNS", "portal.example www.portal.example"),
             ("Логин администратора", ""), ("Пароль администратора", lab.password), ("Повторите пароль", lab.password)]
    lab.install(basic + [("Начать установку?", "нет")], 1)
    lab.run("set -eu; cd /var/tmp/kvn-v5-phase2; test ! -e /root/portal; test ! -e /etc/kvn-v5; "
            f"dpkg-query -W | cmp packages.before; {UNIT_LIST} | cmp units.before")
    lab.install(basic + [("Начать установку?", "да")], 0)
    result = lab.run("set -eu; cd /var/tmp/kvn-v5-phase2; "
                     "dpkg-query -W > packages.after; ss -H -lntu > ports.after; "
                     f"{UNIT_LIST} > units.after; stat -c '%a %u %g' /root | cmp root.before; "
                     "sha256sum /root/portal/*.json /etc/kvn-v5/web/config.json /etc/kvn-v5/gateway/bootstrap.key > private.checks; "
                     "for name in packages ports units; do diff -u $name.before $name.after || test $? = 1; done")
    print(result.stdout.decode(), flush=True)
    lab.install([("Каталог установки", "")], 0)
    lab.run("cd /var/tmp/kvn-v5-phase2 && sha256sum --status --check private.checks")
    lab.probe(lab.password)
    if args.reboot:
        lab.reboot()
        lab.probe(lab.password)
    print("Установка, отмена, отказ на fixture v4.2 и повторный запуск проверены.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stdout.decode(errors="replace"), file=sys.stderr)
        print(exc.stderr.decode(errors="replace"), file=sys.stderr)
        raise SystemExit(exc.returncode)
