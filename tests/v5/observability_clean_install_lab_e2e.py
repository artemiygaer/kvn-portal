"""Чистая установка на отдельной Debian VM и проверка выключенной истории."""

from pathlib import Path
import secrets
import shlex
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT
from v5.tools.build_installer import build


def main():
    lab = Lab(22063, ROOT)
    lab.password = secrets.token_urlsafe(24)
    lab.wait()
    lab.run("test ! -e /root/portal && test ! -e /etc/kvn-v5 && install -d -m 0700 /var/tmp/kvn-v5-clean")
    with TemporaryDirectory(dir=ROOT, prefix="phase13-clean-installer-") as directory:
        archive = Path(directory) / "installer.tar.gz"
        digest = build(archive)
        lab.upload(archive, "/var/tmp/kvn-v5-clean/installer.tar.gz")
        lab.run("set -eu; cd /var/tmp/kvn-v5-clean; sha256sum --check --strict; "
                "tar -xzf installer.tar.gz --no-same-owner --no-same-permissions",
                data=f"{digest}  installer.tar.gz\n".encode())
    # Lab.install ожидает исходники только в фиксированном учебном каталоге.
    lab.run("install -d -m 0700 /var/tmp/kvn-v5-phase2; "
            "cp -a /var/tmp/kvn-v5-clean/v5 /var/tmp/kvn-v5-phase2/v5")
    prompts = [("Каталог установки", ""), ("IP сервера", "192.0.2.8"),
               ("Имена DNS", "portal.example www.portal.example"), ("Логин администратора", ""),
               ("Пароль администратора", lab.password), ("Повторите пароль", lab.password),
               ("Начать установку?", "да")]
    lab.install(prompts, 0)
    lab.run("set -eu; test \"$(systemctl is-enabled kvn-v5-observer.service || true)\" = disabled; "
            "test \"$(systemctl is-active kvn-v5-observer.service || true)\" = inactive; "
            "test ! -e /var/lib/kvn-v5/observability/history.sqlite3; "
            "systemctl is-active --quiet kvn-v5-agent.service; "
            "systemctl is-active --quiet kvn-v5-socket-observer.socket")
    code = ("from pathlib import Path; from v5.portal.rpc import HostClient; "
            "data=HostClient(Path('/run/kvn-v5-agent/control.sock')).observe_live(); "
            "assert isinstance(data['ssh'],list) and isinstance(data['processes'],list)")
    lab.run("cd /usr/local/lib/kvn-v5; runuser -u kvn-v5-web -- python3 -c " + shlex.quote(code), timeout=60)
    print("Чистая Debian: история выключена, БД отсутствует, live RPC доступен.", flush=True)


if __name__ == "__main__":
    main()
