"""Подтвердить результат прерванного теста чистой установки на учебной VM."""

from pathlib import Path
import shlex
from tempfile import TemporaryDirectory

from tests.v5.debian_core_e2e import Lab
from tests.v5.prepare_tunnel_lab import ROOT
from v5.tools.build_installer import build


def main():
    lab = Lab(22063, ROOT)
    lab.wait()
    with TemporaryDirectory(dir=ROOT, prefix="phase13-verify-installer-") as directory:
        digest = build(Path(directory) / "installer.tar.gz")
    result = lab.run("sha256sum /var/tmp/kvn-v5-clean/installer.tar.gz")
    assert result.stdout.decode("ascii").split()[0] == digest, "Исходники изменились после установки"
    code = ("import json; from pathlib import Path; "
            "assert json.loads(Path('/root/portal/install.json').read_text())['status']=='complete'")
    lab.run("python3 -c " + shlex.quote(code))
    lab.run("set -eu; test \"$(systemctl is-enabled kvn-v5-observer.service || true)\" = disabled; "
            "test \"$(systemctl is-active kvn-v5-observer.service || true)\" = inactive; "
            "test ! -e /var/lib/kvn-v5/observability/history.sqlite3; "
            "systemctl is-active --quiet kvn-v5-agent.service; "
            "systemctl is-active --quiet kvn-v5-socket-observer.socket")
    code = ("from pathlib import Path; from v5.portal.rpc import HostClient; "
            "data=HostClient(Path('/run/kvn-v5-agent/control.sock')).observe_live(); "
            "assert isinstance(data['ssh'],list) and isinstance(data['processes'],list)")
    lab.run("cd /usr/local/lib/kvn-v5; runuser -u kvn-v5-web -- python3 -c " + shlex.quote(code), timeout=60)
    print("Чистая Debian: маркер complete, SHA совпал, история выключена, БД отсутствует, live RPC работает.",
          flush=True)


if __name__ == "__main__":
    main()
