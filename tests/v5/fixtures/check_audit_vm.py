"""Проверка настоящего systemd, Unix RPC и фильтров на учебном Debian."""

import json
from datetime import datetime, timezone
from pathlib import Path
import secrets
import subprocess
import time

from v5.core import audit

SOCKET = "/run/kvn-v5-agent/control.sock"


def as_web(source, code, *args):
    return subprocess.run(["/usr/sbin/runuser", "-u", "kvn-v5-web", "--",
                           "/usr/bin/python3", "-c", code, source, *args],
                          capture_output=True, check=True, timeout=6).stdout


def fetch(source):
    payload = as_web(source, f"""
import json, sys
from pathlib import Path
from v5.portal.rpc import HostClient
print(json.dumps(HostClient(Path({SOCKET!r})).journal_recent(sys.argv[1])))
""")
    return json.loads(payload)["entries"]


def main():
    assert Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    marker = "fixture-" + secrets.token_hex(12)
    deadline = time.monotonic() + 30
    while not Path(SOCKET).is_socket():
        if time.monotonic() >= deadline:
            raise AssertionError("Сокет не появился после запуска учебного агента")
        time.sleep(.25)
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    as_web(marker, f"""
import sys
from pathlib import Path
from v5.portal.rpc import AgentRejected, HostClient
client = HostClient(Path({SOCKET!r}))
try:
    client.tls_issue("unregistered.invalid", "fixture-mode", sys.argv[1])
except AgentRejected as exc:
    assert exc.code == "invalid_request"
else:
    raise AssertionError("Некорректная задача TLS принята")
assert client.site_status()["customized"] is False
assert client.site_reset()["reset"] is True
""")
    # Такой идентификатор от пользователя веб-службы не должен попасть в root-аудит.
    as_web("package.rollback ok amneziawg", """
import sys, syslog
syslog.openlog("kvn-v5-audit", facility=syslog.LOG_AUTHPRIV)
syslog.syslog(syslog.LOG_INFO, sys.argv[1])
""")
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        rows = fetch("operations")
        observed = {(row["method"], row["status"]) for row in rows if row["time"] >= started}
        if {("tls.issue", "failed"), ("site.reset", "ok")} <= observed:
            break
        time.sleep(.3)
    else:
        raise AssertionError("Результат реального RPC не появился в журнале")
    assert len(rows) <= audit.LIMIT
    assert marker not in json.dumps(rows)
    assert not any(row["method"] == "package.rollback" and row["module"] == "amneziawg" for row in rows)
    gateway = fetch("gateway")
    assert 0 < len(gateway) <= audit.LIMIT
    assert all(set(row) == {"time", "priority"} for row in gateway)
    print("Debian/systemd: отказ TLS и успешный сброс стандартной страницы через Unix RPC записаны.")
    print("Лишние поля и записи непривилегированного UID исключены.")
    print("Шлюз: доступны ограниченные время и приоритет, сообщения не передаются.")


if __name__ == "__main__":
    main()
