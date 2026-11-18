"""Краткий журнал: фиксированные события, без тел RPC и сырого вывода."""

from datetime import datetime, timezone
import json
import subprocess
import syslog

from .contracts import MODULE_IDS

LIMIT = 40
MAX_OUTPUT = 256 * 1024
_TAG = "kvn-v5-audit"
OPERATIONS = frozenset({
    "package.upload", "package.github", "package.install", "package.rollback", "package.remove",
    "lifecycle.enable", "lifecycle.disable", "lifecycle.upgrade", "lifecycle.initialize", "lifecycle.initialize_xray", "lifecycle.add_xray",
    "lifecycle.replace_xray", "lifecycle.remove_xray",
    "lifecycle.initialize_hysteria", "lifecycle.initialize_mtproto", "lifecycle.change_mtproto",
    "users.create", "users.grant", "users.retry", "users.rotate", "users.revoke",
    "migration.preview", "migration.commit", "migration.rollback", "migration.export",
    "tls.issue", "tls.import", "tls.diagnose", "tls.prepare", "site.publish", "site.reset",
    "maintenance.backup", "maintenance.reset_admin",
    "maintenance.core_update", "maintenance.core_recover",
    "provision.prepare",
    "core.forwarding_enable",
    "lifecycle.change_tunnel",
    "lifecycle.change_hysteria",
    "console.authorize", "console.attach",
    "ssh.create", "ssh.password", "ssh.disable", "ssh.enable", "ssh.delete",
})
UNITS = {
    "gateway": "kvn-v5-gateway.service", "agent": "kvn-v5-agent.service",
    "web": "kvn-v5-web.service", "tls": "kvn-v5-tls.service",
    **{module: f"kvn-v5-module-{module}.service" for module in sorted(MODULE_IDS)},
}
SOURCES = ("operations", *UNITS)


def record(method: str, ok: bool, module=None) -> None:
    if method not in OPERATIONS:
        return
    subject = module if isinstance(module, str) and module in MODULE_IDS else "-"
    try:
        syslog.openlog(_TAG, facility=syslog.LOG_AUTHPRIV)
        syslog.syslog(syslog.LOG_INFO, f"{method} {'ok' if ok else 'failed'} {subject}")
    except OSError:
        # Сбой журнала не должен превращать выполненное изменение в ошибку RPC.
        pass


def outcome(request: dict, response: dict) -> None:
    method, params = request.get("method"), request.get("params")
    if not isinstance(method, str):
        return
    result = response.get("result")
    subject = (result.get("module") if isinstance(result, dict) else None)
    if subject is None and isinstance(params, dict):
        subject = params.get("module")
    record(method, response.get("ok") is True, subject)


def _entry(line: bytes, source: str) -> dict | None:
    try:
        fields = json.loads(line)
        stamp, priority = fields["__REALTIME_TIMESTAMP"], fields["PRIORITY"]
        if (not isinstance(stamp, str) or not stamp.isascii() or not stamp.isdecimal()
                or not 1 <= len(stamp) <= 18 or priority not in ("0", "1", "2", "3", "4", "5", "6", "7")):
            return None
        moment = datetime.fromtimestamp(int(stamp) // 1000000, timezone.utc).isoformat(timespec="seconds")
        if source != "operations":
            return {"time": moment, "priority": int(priority)}
        message = fields.get("MESSAGE")
        if not isinstance(message, str) or len(message) > 100:
            return None
        method, status, module = message.split(" ")
        if method not in OPERATIONS or status not in ("ok", "failed") or (module != "-" and module not in MODULE_IDS):
            return None
        return {"time": moment, "method": method, "status": status, "module": None if module == "-" else module}
    except (ValueError, OverflowError, OSError, KeyError, TypeError, RecursionError):
        return None


def recent(source: str, *, run=subprocess.run) -> list[dict]:
    if source not in SOURCES:
        raise ValueError("Неизвестный источник журнала")
    # journalctl JSON ограничивает отдельные поля 4096 байт без --all.
    argv = ["/usr/bin/journalctl", "--system", "--no-pager", "--quiet", "--reverse",
            f"--lines={LIMIT}", "--since=-24h", "--output=json"]
    if source == "operations":
        argv.extend(("--output-fields=PRIORITY,MESSAGE", "_UID=0", "_TRANSPORT=syslog", f"SYSLOG_IDENTIFIER={_TAG}"))
    else:
        # Текст служб не запрашивается даже внутри агента.
        unit = UNITS[source]
        argv.extend(("--output-fields=PRIORITY", f"_SYSTEMD_UNIT={unit}", "+", "_PID=1", f"UNIT={unit}"))
    result = run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                 timeout=1.4, check=True, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    if len(result.stdout) > MAX_OUTPUT:
        raise ValueError("Журнал превысил ограничение размера")
    return [entry for line in result.stdout.splitlines()[:LIMIT] if (entry := _entry(line, source)) is not None]
