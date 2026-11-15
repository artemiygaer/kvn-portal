"""Только локальный браузерный стенд с синтетическим состоянием панели."""

from time import sleep
from unittest.mock import Mock

from flask import redirect, session

from v5.portal.app import create_app
from v5.portal.rpc import AgentRejected, AgentUnavailable

ADDRESS = "127.0.0.1"
PORT = 18087


def main():
    backend, packages, lifecycle = Mock(), Mock(), Mock()
    backend.status.return_value = {"cpu_percent": 2.1, "memory": {"available_bytes": 612 * 1024**2},
                                   "disk": {"free_bytes": 7 * 1024**3}, "uptime_seconds": 11821,
                                   "network": {"received_bytes": 8 * 1024**2, "sent_bytes": 3 * 1024**2}}
    backend.journal_recent.side_effect = lambda source: {"entries": (
        [{"time": "2026-11-11T12:00:00+00:00", "method": "package.install", "status": "ok", "module": "wireguard"},
         {"time": "2026-11-11T11:59:00+00:00", "method": "tls.issue", "status": "failed", "module": None}]
        if source == "operations" else [{"time": "2026-11-11T12:00:00+00:00", "priority": 6}]
    )}
    packages.status.return_value = {"installed": []}
    installed = {"installed": [{"module": "wireguard", "version": "1.0.0", "enabled": False}]}
    lifecycle.plan.return_value = {"module": "wireguard", "sni": [],
                                   "ports": [{"protocol": "udp", "port": 51821, "ip": "0.0.0.0"}]}

    def github(module, version, tag):
        if module != "wireguard" or version != "1.0.0" or tag is not None:
            raise AgentRejected("invalid_package_signature")
        return {"module": module, "version": version, "sha256": "a" * 64, "ticket": "b" * 64,
                "dependencies": {"host_checks": ["wireguard-tools"], "offline_image": False, "online_image": False}}

    def install(ticket):
        if ticket != "b" * 64:
            raise AgentRejected("unknown_prepared_package")
        # Управляемая задержка только в UI fixture — для наблюдения ожидания.
        sleep(4)
        packages.status.return_value = installed

    packages.github.side_effect, packages.install.side_effect = github, install
    app = create_app({"session_key": "ui-fixture-only", "allowed_hosts": [f"{ADDRESS}:{PORT}"]},
                     client=backend, package_client=packages, lifecycle_client=lifecycle)

    @app.get("/_fixture/<any(empty,installed,unavailable):state>")
    def fixture(state):
        session.clear()
        session.update(admin=True, csrf="ui-fixture")
        packages.status.side_effect = AgentUnavailable("ui-fixture") if state == "unavailable" else None
        packages.status.return_value = installed
        if state == "empty":
            packages.status.return_value = {"installed": []}
        return redirect("/" if state == "empty" else "/modules", code=303)

    app.run(host=ADDRESS, port=PORT, ssl_context="adhoc", use_reloader=False)


if __name__ == "__main__":
    main()
