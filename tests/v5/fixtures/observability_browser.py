"""Локальный фиктивный портал только для браузерной проверки разметки."""

from unittest.mock import Mock

from flask import redirect, session

from v5.portal.app import create_app


def main():
    backend, lifecycle = Mock(), Mock()
    process = {"pid": 127, "name": "fixture-process", "user": "fixture", "rss_bytes": 1234,
               "cpu_percent": 2.5, "age_seconds": 100}
    ssh = {"id": "1", "user": "fixture", "ip": "2001:db8::12", "port": 12345, "tty": "pts/1",
           "started_at": 1000, "age_seconds": 200, "rx_bytes": 1200, "tx_bytes": 1800,
           "rx_per_second": 10, "tx_per_second": 15}
    network = {"received_bytes": 2000, "sent_bytes": 3000, "rx_per_second": 20, "tx_per_second": 30}
    sample = {"captured_at": 1200, "ssh": [ssh],
              "processes": [{**process, "pid": 127 + index} for index in range(12)], "network": network,
              "ssh_partial": False, "tcp_partial": False, "processes_partial": False}
    backend.observe_live.return_value = {**sample, "session_filter_confirmed": None}
    backend.observe_history.return_value = {"hours": 1, "captured_count": 1, "samples": [sample],
                                             "gaps": [(900, 1000)], "events": [], "truncated": False}
    lifecycle.history_status.return_value = {"enabled": True, "active": True}
    app = create_app({"session_key": "browser-fixture-only", "allowed_hosts": ["127.0.0.1:18777"]},
                     client=backend, lifecycle_client=lifecycle)
    app.config.update(SESSION_COOKIE_NAME="fixture-session", SESSION_COOKIE_SECURE=False)

    @app.get("/fixture-login")
    def fixture_login():
        session.update(admin=True, csrf="browser-fixture-only")
        return redirect("/observability")

    app.run(host="127.0.0.1", port=18777, debug=False)


if __name__ == "__main__":
    main()
