import json
import re
import tempfile
import unittest
from pathlib import Path

from app import create_app
from agent_client import AgentClientError
from app.security import hash_password


class FakeAgent:
    def __init__(self, backup_dir="/backup"):
        self.backup_dir = backup_dir
        self.calls = []
        self.fail_network = False

    def call(self, method, _params):
        self.calls.append((method, dict(_params)))
        if method == "dashboard.snapshot":
            data = {
                "host": {"uptime": {"stdout": "up 1 day"}},
                "metrics": {"available": True, "sample": {"cpu_percent": 10, "memory_percent": 24, "disk_percent": 42, "load1": 0.1}},
                "containers": {"available": True, "containers": []},
                "protocols": {"collectors": {
                    "hysteria": {"available": True, "values": {"users": 3, "online": 2, "tx": 1200, "rx": 800}},
                    "amneziawg": {"available": True, "values": {"peers": 4}},
                    "wireguard": {"available": True, "values": {"peers": 2}},
                }},
                "health_summary": {"services": {
                    "xray": {"active": True}, "hysteria": {"active": True}, "telemt": {"active": True},
                    "mtg": {"active": False}, "amneziawg": {"active": True}, "wireguard": {"active": True}, "ocserv": {"active": True},
                }, "certificates": [], "diagnostics": []},
                "certificates": {"certificates": [
                    {"target": "site", "expiry": "ok", "expires_days": 90, "source": "letsencrypt"},
                    {"target": "ocserv", "expiry": "warning", "expires_days": 20, "source": "letsencrypt"},
                ]},
            }
            return {
                "sources": {
                    name: {"data": value, "collected_at": 1_800_000_000, "age_seconds": 0, "stale": False, "error": ""}
                    for name, value in data.items()
                },
                "generated_at": 1_800_000_000, "refreshing": False, "stale": False, "status": "ok",
            }
        if method == "network.topology":
            if self.fail_network:
                raise AgentClientError("fixture unavailable")
            systems = ["tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg", "amneziawg", "wireguard", "ocserv"]
            return {
                "revision": "safe-revision",
                "ingress": [{"id": "tcp-443-sni", "port": 443, "protocol": "tcp", "role": "nginx SNI router"}],
                "routes": [{"system": "tls", "default": "example.test", "aliases": ["example.test"], "dest": "xray:443", "kind": "nginx-sni"}],
                "protocols": [{
                    "system": system, "label": system, "enabled": True,
                    "service": "xray" if system.startswith(("tls", "reality")) else system,
                    "ingress": ["tcp-443-sni"], "transport": "safe transport", "backend": f"{system}:443",
                    "backend_kind": "docker", "apply_kind": "reload", "users": {"assigned": 0, "enabled": 0},
                    "sni": {"scope": "not_applicable", "default": "", "aliases": [], "aliases_count": 0, "target": "", "server_names": []},
                    "sni_scope": "not_applicable", "read_only": True,
                    "facts": ({
                        "hysteria": {"public_transport": "443/udp", "certificate_target": "site"},
                        "telemt": {"direct_transport": "2446/tcp", "sni_scope": "service"},
                        "mtg": {"direct_transport": "2447/tcp", "sni_scope": "service"},
                        "amneziawg": {"public_transport": "51820/udp", "interface": "awg0", "apply_path": "awg syncconf"},
                        "wireguard": {"public_transport": "51821/udp", "interface": "wg0", "apply_path": "wg syncconf"},
                        "ocserv": {"dtls_transport": "4443/udp", "certificate_target": "ocserv"},
                    }.get(system, {})),
                    "settings": {"path": "/api/v1/data", "xhttp_mode": "stream-one"} if system == "reality-xhttp" else {},
                } for system in systems],
                "infrastructure": [{"id": "nginx", "kind": "docker", "role": "router"}],
            }
        if method == "domain.advice":
            return {
                "zone": _params["zone"], "status": "needs_attention", "timeout_seconds": 4.0, "hostname_count": 2,
                "hostnames": [
                    {"role": "site", "hostname": _params["zone"], "dns": "ok", "tls": "ok", "cert_match": "match", "same_server": True, "recommendation": "ready"},
                    {"role": "wildcard", "hostname": f"kvn-wildcard-check.{_params['zone']}", "dns": "unavailable", "tls": "not_checked", "cert_match": "not_checked", "same_server": False, "recommendation": "wildcard-absent"},
                ],
                "protocols": [
                    {"system": "reality-xhttp", "same_server": True, "recommendation": "external-cover-required"},
                    {"system": "telemt", "same_server": False, "recommendation": "service-level-camouflage"},
                    {"system": "wireguard", "same_server": False, "recommendation": "no-sni"},
                ],
            }
        if method == "health.host":
            return {"uptime": {"stdout": "up 1 day"}}
        if method == "protocol.apply":
            return {"changed": True, "revision": "b" * 64, "plan": {"changed": True}, "apply": {"outcome": "applied", "reconcile_required": False}, "protocol": {"system": "reality-xhttp", "xhttp_mode": _params["mode"]}}
        if method == "sni.apply":
            return {"changed": True, "revision": "b" * 64, "plan": {"changed": True}, "apply": {"outcome": "applied", "reconcile_required": False}}
        if method == "metrics.current":
            return {"available": True, "sample": {"cpu_percent": 10, "memory_percent": 24, "disk_percent": 42, "load1": 0.1}}
        if method == "metrics.history":
            return {"available": False, "range_hours": 24, "step_minutes": 5, "points": []}
        if method == "stats.containers":
            return {"available": True, "containers": []}
        if method == "protocol.stats":
            return {"hysteria": {"sessions": 1}}
        if method == "health.summary":
            return {
                "services": {
                    "nginx": {"active": True}, "portal": {"active": True}, "xray": {"active": True},
                    "hysteria": {"active": True}, "telemt": {"active": True}, "mtg": {"active": True},
                    "ocserv": {"active": True}, "amneziawg": {"active": True}, "wireguard": {"active": True}, "agent": {"active": True},
                },
                "certificates": [],
                "diagnostics": [],
            }
        if method == "certificates.status":
            return {"certificates": []}
        if method == "logs.tail":
            return {
                "service": _params["service"],
                "tail": _params["tail"],
                "since_minutes": _params["since_minutes"],
                "cursor": 1_800_000_000_000,
                "command": {
                    "returncode": 0,
                    "stdout": "match line\nskip line\n",
                    "stderr": "",
                    "duration_ms": 7,
                },
            }
        if method == "backup.list":
            return {
                "available": True,
                "directory": str(self.backup_dir),
                "backups": [{
                    "name": "kvn-vpn-backup-20260702-test.tar",
                    "size": 12,
                    "mtime": 1_800_000_000,
                    "readable": True,
                }],
            }
        if method == "project.backup":
            return {
                "ok": True,
                "action": "backup",
                "unit": "kvn-project-backup-test",
                "journal_command": "journalctl -u kvn-project-backup-test -n 200 --no-pager",
                "command": {"stderr": ""},
                "correlation_id": "backup-test",
                "backup_dir": str(self.backup_dir),
            }
        if method == "maintenance.commands":
            return {"commands": [
                {
                    "id": "compose_ps",
                    "title": "Docker Compose ps",
                    "group": "Docker",
                    "description": "Состояние контейнеров проекта.",
                    "requires_confirmation": False,
                },
                {
                    "id": "kvn_reconcile",
                    "title": "Согласование состояния",
                    "group": "KVN",
                    "description": "Повторно применяет целевое состояние.",
                    "requires_confirmation": True,
                },
            ]}
        if method == "maintenance.run":
            return {
                "ok": True,
                "id": _params["command"],
                "title": "Docker Compose ps",
                "group": "Docker",
                "description": "Состояние контейнеров проекта.",
                "requires_confirmation": False,
                "correlation_id": "maintenance-test",
                "command": {
                    "argv": ["docker", "compose", "ps"],
                    "returncode": 0,
                    "stdout": "nginx-front running\n",
                    "stderr": "",
                    "duration_ms": 5,
                },
            }
        if method == "shell.open":
            return {
                "ok": True,
                "shell_id": "c" * 32,
                "alive": True,
                "exit_code": None,
                "output": "root@kvn:/srv/kvn# ",
                "limits": {"idle_seconds": 900, "absolute_seconds": 3600, "max_write_bytes": 4096},
            }
        if method == "shell.read":
            return {"ok": True, "shell_id": _params["shell_id"], "alive": True, "exit_code": None, "output": ""}
        if method == "shell.write":
            return {"ok": True, "shell_id": _params["shell_id"], "alive": True, "written": len(_params.get("data", ""))}
        if method == "shell.resize":
            return {"ok": True, "shell_id": _params["shell_id"], "alive": True, "rows": _params.get("rows", 24), "cols": _params.get("cols", 100)}
        if method == "shell.close":
            return {"ok": True, "shell_id": _params["shell_id"], "alive": False, "exit_code": 0}
        raise AssertionError(f"Неожиданный метод: {method}")


class PortalUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.static = Path("app/static")
        cls.templates = Path("app/templates")
        cls.password_hash = hash_password("VisualPassword-2026")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.backup_dir = root / "backup"
        self.backup_dir.mkdir()
        (self.backup_dir / "kvn-vpn-backup-20260702-test.tar").write_bytes(b"backup-bytes")
        self.agent = FakeAgent(self.backup_dir)
        users = root / "users.json"
        users.write_text(json.dumps({"users": []}), encoding="utf-8")
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE": root / "portal.db",
                "USERS_FILE": users,
                "PORTAL_PATH": "/gaer",
                "PORTAL_NAME": "Тестовый портал",
                "ADMIN_LOGIN": "admin",
                "ADMIN_PASSWORD_HASH": self.password_hash,
                "PROXY_SECRET": "proxy-secret-value",
                "HYSTERIA_SECRET": "hysteria-secret-value",
                "BUILD_ID": "test-build-20260628",
                "NOW_PROVIDER": lambda: 1_800_000_000,
                "AGENT_CLIENT": self.agent,
                "BACKUP_DIR": self.backup_dir,
            }
        )
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy-secret-value",
            "X-Real-IP": "192.0.2.10",
            "X-Forwarded-Proto": "https",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def login(self):
        page = self.client.get("/gaer/login", headers=self.headers)
        csrf = self.csrf(page)
        return self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": "VisualPassword-2026", "csrf_token": csrf},
            headers=self.headers,
        )

    @staticmethod
    def csrf(response):
        match = re.search(rb'name="csrf_token" value="([^"]*)"', response.data)
        return match.group(1).decode("ascii") if match else ""

    def test_login_has_labels_reveal_alert_and_no_js_form(self):
        response = self.client.get("/gaer/login", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        for marker in [b'<label for="login">', b'<label for="password">', b"data-password-toggle", b'method="post"']:
            self.assertIn(marker, response.data)
        self.assertNotIn(b"onsubmit=", response.data)
        static_url = re.search(rb'href="([^"]*style\.css)"', response.data).group(1)
        self.assertEqual(static_url, b"/gaer/static/style.css")

    def test_authenticated_shell_has_landmarks_skip_link_dialog_and_live_region(self):
        self.assertEqual(self.login().status_code, 302)
        response = self.client.get("/gaer/", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        for marker in [b'class="skip-link"', b'<aside class="sidebar"', b'<main id="content"', b'<dialog class="confirm-dialog"', b'aria-live="polite"', b'data-dashboard']:
            self.assertIn(marker, response.data)
        self.assertIn("IP входа".encode(), response.data)
        self.assertIn(b"192.0.2.10", response.data)
        self.assertIn(b"test-build-20260628", response.data)
        self.assertGreaterEqual(response.data.count(b'action="/gaer/logout"'), 2)
        self.assertNotIn(b"<pre>", response.data)
        self.assertIn(b"data-history-range", response.data)
        self.assertIn(b"data-chart", response.data)

    def test_network_page_and_json_show_all_protocols_from_cached_dashboard(self):
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/gaer/network", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        for marker in [b'data-network-zone="ingress"', b'data-network-zone="routing"', b'data-network-zone="protocols"']:
            self.assertIn(marker, page.data)
        self.assertEqual(page.data.count(b"data-protocol-card"), 9)
        payload = self.client.get("/gaer/network.json", headers=self.headers).get_json()
        self.assertEqual(len(payload["protocols"]), 9)
        by_system = {item["system"]: item for item in payload["protocols"]}
        self.assertEqual(by_system["hysteria"]["runtime"]["counters"]["online"], 2)
        self.assertEqual(by_system["amneziawg"]["facts"]["public_transport"], "51820/udp")
        self.assertEqual(by_system["wireguard"]["facts"]["public_transport"], "51821/udp")
        self.assertEqual(by_system["ocserv"]["runtime"]["certificate"]["expiry"], "warning")
        for item in payload["protocols"]:
            self.assertIn("change_url", item)
            self.assertTrue(item["change_url"].startswith("/gaer/"))
        self.assertEqual({method for method, _params in self.agent.calls if method.startswith("dashboard")}, {"dashboard.snapshot"})

    def test_network_xray_editor_uses_typed_rpc_and_secret_free_audit(self):
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/gaer/network", headers=self.headers)
        for marker in [b"XHTTP mode", b"XHTTP path", b"Reality target", b"serverNames", b"stream-one", b"packet-up"]:
            self.assertIn(marker, page.data)
        response = self.client.post(
            "/gaer/network/protocol/apply",
            data={"csrf_token": self.csrf(page), "revision": "a" * 64, "mode": "stream-up", "backend": "attacker:443"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        method, params = self.agent.calls[-1]
        self.assertEqual(method, "protocol.apply")
        self.assertEqual(set(params), {"action", "system", "mode", "revision"})
        audit = json.dumps(self.app.extensions["kvn_storage"].list_audit(), ensure_ascii=False)
        self.assertIn("protocol.set-xhttp-mode", audit)
        for forbidden in ["attacker:443", "private_key", "root_password", "uuid"]:
            self.assertNotIn(forbidden, audit)

    def test_domain_advisor_shows_safe_policy_without_network_identity(self):
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/gaer/network?zone=gaer.loc.cc", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        for marker in [b"data-domain-advice", b"external-cover-required", b"service-level-camouflage", b"no-sni", b"wildcard-absent"]:
            self.assertIn(marker, page.data)
        for forbidden in [b"203.0.113.10", b"private_key", b"password", b"BEGIN CERTIFICATE"]:
            self.assertNotIn(forbidden, page.data)

    def test_network_page_keeps_visible_error_state_when_agent_is_unavailable(self):
        self.assertEqual(self.login().status_code, 302)
        self.agent.fail_network = True
        page = self.client.get("/gaer/network", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Host-agent временно недоступен".encode(), page.data)
        self.assertIn(b'data-network-zone="ingress"', page.data)

    def test_assets_are_local_and_below_budget(self):
        assets = [self.static / "style.css", *sorted(self.static.glob("*.js"))]
        self.assertLessEqual(sum(item.stat().st_size for item in assets), 106 * 1024)
        base = (self.static / "base.js").stat().st_size
        export = (self.static / "user-export.js").stat().st_size
        self.assertLessEqual(
            base + export + (self.static / "users.js").stat().st_size,
            30 * 1024,
        )
        self.assertLessEqual(
            base + export + (self.static / "update.js").stat().st_size,
            30 * 1024,
        )
        content = "\n".join(item.read_text(encoding="utf-8") for item in assets)
        self.assertNotRegex(content, r"https?://|@import|url\s*\(")

    def test_staged_update_markup_and_client_states_are_accessible(self):
        settings = (self.templates / "settings.html").read_text(encoding="utf-8")
        script = (self.static / "update.js").read_text(encoding="utf-8")
        css = (self.static / "style.css").read_text(encoding="utf-8")
        prepare_form = settings.split("data-update-prepare", 1)[1].split("</form>", 1)[0]
        self.assertNotIn("root_password", prepare_form)
        for marker in [
            "project_release_check", "project_release_prepare",
            "project_update_prepare", "project_update_start", "project_update_discard",
            "data-update-progress-bar", "data-update-cancel", "data-update-retry",
            'aria-live="polite"', 'aria-valuenow="0"', 'name="prepared_id"',
            'data-confirm="Запустить обновление проекта"',
        ]:
            self.assertIn(marker, settings)
        update_script = script
        for state in ["idle", "uploading", "verifying", "ready", "error", "aborted"]:
            self.assertIn(f'"{state}"', update_script)
        for marker in [
            "XMLHttpRequest", "progressEvent.loaded", "selectedFile.size", "textContent", "window.location.reload()",
            'X-CSRF-Token', 'X-KVN-Archive-Name', 'application/octet-stream', "xhr.send(selectedFile)",
            '"checking"', '"preparing"', "data-github-progress",
        ]:
            self.assertIn(marker, update_script)
        self.assertNotIn("innerHTML", update_script)
        for marker in [".update-progress", ".update-ready-card", ".update-meta", ".update-actions"]:
            self.assertIn(marker, css)

    def test_polling_pauses_and_uses_bounded_backoff(self):
        script = "\n".join(
            (self.static / name).read_text(encoding="utf-8")
            for name in ("dashboard.js", "logs.js", "root-shell.js")
        )
        for marker in ["visibilitychange", "document.hidden", "Math.min(240000", "60000 * (2 ** failures)", "if (polling) return"]:
            self.assertIn(marker, script)
        self.assertIn("failures = Math.min(failures + 1, 2)", script)
        self.assertIn('payload.status === "loading" ? msg.snapshotLoading', script)
        self.assertNotIn("payload.refreshing ? msg.snapshotLoading", script)
        for marker in ["scheduleLogs", "logPaused", 'Accept": "application/json"', "cache: \"no-store\"", "window.setTimeout(refreshLogs, 20000)"]:
            self.assertIn(marker, script)
        self.assertIn("window.setTimeout(pollShell, data.output ? 80 : 160)", script)
        self.assertIn("Math.min(1600, 240 + readFailures * 120)", script)
        self.assertNotIn("DOMParser", script)
        self.assertNotIn('Accept": "text/html"', script)

    def test_logs_json_requires_session_and_validates_bounds(self):
        unauth = self.client.get("/gaer/logs.json", headers=self.headers)
        self.assertEqual(unauth.status_code, 302)
        self.assertTrue(unauth.headers["Location"].endswith("/gaer/login"))
        self.assertEqual(self.login().status_code, 302)
        invalid_urls = [
            "/gaer/logs.json?service=unknown",
            "/gaer/logs.json?tail=49",
            "/gaer/logs.json?since=0",
            "/gaer/logs.json?filter=" + ("x" * 65),
        ]
        for url in invalid_urls:
            response = self.client.get(url, headers=self.headers)
            self.assertEqual(response.status_code, 400, url)

    def test_logs_json_contract_and_html_refresh_metadata(self):
        self.assertEqual(self.login().status_code, 302)
        response = self.client.get("/gaer/logs.json?service=nginx&tail=50&since=1&filter=match", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        for key in ["service", "tail", "since", "filter", "cursor", "generated_at", "content", "truncated", "command"]:
            self.assertIn(key, payload)
        self.assertEqual(payload["service"], "nginx")
        self.assertEqual(payload["tail"], 50)
        self.assertEqual(payload["since"], 1)
        self.assertEqual(payload["filter"], "match")
        self.assertEqual(payload["content"], "match line")
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["command"]["source"], "docker compose logs")
        self.assertNotIn("argv", payload["command"])
        self.assertNotIn("stdout", payload["command"])

        page = self.client.get("/gaer/logs?service=nginx&tail=50&since=1&filter=match", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        for marker in [b"data-logs-endpoint", b"data-log-status", b"data-log-updated", b"data-log-command", b"/gaer/logs.json"]:
            self.assertIn(marker, page.data)

    def test_backup_page_launches_agent_and_downloads_only_safe_archives(self):
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/gaer/backups", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"kvn-vpn-backup-20260702-test.tar", page.data)
        self.assertIn(b"/gaer/backups/files/kvn-vpn-backup-20260702-test.tar", page.data)

        download = self.client.get(
            "/gaer/backups/files/kvn-vpn-backup-20260702-test.tar",
            headers=self.headers,
        )
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.data, b"backup-bytes")
        self.assertEqual(download.headers["Content-Type"], "application/x-tar")
        download.close()

        denied = self.client.get("/gaer/backups/files/kvn-vpn-deploy.tar.gz", headers=self.headers)
        self.assertEqual(denied.status_code, 404)

        response = self.client.post(
            "/gaer/backups",
            data={"csrf_token": self.csrf(page)},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"kvn-project-backup-test", response.data)
        self.assertEqual(self.agent.calls[-1][0], "project.backup")
        self.assertEqual(self.agent.calls[-1][1], {})

    def test_terminal_page_runs_allowlisted_command_and_confirms_mutation(self):
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/gaer/terminal", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        for marker in ["Команды обслуживания", "Docker Compose ps", "Согласование состояния", "data-confirm"]:
            self.assertIn(marker.encode(), page.data)
        for marker in ["Root shell", "data-root-shell", "data-shell-open-form", "Пароль root"]:
            self.assertNotIn(marker.encode(), page.data)
        self.assertNotIn(b'name="argv"', page.data)
        self.assertNotIn(b'name="shell"', page.data)

        response = self.client.post(
            "/gaer/terminal",
            data={"csrf_token": self.csrf(page), "command": "compose_ps"},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"nginx-front running", response.data)
        run_calls = [call for call in self.agent.calls if call[0] == "maintenance.run"]
        self.assertEqual(len(run_calls), 1)
        self.assertEqual(run_calls[0][1]["command"], "compose_ps")
        self.assertNotIn("argv", run_calls[0][1])

    def test_root_shell_json_opens_writes_reads_and_closes(self):
        self.assertEqual(self.login().status_code, 302)
        page = self.client.get("/gaer/shell", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        for marker in ["Консоль", "Root shell", "data-root-shell", "data-shell-open-form", "Пароль root"]:
            self.assertIn(marker.encode(), page.data)
        csrf = self.csrf(page)
        json_headers = {**self.headers, "X-CSRF-Token": csrf}

        opened = self.client.post(
            "/gaer/terminal/shell/open",
            json={"root_password": "RootPassword-2026", "rows": 24, "cols": 100},
            headers=json_headers,
        )
        self.assertEqual(opened.status_code, 200)
        payload = opened.get_json()
        self.assertEqual(payload["shell_id"], "c" * 32)
        self.assertNotIn("RootPassword-2026", opened.get_data(as_text=True))

        shell_open_call = [call for call in self.agent.calls if call[0] == "shell.open"][-1]
        self.assertEqual(shell_open_call[1]["root_password"], "RootPassword-2026")
        self.assertRegex(shell_open_call[1]["session_owner"], r"^[0-9a-f]{64}$")

        for endpoint, body in [
            ("write", {"shell_id": "c" * 32, "data": "id\n"}),
            ("read", {"shell_id": "c" * 32}),
            ("resize", {"shell_id": "c" * 32, "rows": 30, "cols": 120}),
            ("close", {"shell_id": "c" * 32}),
        ]:
            response = self.client.post(f"/gaer/terminal/shell/{endpoint}", json=body, headers=json_headers)
            self.assertEqual(response.status_code, 200, endpoint)
            self.assertTrue(response.get_json()["ok"])

    def test_confirmation_dialog_returns_focus_after_cancel(self):
        script = (self.static / "base.js").read_text(encoding="utf-8")
        for marker in ["event.submitter", "pendingTrigger", "pendingTrigger.focus()"]:
            self.assertIn(marker, script)

    def test_destructive_forms_name_action_and_object(self):
        for filename in ["user_detail.html", "services.html", "certificates.html"]:
            content = (self.templates / filename).read_text(encoding="utf-8")
            self.assertIn("data-confirm", content)
            self.assertIn("data-object", content)
            self.assertIn('method="post"', content)

    def test_css_has_focus_dark_reduced_motion_and_mobile_navigation(self):
        css = (self.static / "style.css").read_text(encoding="utf-8")
        for marker in [":focus-visible", 'data-theme="dark"', "prefers-color-scheme: dark", "prefers-reduced-motion: reduce", ".mobile-nav", "min-height: 2.75rem"]:
            self.assertIn(marker, css)

    def test_action_hierarchy_and_private_result_panel_are_explicit(self):
        css = (self.static / "style.css").read_text(encoding="utf-8")
        for marker in [".action-group", ".action-tile", ".warning", ".quiet", ".danger-actions", ".private-panel"]:
            self.assertIn(marker, css)
        certificates = (self.templates / "certificates.html").read_text(encoding="utf-8")
        services = (self.templates / "services.html").read_text(encoding="utf-8")
        result = (self.templates / "user_result.html").read_text(encoding="utf-8")
        self.assertIn("certificate-actions", certificates)
        self.assertIn("service-actions", services)
        self.assertIn("private-panel", result)
        self.assertNotIn('class="alert secret-result"', result)

    def test_mobile_navigation_contains_every_primary_section(self):
        template = (self.templates / "base.html").read_text(encoding="utf-8")
        mobile = template.split('<nav class="mobile-nav"', 1)[1].split("</nav>", 1)[0]
        navigation = (self.templates.parent / "navigation.py").read_text(encoding="utf-8")
        self.assertIn("navigation_links(navigation_items)", mobile)
        for endpoint in ["dashboard", "users_list", "services_list", "logs_view", "root_shell_view", "terminal_view", "certificates_view", "health_view", "audit_view", "backups_view"]:
            self.assertIn(f'"endpoint": "{endpoint}"', navigation)

    def test_error_conflict_and_result_states_have_accessible_status(self):
        expected = {
            "error.html": ['role="alert"', "error-title", "Вернуться"],
            "conflict.html": ['role="alert"', "conflict-title", "Загрузить актуальные данные"],
            "user_result.html": ['role="status"', "result-title"],
            "service_result.html": ['role="status"', "service-result-title"],
            "certificate_result.html": ['role="status"', "certificate-result-title"],
            "update_result.html": ['role="status"', "update-result-title"],
            "backup_result.html": ['role="status"', "backup-result-title"],
        }
        for filename, markers in expected.items():
            content = (self.templates / filename).read_text(encoding="utf-8")
            for marker in markers:
                self.assertIn(marker, content)

    def test_user_visible_copy_has_no_english_placeholders(self):
        combined = "\n".join(path.read_text(encoding="utf-8") for path in self.templates.glob("*.html"))
        for marker in [">Health<", ">Issuer<", ">Correlation<", "Использовать default", ">OK<", "безопасный fallback", "Runtime не полностью"]:
            self.assertNotIn(marker, combined)
        result = (self.templates / "user_result.html").read_text(encoding="utf-8")
        for marker in ["Приватный ключ AmneziaWG", "Токен подписки", "резервный режим"]:
            self.assertIn(marker, result)
        service_result = (self.templates / "service_result.html").read_text(encoding="utf-8")
        self.assertIn("перезапуск", service_result)

    def test_service_guidance_is_catalog_driven_and_has_no_template_kind_lists(self):
        catalog = (self.templates.parent / "service_catalog.py").read_text(
            encoding="utf-8",
        )
        macro = (self.templates / "_service_guidance.html").read_text(
            encoding="utf-8",
        )
        detail = (self.templates / "user_detail.html").read_text(
            encoding="utf-8",
        )
        services = (self.templates / "services.html").read_text(
            encoding="utf-8",
        )
        user_form = (self.templates / "user_form.html").read_text(
            encoding="utf-8",
        )
        settings = (self.templates / "settings.html").read_text(
            encoding="utf-8",
        )
        project = (self.templates / "project_info.html").read_text(
            encoding="utf-8",
        )
        for marker in [
            "SYSTEM_ORDER", "MANAGED_SERVICE_ORDER", "GUIDANCE_TOPICS",
            "FILE_KIND_CATALOG", "51820/udp", "51821/udp", "IP SAN",
        ]:
            self.assertIn(marker, catalog)
        for marker in [
            "data-service-guide", "Порты", "Клиенты", "Применение",
            "Быстрая диагностика", "data-service-catalog", "tabindex=\"0\"",
        ]:
            self.assertIn(marker, macro)
        for marker in [
            "client_file_group(file.kind)", "is_qr_file(file.kind)",
        ]:
            self.assertIn(marker, detail)
        for marker in [
            "service_help(guide)", "guide.host_service",
        ]:
            self.assertIn(marker, services)
        self.assertIn("guide.default_user_enabled", user_form)
        self.assertIn("service_help(service_guide(system), true)", settings)
        self.assertIn("catalog_table(service_catalog.values())", project)
        combined = "\n".join((detail, services, user_form, settings))
        for duplicate in [
            "file.kind in [", "host_services=[", "credential_scope ==",
            "system not in ['amneziawg'",
        ]:
            self.assertNotIn(duplicate, combined)


if __name__ == "__main__":
    unittest.main()
