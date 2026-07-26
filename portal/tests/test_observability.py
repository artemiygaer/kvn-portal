import json
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path

from agent_client import AgentClientError
from app import create_app
from app.cache import WidgetCache
from app.security import hash_password


PASSWORD = "ObservabilityPassword-2026"
SECRET = "AUDIT-SHOULD-NOT-CONTAIN"


class ObservabilityAgent:
    def __init__(self):
        self.counts = {}

    def call(self, method, params):
        self.counts[method] = self.counts.get(method, 0) + 1
        if method == "dashboard.snapshot":
            sources = {}
            for name, source_method in {
                "host": "health.host", "metrics": "metrics.current",
                "containers": "stats.containers", "protocols": "protocol.stats",
                "health_summary": "health.summary", "certificates": "certificates.status",
            }.items():
                try:
                    data = ObservabilityAgent.call(self, source_method, {})
                    error = ""
                except AgentClientError:
                    data = None
                    error = "Источник временно недоступен."
                self.counts.pop(source_method, None)
                sources[name] = {
                    "data": data, "collected_at": self.now,
                    "age_seconds": 0, "stale": bool(error), "error": error,
                }
            return {
                "sources": sources, "generated_at": self.now,
                "refreshing": False, "stale": any(item["stale"] for item in sources.values()),
                "status": "stale",
            }
        if method == "health.host":
            return {"uptime": {"stdout": "up 2 days"}, "memory": {"stdout": "Mem: 100 20 80"}}
        if method == "metrics.current":
            return {"available": True, "sample": {
                "timestamp": 1_800_000_000, "cpu_percent": 17.5,
                "memory_used": 2_000_000_000, "memory_total": 8_000_000_000,
                "memory_percent": 25.0, "disk_used": 10_000_000_000,
                "disk_total": 100_000_000_000, "disk_percent": 10.0,
                "load1": 0.4, "rx_bytes_per_second": 2048,
                "tx_bytes_per_second": 1024,
            }}
        if method == "metrics.history":
            return {
                "available": True, "range_hours": params["range_hours"], "step_minutes": 5,
                "generated_at": 1_800_000_000,
                "points": [
                    {"timestamp": 1_799_999_700, "cpu_percent": 10, "memory_percent": 24,
                     "disk_percent": 10, "rx_bytes_per_second": 1024},
                    {"timestamp": 1_800_000_000, "cpu_percent": 17.5, "memory_percent": 25,
                     "disk_percent": 10, "rx_bytes_per_second": 2048},
                ],
            }
        if method == "stats.containers":
            raise AgentClientError("collector_failed: docker")
        if method == "protocol.stats":
            return {"collectors": {"xray": {"available": True, "values": {"total": 42}}}}
        if method == "certificates.status":
            return {"certificates": [{
                "target": "site", "source": "letsencrypt", "issuer": "Let's Encrypt",
                "domains": ["vpn.example.com"], "sans": ["vpn.example.com"],
                "not_after": "2030", "expiry": "ok", "san_mismatch": False,
            }]}
        if method == "logs.tail":
            return {"command": {"stdout": "first line\nmatched line\nlast line"}, "cursor": 10}
        if method == "health.summary":
            return {
                "services": {"xray": {"active": False}}, "certificates": [],
                "diagnostics": [{"reason": "Сервис Xray остановлен.", "command": "docker compose ps xray"}],
            }
        if method == "certificate.action":
            return {
                "ok": True, "action": params["action"], "target": params["target"],
                "reloads": [{"service": "nginx"}], "correlation_id": "cert-correlation",
            }
        raise AssertionError(method)


class SlowObservabilityAgent(ObservabilityAgent):
    """Фиксирует стоимость холодной сводки до оптимизации snapshot RPC."""

    def __init__(self, delay=0.03):
        super().__init__()
        self.delay = delay
        self.methods = []

    def call(self, method, params):
        self.methods.append(method)
        time.sleep(self.delay)
        return super().call(method, params)


class PortalObservabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = hash_password(PASSWORD)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.db = root / "portal.db"
        users = root / "users.json"
        users.write_text(json.dumps({"users": []}), encoding="utf-8")
        self.clock = [1_800_000_000]
        self.agent = ObservabilityAgent()
        self.agent.now = self.clock[0]
        self.app = create_app({
            "TESTING": True, "DATABASE": self.db, "USERS_FILE": users,
            "PORTAL_PATH": "/gaer", "PORTAL_NAME": "KVN",
            "ADMIN_LOGIN": "admin", "ADMIN_PASSWORD_HASH": self.password_hash,
            "PROXY_SECRET": "proxy", "HYSTERIA_SECRET": "hysteria",
            "AGENT_CLIENT": self.agent, "NOW_PROVIDER": lambda: self.clock[0],
        })
        self.client = self.app.test_client()
        self.headers = {
            "X-KVN-Proxy-Secret": "proxy", "X-Real-IP": "198.51.100.10",
            "X-Forwarded-Proto": "https",
        }
        login = self.client.get("/gaer/login", headers=self.headers)
        self.client.post(
            "/gaer/login",
            data={"login": "admin", "password": PASSWORD, "csrf_token": self.csrf(login)},
            headers=self.headers,
        )

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def csrf(response):
        return re.search(rb'name="csrf_token" value="([^"]+)"', response.data).group(1).decode()

    def test_dashboard_partial_failure_and_single_rpc_per_poll(self):
        first = self.client.get("/gaer/dashboard.json", headers=self.headers)
        self.assertEqual(first.status_code, 200)
        cards = {item["id"]: item for item in first.get_json()["cards"]}
        self.assertEqual(cards["server"]["status"], "ok")
        self.assertEqual(cards["containers"]["status"], "stale")
        self.assertEqual(cards["protocols"]["value"], "0 из 7")
        self.assertEqual(cards["cpu"]["value"], "17.5%")
        self.assertNotIn("stdout", first.get_data(as_text=True))
        self.assertNotIn("collectors", first.get_data(as_text=True))
        self.client.get("/gaer/dashboard.json", headers=self.headers)
        self.assertEqual(self.agent.counts["dashboard.snapshot"], 2)
        self.clock[0] += 61
        self.agent.now = self.clock[0]
        self.client.get("/gaer/dashboard.json", headers=self.headers)
        self.assertEqual(self.agent.counts, {"dashboard.snapshot": 3})

    def test_historical_container_restart_does_not_mark_running_service_stale(self):
        class RestartSnapshotAgent:
            def call(_self, method, _params):
                if method != "dashboard.snapshot":
                    raise AssertionError(method)
                data = {
                    "host": {"uptime": {"stdout": "up 2 days"}},
                    "metrics": self.agent.call("metrics.current", {}),
                    "containers": {"available": True, "containers": [{
                        "name": "portal", "state": "running", "health": "healthy", "restarts": 1,
                    }]},
                    "protocols": {"collectors": {}},
                    "health_summary": {"services": {}, "certificates": [], "diagnostics": []},
                    "certificates": {"certificates": []},
                }
                return {
                    "sources": {
                        name: {"data": value, "collected_at": self.clock[0], "age_seconds": 0,
                               "stale": False, "error": ""}
                        for name, value in data.items()
                    },
                    "generated_at": self.clock[0], "refreshing": False,
                    "stale": False, "status": "ok",
                }

        self.app.config["AGENT_CLIENT"] = RestartSnapshotAgent()
        response = self.client.get("/gaer/dashboard.json", headers=self.headers)
        cards = {item["id"]: item for item in response.get_json()["cards"]}

        self.assertEqual(cards["containers"]["status"], "ok")
        self.assertEqual(cards["containers"]["status_label"], "актуально")
        self.assertEqual(cards["containers"]["detail"], "Требуют внимания: 0")

    def test_cold_dashboard_is_fast_and_poll_uses_one_snapshot_rpc(self):
        # 30 мс сравнивали скорость машины, а не non-blocking контракт страницы.
        slow_agent = SlowObservabilityAgent(delay=0.2)
        slow_agent.now = self.clock[0]
        self.app.config["AGENT_CLIENT"] = slow_agent
        self.app.extensions["kvn_agent_client"] = slow_agent
        self.app.extensions["kvn_widget_cache"] = WidgetCache()

        started = time.monotonic()
        html = self.client.get("/gaer/", headers=self.headers)
        html_elapsed = time.monotonic() - started
        started = time.monotonic()
        response = self.client.get("/gaer/dashboard.json", headers=self.headers)
        json_elapsed = time.monotonic() - started

        self.assertEqual(html.status_code, 200)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(slow_agent.methods, ["dashboard.snapshot"])
        self.assertLess(html_elapsed, slow_agent.delay)
        self.assertGreaterEqual(json_elapsed, slow_agent.delay)
        self.assertLess(json_elapsed, slow_agent.delay * 3)

    def test_cache_different_keys_do_not_share_loader_lock(self):
        cache = WidgetCache()
        loader_started = threading.Event()
        release_loader = threading.Event()
        independent_done = threading.Event()

        def slow_loader():
            loader_started.set()
            release_loader.wait(timeout=2)
            return {"value": "slow"}

        slow_thread = threading.Thread(
            target=lambda: cache.get("slow", slow_loader, 100, ttl=10), daemon=True,
        )
        fast_thread = threading.Thread(
            target=lambda: (
                cache.get("independent", lambda: {"value": "fast"}, 100, ttl=10),
                independent_done.set(),
            ),
            daemon=True,
        )
        slow_thread.start()
        self.assertTrue(loader_started.wait(timeout=1))
        fast_thread.start()
        self.assertTrue(independent_done.wait(timeout=0.2))
        release_loader.set()
        slow_thread.join(timeout=1)
        fast_thread.join(timeout=1)

    def test_metrics_history_endpoint_is_bounded_and_typed(self):
        response = self.client.get(
            "/gaer/metrics/history.json?range_hours=24&step=5", headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(len(payload["points"]), 2)
        self.assertNotIn("argv", json.dumps(payload))
        self.assertEqual(
            self.client.get("/gaer/metrics/history.json?range_hours=72&step=1", headers=self.headers).status_code,
            400,
        )
        self.assertEqual(
            self.client.get("/gaer/metrics/history.json?range_hours=../../root", headers=self.headers).status_code,
            400,
        )

    def test_cache_returns_stale_value_after_local_failure(self):
        cache = WidgetCache()
        calls = []

        def success():
            calls.append(1)
            return {"value": 7}

        first = cache.get("expensive", success, 100, ttl=10)
        second = cache.get("expensive", success, 105, ttl=10)
        self.assertEqual(len(calls), 1)
        self.assertFalse(second["stale"])

        def failure():
            raise TimeoutError

        stale = cache.get("expensive", failure, 111, ttl=10)
        self.assertTrue(stale["stale"])
        self.assertEqual(stale["data"], first["data"])

    def test_logs_bounds_filter_download_and_injection(self):
        valid = self.client.get(
            "/gaer/logs?service=xray&tail=50&since=5&filter=matched",
            headers=self.headers,
        )
        self.assertEqual(valid.status_code, 200)
        self.assertIn(b"matched line", valid.data)
        self.assertNotIn(b"first line", valid.data)
        download = self.client.get(
            "/gaer/logs?service=xray&tail=2000&since=10080&download=1",
            headers=self.headers,
        )
        self.assertEqual(download.status_code, 200)
        self.assertLessEqual(len(download.data), 256 * 1024)
        for query in [
            "service=../../root&tail=50&since=5",
            "service=xray&tail=2001&since=5",
            "service=xray&tail=50&since=0",
        ]:
            self.assertEqual(self.client.get(f"/gaer/logs?{query}", headers=self.headers).status_code, 400)

    def test_health_reason_and_certificate_confirmed_action(self):
        health = self.client.get("/gaer/health", headers=self.headers)
        self.assertEqual(health.status_code, 200)
        self.assertIn("Сервис Xray остановлен".encode(), health.data)
        self.assertIn(b"docker compose ps xray", health.data)
        certs = self.client.get("/gaer/certificates", headers=self.headers)
        token = re.search(
            rb'name="action" value="renew"><input type="hidden" name="target" value="site"><input type="hidden" name="confirmation_token" value="([^"]+)"',
            certs.data,
        ).group(1).decode()
        response = self.client.post(
            "/gaer/certificates/action",
            data={
                "csrf_token": self.csrf(certs), "action": "renew", "target": "site",
                "confirmation_token": token,
            },
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)

    def test_expired_certificate_and_agent_timeout_are_localized(self):
        original_call = self.agent.call

        def expired(method, params):
            if method == "certificates.status":
                return {"certificates": [{
                    "target": "site", "source": "letsencrypt", "issuer": "Test CA",
                    "domains": ["vpn.example.com"], "sans": ["vpn.example.com"],
                    "not_after": "2020", "expiry": "expired", "san_mismatch": False,
                }]}
            return original_call(method, params)

        self.agent.call = expired
        certificates = self.client.get("/gaer/certificates", headers=self.headers)
        self.assertEqual(certificates.status_code, 200)
        self.assertIn("истёк".encode(), certificates.data)
        self.assertNotIn(b">expired<", certificates.data)

        def unavailable(_method, _params):
            raise AgentClientError("command_timeout")

        self.agent.call = unavailable
        unavailable_page = self.client.get("/gaer/logs", headers=self.headers)
        self.assertEqual(unavailable_page.status_code, 502)
        self.assertIn("Host-agent недоступен".encode(), unavailable_page.data)
        self.assertIn(b'role="alert"', unavailable_page.data)

    def test_missing_agent_secret_or_socket_returns_502(self):
        self.app.config["AGENT_CLIENT"] = None
        secret_file = Path(self.tmp.name) / "missing-agent.secret"
        self.app.config["AGENT_SECRET_FILE"] = secret_file
        self.app.config["AGENT_SOCKET"] = Path(self.tmp.name) / "missing-control.sock"

        missing_secret = self.client.get("/gaer/users", headers=self.headers)
        self.assertEqual(missing_secret.status_code, 502)
        self.assertIn("Host-agent недоступен".encode(), missing_secret.data)

        secret_file.write_text("a" * 64, encoding="utf-8")
        missing_socket = self.client.get("/gaer/users", headers=self.headers)
        self.assertEqual(missing_socket.status_code, 502)
        self.assertIn("Host-agent недоступен".encode(), missing_socket.data)

    def test_internal_health_is_light_and_does_not_call_agent(self):
        before = dict(self.agent.counts)
        response = self.client.get("/internal/health", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"ok": True})
        self.assertEqual(self.agent.counts, before)

    def test_audit_filter_pagination_export_retention_and_redaction(self):
        storage = self.app.extensions["kvn_storage"]
        for index in range(150):
            storage.audit(
                "admin", "198.51.100.10", "fixture.action",
                "success" if index % 2 else "failed",
                f"index={index} password={SECRET}", now=self.clock[0] + index,
            )
        storage.prune_audit(100)
        page = storage.list_audit(action="fixture.action", page=1, page_size=50)
        second = storage.list_audit(action="fixture.action", page=2, page_size=50)
        self.assertEqual(page["total"], 100)
        self.assertEqual(len(page["events"]), 50)
        self.assertEqual(len(second["events"]), 50)
        html = self.client.get("/gaer/audit?action=fixture.action", headers=self.headers)
        export = self.client.get("/gaer/audit/export.csv?action=fixture.action", headers=self.headers)
        self.assertEqual(html.status_code, 200)
        self.assertEqual(export.status_code, 200)
        self.assertNotIn(SECRET.encode(), self.db.read_bytes())
        self.assertNotIn(SECRET.encode(), html.data)
        self.assertNotIn(SECRET.encode(), export.data)
        self.assertIn(b"correlation_id", export.data)

    def test_audit_page_humanizes_known_event_and_json_detail(self):
        storage = self.app.extensions["kvn_storage"]
        storage.audit(
            "admin", "198.51.100.10", "service.action", "success",
            json.dumps({"service": "nginx", "action": "restart", "health": True}),
            now=1_782_000_000,
        )
        page = self.client.get("/gaer/audit", headers=self.headers)
        self.assertEqual(page.status_code, 200)
        for marker in ["Управление сервисом", "успешно", "перезапуск", "проверка: да", "UTC"]:
            self.assertIn(marker.encode(), page.data)
        self.assertNotIn(b'{"service"', page.data)


if __name__ == "__main__":
    unittest.main()
