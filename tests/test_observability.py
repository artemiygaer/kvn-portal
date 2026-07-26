import datetime
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from portal.agent import AgentDispatcher, CommandResult, DashboardSnapshotCache
from portal.agent_protocol import ProtocolError
from portal.control import KvnControl
from portal.metrics import (
    HostMetricsCollector,
    MetricsQueryError,
    MetricsSampler,
    MetricsStore,
    RETENTION_SECONDS,
)


class ObservabilityControl:
    def observability_config(self):
        return {"hysteria_secret": "internal-only"}

    def certificate_status(self):
        return {
            "certificates": [{
                "target": "site", "san_mismatch": True,
                "domains": ["vpn.example.com"], "sans": ["other.example.com"],
            }]
        }


class ObservabilityRunner:
    def __init__(self, timeout_telemt=False, inactive_xray=False):
        self.calls = []
        self.timeout_telemt = timeout_telemt
        self.inactive_xray = inactive_xray

    def run(self, argv, *, timeout=30, max_output=128 * 1024):
        self.calls.append((tuple(argv), timeout, max_output))
        joined = " ".join(argv)
        if "statsquery" in argv:
            stdout = '{"stat":[{"name":"uplink","value":"12"},{"name":"downlink","value":"30"}]}'
        elif argv[:3] == ["docker", "exec", "hysteria"]:
            stdout = '{"Alice":{"tx":50,"rx":70}}' if argv[-1].endswith("/traffic") else '{"Alice":2}'
        elif argv and argv[0] == "curl":
            if self.timeout_telemt:
                raise ProtocolError("command_timeout", "timeout")
            stdout = "connections 4\nbytes 100\n"
        elif "occtl" in argv:
            stdout = '{"active":3,"total":20}'
        elif argv and argv[0] in {"awg", "wg"}:
            now = int(datetime.datetime.now().timestamp())
            stdout = f"private\tpublic\t51820\toff\npeer\tpsk\tendpoint\t10.0.0.2/32\t{now}\t100\t200\t25\n"
        elif "nginx_status" in joined:
            stdout = "Active connections: 5\nserver accepts handled requests\n 10 10 20\n"
        elif argv[:2] == ["docker", "inspect"]:
            stdout = "".join(f"/{name}\trunning\tnone\t0\n" for name in argv[4:])
        elif argv[:2] == ["docker", "stats"]:
            stdout = "".join(json.dumps({"Name": name, "CPUPerc": "0.1%"}) + "\n" for name in argv[5:])
        elif "ps" in argv:
            service = argv[-1]
            state = "exited" if self.inactive_xray and service == "xray" else "running"
            stdout = json.dumps({"Service": service, "State": state})
        else:
            stdout = "active\n"
        return CommandResult(tuple(argv), 0, stdout, "", 1)


class ProtocolCollectorTests(unittest.TestCase):
    def test_dashboard_snapshot_is_single_flight_cached_and_bounded(self):
        runner = ObservabilityRunner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, ObservabilityControl())

        cold = dispatcher._dashboard_snapshot({})
        concurrent = dispatcher._dashboard_snapshot({})
        self.assertEqual(cold["status"], "loading")
        self.assertTrue(cold["refreshing"])
        self.assertTrue(concurrent["refreshing"])
        self.assertTrue(dispatcher.dashboard_cache.wait(timeout=2))
        ready = dispatcher._dashboard_snapshot({})
        command_count = len(runner.calls)
        cached = dispatcher._dashboard_snapshot({})

        self.assertEqual(ready["status"], "ok")
        self.assertFalse(ready["stale"])
        self.assertEqual(len(runner.calls), command_count)
        self.assertEqual(command_count, 16)
        self.assertEqual(
            len([call for call, _timeout, _max in runner.calls if call[:2] == ("docker", "inspect")]),
            1,
        )
        self.assertLessEqual(max(timeout for _call, timeout, _max in runner.calls), 30)
        self.assertNotIn("internal-only", json.dumps(cached))

    def test_dashboard_snapshot_preserves_last_data_after_collector_failure(self):
        clock = [100]
        failing = [False]

        def loader(name, _context):
            if name == "protocols" and failing[0]:
                raise TimeoutError
            return {"source": name, "revision": clock[0]}

        cache = DashboardSnapshotCache(loader, now_provider=lambda: clock[0])
        cache.get()
        self.assertTrue(cache.wait(timeout=1))
        first = cache.get()
        first_collected = first["sources"]["protocols"]["collected_at"]
        clock[0] += 901
        failing[0] = True
        cache.get()
        self.assertTrue(cache.wait(timeout=1))
        stale = cache.get()["sources"]["protocols"]

        self.assertTrue(stale["stale"])
        self.assertEqual(stale["collected_at"], first_collected)
        self.assertEqual(stale["data"]["revision"], 100)
        self.assertEqual(stale["error"], "Источник временно недоступен.")

    def test_background_refresh_keeps_last_successful_snapshot_current(self):
        clock = [100]
        block_refresh = [False]
        refresh_started = threading.Event()
        release_refresh = threading.Event()

        def loader(name, _context):
            if block_refresh[0] and name == "host":
                refresh_started.set()
                release_refresh.wait(timeout=1)
            return {"source": name, "revision": clock[0]}

        cache = DashboardSnapshotCache(loader, now_provider=lambda: clock[0])
        cache.get()
        self.assertTrue(cache.wait(timeout=1))

        clock[0] += 61
        block_refresh[0] = True
        refreshing = cache.get()
        self.assertTrue(refresh_started.wait(timeout=1))
        refreshing = cache.get()

        self.assertTrue(refreshing["refreshing"])
        self.assertFalse(refreshing["stale"])
        self.assertEqual(refreshing["status"], "ok")
        self.assertFalse(refreshing["sources"]["host"]["stale"])
        self.assertEqual(refreshing["sources"]["host"]["data"]["revision"], 100)

        release_refresh.set()
        self.assertTrue(cache.wait(timeout=1))

    def test_protocol_fixture_matrix_is_aggregated_without_identifiers(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), ObservabilityRunner(), ObservabilityControl())
        collectors = dispatcher._protocol_stats({})["collectors"]
        for name in ["xray", "hysteria", "telemt", "ocserv", "amneziawg", "wireguard", "nginx"]:
            self.assertTrue(collectors[name]["available"], name)
        self.assertEqual(collectors["xray"]["values"]["total"], 42)
        self.assertEqual(collectors["hysteria"]["values"], {"users": 1, "online": 2, "tx": 50, "rx": 70})
        self.assertEqual(collectors["amneziawg"]["values"]["peers"], 1)
        self.assertEqual(collectors["wireguard"]["values"]["peers"], 1)
        self.assertEqual(collectors["nginx"]["values"]["active"], 5)
        self.assertEqual(collectors["mtg"]["error"], "container_metrics_only")
        self.assertNotIn("Alice", json.dumps(collectors))
        self.assertNotIn("internal-only", json.dumps(collectors))

    def test_one_collector_timeout_is_local(self):
        dispatcher = AgentDispatcher(
            Path("/srv/kvn"), ObservabilityRunner(timeout_telemt=True), ObservabilityControl()
        )
        collectors = dispatcher._protocol_stats({})["collectors"]
        self.assertFalse(collectors["telemt"]["available"])
        self.assertEqual(collectors["telemt"]["error"], "command_timeout")
        self.assertTrue(collectors["xray"]["available"])
        self.assertTrue(collectors["ocserv"]["available"])

    def test_health_errors_have_russian_reason_and_safe_command(self):
        dispatcher = AgentDispatcher(
            Path("/srv/kvn"), ObservabilityRunner(inactive_xray=True), ObservabilityControl()
        )
        health = dispatcher._health_summary({})
        self.assertGreaterEqual(len(health["diagnostics"]), 2)
        for item in health["diagnostics"]:
            self.assertTrue(item["reason"])
            self.assertTrue(item["command"])
            self.assertNotIn("internal-only", json.dumps(item))

    def test_site_certificate_action_reloads_only_nginx(self):
        runner = ObservabilityRunner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, ObservabilityControl())
        result = dispatcher._certificate_action({"action": "renew", "target": "site"})
        self.assertTrue(result["ok"])
        calls = [call for call, _timeout, _max in runner.calls]
        self.assertTrue(any("issue-configured" in call and "site" in call for call in calls))
        self.assertTrue(any("nginx" in call and "reload" not in call for call in calls))
        self.assertFalse(any(call[-1] == "ocserv" and "ps" not in call for call in calls))
        self.assertFalse(any("restart" in call for call in calls))


class FakeCertificateKvnctl:
    def __init__(self, root):
        self.root = root
        self.STATE_STORE = mock.Mock()
        self.STATE_STORE.load.return_value = {"letsencrypt": {}}

    @staticmethod
    def letsencrypt_target_domains(_state, target):
        return ["vpn.example.com"] if target == "site" else ["oc.example.com"]

    def cert_target_dir(self, target):
        return self.root / target

    @staticmethod
    def certificate_dates(path):
        days = 40 if path.parent.name == "site" else -1
        expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
        return "Jan 01 00:00:00 2026 GMT", expires.strftime("%b %d %H:%M:%S %Y GMT")

    @staticmethod
    def certificate_sans(path):
        return ["vpn.example.com"] if path.parent.name == "site" else ["wrong.example.com"]

    @staticmethod
    def certificate_source(path):
        return "letsencrypt" if path.parent.name == "site" else "self-signed"

    @staticmethod
    def certificate_issuer(path):
        return "Let's Encrypt" if path.parent.name == "site" else "fallback"


class CertificateStatusTests(unittest.TestCase):
    def test_source_san_mismatch_and_expiry_thresholds(self):
        with tempfile.TemporaryDirectory() as tmp:
            control = KvnControl.__new__(KvnControl)
            control.kvnctl = FakeCertificateKvnctl(Path(tmp))
            status = control.certificate_status()["certificates"]
        self.assertEqual(status[0]["source"], "letsencrypt")
        self.assertEqual(status[0]["expiry"], "ok")
        self.assertRegex(status[0]["not_after_display"], r"^\d{2}\.\d{2}\.\d{4} \d{2}:\d{2} UTC$")
        self.assertFalse(status[0]["san_mismatch"])
        self.assertEqual(status[1]["source"], "self-signed")
        self.assertEqual(status[1]["expiry"], "expired")
        self.assertTrue(status[1]["san_mismatch"])


class MetricsHistoryTests(unittest.TestCase):
    @staticmethod
    def sample(timestamp, value=10):
        return {
            "timestamp": timestamp,
            "cpu_percent": value,
            "memory_used": value * 100,
            "memory_total": 10000,
            "memory_percent": value,
            "disk_used": value * 1000,
            "disk_total": 100000,
            "disk_percent": value,
            "load1": value / 10,
            "rx_bytes_per_second": value * 2,
            "tx_bytes_per_second": value * 3,
        }

    def test_store_retention_boundary_and_bounded_aggregation(self):
        now = 1_800_000_000
        with tempfile.TemporaryDirectory() as tmp:
            store = MetricsStore(Path(tmp) / "metrics.db")
            store.record(self.sample(now - RETENTION_SECONDS - 1), now=now - RETENTION_SECONDS - 1)
            store.record(self.sample(now - RETENTION_SECONDS), now=now - RETENTION_SECONDS)
            store.record(self.sample(now - 60, 20), now=now)
            store.record(self.sample(now, 40), now=now)
            with store.session() as db:
                timestamps = [row[0] for row in db.execute("SELECT ts FROM samples ORDER BY ts")]
            history = store.history(1, 1, now=now)
        self.assertNotIn(now - RETENTION_SECONDS - 1, timestamps)
        self.assertIn(now - RETENTION_SECONDS, timestamps)
        self.assertTrue(history["available"])
        self.assertEqual(history["step_minutes"], 1)
        self.assertLessEqual(len(history["points"]), 60)
        self.assertNotIn("argv", json.dumps(history))

    def test_query_rejects_unknown_and_oversized_combinations(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MetricsStore(Path(tmp) / "metrics.db")
            for query in [(2, "auto"), (72, 1), (24, 2), (24, "bad")]:
                with self.subTest(query=query), self.assertRaises(MetricsQueryError):
                    store.history(*query, now=1_800_000_000)

    def test_three_day_database_and_history_stay_within_budget(self):
        now = 1_800_000_000
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "metrics.db"
            store = MetricsStore(path)
            rows = []
            for index in range(72 * 60 + 1):
                sample = self.sample(now - index * 60, 10 + index % 30)
                rows.append([sample["timestamp"], *[sample[key] for key in (
                    "cpu_percent", "memory_used", "memory_total", "memory_percent",
                    "disk_used", "disk_total", "disk_percent", "load1",
                    "rx_bytes_per_second", "tx_bytes_per_second",
                )]])
            with store.session() as db:
                db.executemany("INSERT OR REPLACE INTO samples VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
            history = store.history(72, 5, now=now)
            total_bytes = sum(item.stat().st_size for item in Path(tmp).glob("metrics.db*"))
        self.assertLessEqual(len(history["points"]), 72 * 12 + 1)
        self.assertLess(total_bytes, 2 * 1024 * 1024)

    def test_collector_handles_first_sample_and_counter_reset(self):
        state = {"cpu": "cpu  10 0 10 80 0 0 0 0\n", "net": "", "rx": 1000, "tx": 2000}

        def read_file(path):
            normalized = path.as_posix()
            if normalized == "/proc/stat":
                return state["cpu"]
            if normalized == "/proc/meminfo":
                return "MemTotal: 1000 kB\nMemAvailable: 400 kB\n"
            if normalized == "/proc/loadavg":
                return "0.50 0.25 0.10 1/100 1\n"
            if normalized == "/proc/net/dev":
                return (
                    "Inter-| Receive | Transmit\n face |bytes|bytes\n"
                    f" eth0: {state['rx']} 0 0 0 0 0 0 0 {state['tx']} 0 0 0 0 0 0 0\n"
                )
            raise AssertionError(path)

        stats = SimpleNamespace(f_blocks=1000, f_frsize=4096, f_bavail=250)
        collector = HostMetricsCollector(Path("/srv/kvn"), read_file=read_file, statvfs=lambda _path: stats)
        first = collector.collect(100)
        state.update(cpu="cpu  30 0 20 150 0 0 0 0\n", rx=1600, tx=2600)
        second = collector.collect(160)
        state.update(cpu="cpu  1 0 1 8 0 0 0 0\n", rx=10, tx=10)
        reset = collector.collect(220)
        self.assertIsNone(first["cpu_percent"])
        self.assertIsNone(first["rx_bytes_per_second"])
        self.assertGreater(second["cpu_percent"], 0)
        self.assertEqual(second["rx_bytes_per_second"], 10)
        self.assertIsNone(reset["cpu_percent"])
        self.assertIsNone(reset["tx_bytes_per_second"])

    def test_sampler_writes_immediately_and_rpc_stays_typed(self):
        class Collector:
            def collect(self):
                return MetricsHistoryTests.sample(int(time.time()), 25)

        with tempfile.TemporaryDirectory() as tmp:
            store = MetricsStore(Path(tmp) / "metrics.db")
            sampler = MetricsSampler(store, Collector())
            sampler.start()
            deadline = time.time() + 1
            while not store.current()["available"] and time.time() < deadline:
                time.sleep(0.01)
            dispatcher = AgentDispatcher(Path("/srv/kvn"), metrics=store)
            current = dispatcher._metrics_current({})
            history = dispatcher._metrics_history({"range_hours": 1, "step": "auto"})
            with self.assertRaises(ProtocolError):
                dispatcher._metrics_history({"range_hours": 72, "step": 1})
            sampler.stop()
        self.assertTrue(current["available"])
        self.assertEqual(history["step_minutes"], 1)
        self.assertLess(time.time() - deadline + 1, 1.5)

    def test_disabled_monitoring_skips_collector_and_returns_typed_payloads(self):
        class Collector:
            calls = 0

            def collect(self):
                self.calls += 1
                return MetricsHistoryTests.sample(int(time.time()), 25)

        class LightControl:
            @staticmethod
            def portal_performance():
                return {"features": {"monitoring": False, "background_refresh": False}}

        with tempfile.TemporaryDirectory() as tmp:
            store = MetricsStore(Path(tmp) / "metrics.db")
            collector = Collector()
            sampler = MetricsSampler(store, collector, enabled_provider=lambda: False)
            sampler.start()
            time.sleep(0.05)
            sampler.stop()
            dispatcher = AgentDispatcher(
                Path("/srv/kvn"), control=LightControl(), metrics=store
            )
            current = dispatcher._metrics_current({})
            history = dispatcher._metrics_history({"range_hours": 1, "step": "auto"})
        self.assertEqual(collector.calls, 0)
        self.assertTrue(current["disabled"])
        self.assertEqual(current["reason"], "monitoring_disabled")
        self.assertTrue(history["disabled"])
        self.assertEqual(history["points"], [])


if __name__ == "__main__":
    unittest.main()
