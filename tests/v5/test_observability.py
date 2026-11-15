"""Начальные контракты снимка процессов, приватности и повторного PID."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.observability.processes import Process, descendants, parse_stat, project, sample
from v5.core.observability import ssh
from v5.core.observability.live import Observer
from v5.core.observability.history import History, summarize
from v5.core.observability.collector import collect
from v5.core.observability import control
from v5.core.lifecycle.rpc import Application as LifecycleApplication
from v5.core.lifecycle.controller import LifecycleError
from v5.core.release import SERVICES, TRIGGERS, UNIT_FILES
from v5.core.tls.gateway import _portal_proxy, _vhost
from v5.core.tls.identity import TLSIdentity
from v5.core.agent import AgentApplication
from v5.portal.app import create_app
from v5.portal.rpc import AgentUnavailable


class ProcessObservationTests(TestCase):
    def test_comm_with_parentheses_and_no_argv_projection(self):
        fields = ["S", "1", *["0"] * 9, "12", "5", *["0"] * 6, "40", "1000", "2"]
        raw = ("123 (lab ) name\t) " + " ".join(fields)).encode()
        row = parse_stat(raw, 123, os.getuid(), 4096)
        self.assertEqual((row.parent, row.name, row.ticks, row.started, row.rss),
                         (1, "lab ) name?", 17, 40, 8192))
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "123").mkdir()
            (root / "123/stat").write_bytes(raw)
            (root / "123/cmdline").write_bytes(b"fixture-secret")
            (root / "123/environ").write_bytes(b"fixture-secret")
            rows, partial = sample(root)
        self.assertFalse(partial)
        output = project(rows, {}, 1, 4, ticks_per_second=10)
        self.assertEqual(set(output[0]), {"pid", "name", "user", "rss_bytes", "cpu_percent", "age_seconds"})
        self.assertNotIn("fixture-secret", repr(output))
        self.assertIsNone(output[0]["cpu_percent"])

    def test_cpu_and_ancestry_never_use_recycled_pid(self):
        uid = os.getuid()
        old = Process(5, 1, 10, "session", uid, 10, 1)
        new = Process(5, 1, 40, "unrelated", uid, 15, 1)
        child = Process(6, 5, 20, "old", uid, 10, 2)
        fresh = Process(7, 5, 45, "new", uid, 15, 3)
        rows = {5: new, 6: child, 7: fresh}
        self.assertEqual(descendants(rows, old.key), frozenset())
        self.assertEqual(descendants(rows, new.key), {5, 7})
        self.assertIsNone(project(rows, {5: old}, 1, 10, visible={5})[0]["cpu_percent"])
        previous = Process(5, 1, 40, "unrelated", uid, 10, 1)
        self.assertEqual(project(rows, {5: previous}, 2, 10, visible={5},
                                 ticks_per_second=10)[0]["cpu_percent"], 25)

    def test_live_process_is_visible(self):
        rows, _ = sample()
        self.assertIn(os.getpid(), rows)
        self.assertGreater(rows[os.getpid()].started, 0)


def logind(sid, *, name="root", leader=12, address="2001:db8::2", remote="yes", service="sshd"):
    return (f"Id={sid}\nName={name}\nLeader={leader}\nRemote={remote}\nRemoteHost={address}\n"
            f"Service={service}\nState=active\nTTY=pts/1\nTimestampMonotonic=2000000")


def ss_line(pid=12, cookie="d", rx=120, tx=200):
    return (f'0 0 [2001:db8::1]:2222 [2001:db8::2]:48120 users:(("sshd-session",pid={pid},fd=7)) '
            f'ino:412 sk:{cookie} bytes_received:{rx} bytes_acked:{tx}')


class SSHObservationTests(TestCase):
    def test_who_fallback_requires_tty_owner_sshd_ancestry_and_socket(self):
        with TemporaryDirectory() as temporary:
            devices = Path(temporary)
            (devices / "pts").mkdir()
            (devices / "pts/1").symlink_to("/dev/null")
            info = (devices / "pts/1").stat()
            uid = info.st_uid
            processes = {12: Process(12, 1, 20, "sshd-session", 0, 1, 512),
                         13: Process(13, 12, 30, "bash", uid, 1, 512, info.st_rdev)}
            sockets = ssh.connections(query=lambda _: ss_line())
            who = lambda _: "fixture pts/1 2026-11-13 12:00 (2001:db8::2)\n"
            lookup = lambda _: Mock(pw_uid=uid)
            rows = ssh.fallback_sessions(processes, sockets, query=who, devices=devices, user_lookup=lookup)
            self.assertEqual([(row.id, row.user, row.address, row.leader) for row in rows],
                             [("w1", "fixture", "2001:db8::2", 12)])
            self.assertEqual(ssh.fallback_sessions(processes, [], query=who, devices=devices, user_lookup=lookup), [])
            unrelated = {**processes, 13: Process(13, 1, 30, "bash", uid, 1, 512, info.st_rdev)}
            self.assertEqual(ssh.fallback_sessions(unrelated, sockets, query=who, devices=devices, user_lookup=lookup), [])
            self.assertEqual(ssh.fallback_sessions(processes, sockets, query=lambda _: "fixture pts/1 2026-11-13 12:00 (host.invalid)",
                                                   devices=devices, user_lookup=lookup), [])
            no_who = ssh.fallback_sessions(processes, sockets, query=lambda _: "", devices=devices,
                                           uid_lookup=lambda _: Mock(pw_name="fixture"),
                                           ttys=lambda _: [("pts/1", info)])
            self.assertEqual([(row.user, row.address, row.leader) for row in no_who],
                             [("fixture", "2001:db8::2", 12)])
            self.assertEqual(ssh.fallback_sessions(unrelated, sockets, query=lambda _: "", devices=devices,
                                                  uid_lookup=lambda _: Mock(pw_name="fixture"),
                                                  ttys=lambda _: [("pts/1", info)]), [])

    def test_unavailable_logind_uses_confirmed_fallback_and_marks_partial(self):
        session = ssh.parse_sessions(logind("1"), {"1"})[0]
        process = {12: Process(12, 1, 20, "sshd-session", 0, 1, 512)}
        def unavailable():
            raise OSError("fixture")
        observer = Observer(process_source=lambda: (process, False), session_source=unavailable,
                            socket_source=lambda: [], network_source=lambda: {"received_bytes": 1, "sent_bytes": 1},
                            clock=lambda: 0, wall=lambda: 100, uptime=lambda: 6)
        with patch.object(ssh, "fallback_sessions", return_value=[session]) as fallback:
            data = observer.snapshot()
        self.assertTrue(data["ssh_partial"])
        self.assertEqual(data["ssh"][0]["user"], "root")
        fallback.assert_called_once()

    def test_logind_authenticates_session_kind_and_does_not_resolve_hostnames(self):
        blocks = [logind("1"), logind("2", remote="no"), logind("3", service="sudo"),
                  logind("4", address="host.invalid", name="lab"), logind("5")]
        rows = ssh.parse_sessions("\n\n".join(blocks), {"1", "2", "3", "4"})
        self.assertEqual([(row.user, row.address) for row in rows], [("root", "2001:db8::2"), ("lab", None)])

    def test_exact_ssh_socket_rates_reuse_and_multiplex(self):
        session = ssh.parse_sessions(logind("1"), {"1"})[0]
        processes = {12: Process(12, 1, 20, "sshd-session", 0, 1, 512)}
        def sockets(*lines):
            return ssh.connections(query=lambda _: "\n".join(lines))
        first, earlier = ssh.project([session], processes, sockets(ss_line(), ss_line(pid=13)), {}, 0, 5)
        self.assertEqual((first[0]["port"], first[0]["rx_bytes"], first[0]["tx_bytes"]), (48120, 120, 200))
        self.assertIsNone(first[0]["tx_per_second"])
        latest, _ = ssh.project([session], processes, sockets(ss_line(rx=140, tx=260)), earlier, 2, 7)
        self.assertEqual((latest[0]["rx_per_second"], latest[0]["tx_per_second"]), (10, 30))
        reused, _ = ssh.project([session], processes, sockets(ss_line(cookie="e")), earlier, 2, 7)
        self.assertIsNone(reused[0]["rx_per_second"])
        duplicate = ssh.parse_sessions(logind("2"), {"2"})[0]
        multiplexed, _ = ssh.project([session, duplicate], processes, sockets(ss_line()), earlier, 2, 7)
        self.assertTrue(all(row["rx_bytes"] is None for row in multiplexed))
        same_ip, _ = ssh.project([session], processes, sockets(ss_line(pid=99)), earlier, 2, 7)
        self.assertIsNone(same_ip[0]["port"])

    def test_snapshot_filter_and_two_second_cache(self):
        session = ssh.parse_sessions(logind("1"), {"1"})[0]
        rows = {12: Process(12, 1, 20, "sshd-session", 0, 1, 512),
                13: Process(13, 12, 30, "bash", os.getuid(), 1, 512),
                14: Process(14, 1, 40, "unrelated", os.getuid(), 1, 512)}
        time = [0]
        calls = []
        def proc():
            calls.append(1)
            return rows, False
        observer = Observer(process_source=proc, session_source=lambda: ([session], False), socket_source=lambda: [],
                            clock=lambda: time[0], wall=lambda: 100, uptime=lambda: 6)
        self.assertEqual(observer.snapshot()["ssh"][0]["started_at"], 96)
        self.assertEqual({row["pid"] for row in observer.snapshot("1")["processes"]}, {12, 13})
        self.assertEqual(observer.snapshot("missing")["processes"], [])
        self.assertEqual(len(calls), 1)
        time[0] = 3
        self.assertEqual(observer.snapshot()["processes"][0]["cpu_percent"], 0)
        self.assertEqual(len(calls), 2)
        other = ssh.parse_sessions(logind("2"), {"2"})[0]
        ambiguous = Observer(process_source=proc, session_source=lambda: ([session, other], False),
                             socket_source=lambda: [], clock=lambda: 0, wall=lambda: 100, uptime=lambda: 6)
        self.assertFalse(ambiguous.snapshot("1")["session_filter_confirmed"])
        self.assertEqual(ambiguous.snapshot("1")["processes"], [])

    def test_server_network_rates_do_not_assume_zero_or_counter_reset(self):
        now, counters = [0], [{"received_bytes": 100, "sent_bytes": 200}]
        observer = Observer(process_source=lambda: ({}, False), session_source=lambda: ([], False),
                            network_source=lambda: counters[0], clock=lambda: now[0], wall=lambda: 10,
                            uptime=lambda: 10)
        self.assertIsNone(observer.snapshot()["network"]["rx_per_second"])
        now[0], counters[0] = 4, {"received_bytes": 180, "sent_bytes": 10}
        network = observer.snapshot()["network"]
        self.assertEqual(network["rx_per_second"], 20)
        self.assertIsNone(network["tx_per_second"])


class ObservationAccessTests(TestCase):
    def test_agent_requires_uid_and_accepts_only_session_identifier(self):
        observer = Mock()
        observer.snapshot.return_value = {"ssh": [], "processes": [], "boot_id": "fixture-private"}
        agent = AgentApplication(123, observer=observer)
        request = {"version": 1, "method": "observe.live", "params": {"session": "c42"}}
        self.assertEqual(agent.dispatch(124, request)["error"], "forbidden")
        response = agent.dispatch(123, request)
        self.assertTrue(response["ok"])
        self.assertNotIn("boot_id", response["result"])
        observer.snapshot.assert_called_once_with("c42")
        for params in ({"session": "../etc"}, {"command": "id"}, {"session": None}):
            self.assertEqual(agent.dispatch(123, {**request, "params": params})["error"], "invalid_request")
        self.assertEqual(agent.dispatch(123, request, body=b"id")["error"], "invalid_request")

    def test_portal_authentication_escaping_and_unavailable_state(self):
        backend = Mock()
        backend.observe_live.return_value = {
            "captured_at": 100, "ssh_partial": False, "tcp_partial": False,
            "processes_partial": False, "session_filter_confirmed": None,
            "ssh": [{"id": "1", "user": "<script>", "tty": None, "ip": "192.0.2.1",
                     "port": 1234, "started_at": 90, "age_seconds": 10, "rx_bytes": None,
                     "tx_bytes": None, "rx_per_second": None, "tx_per_second": None}],
            "processes": [{"pid": 7, "name": "<script>", "user": "root", "cpu_percent": None,
                           "rss_bytes": 3, "age_seconds": 2}],
        }
        app = create_app({"session_key": "test-only", "allowed_hosts": ["localhost:8443"]}, client=backend)
        web = app.test_client()
        origin = "https://localhost:8443"
        self.assertEqual(web.get("/observability", base_url=origin).status_code, 303)
        backend.observe_live.assert_not_called()
        with web.session_transaction(base_url=origin) as session:
            session["admin"] = True
        response = web.get("/observability", base_url=origin)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertNotIn(b"<script>", response.data)
        self.assertEqual(web.get("/observability?session=../etc", base_url=origin).status_code, 400)
        self.assertEqual(web.get("/observability?session=1&session=2", base_url=origin).status_code, 400)
        backend.observe_live.side_effect = AgentUnavailable()
        self.assertEqual(web.get("/observability", base_url=origin).status_code, 503)


class ObservationHistoryTests(TestCase):
    def test_clean_install_does_not_enable_history_service(self):
        self.assertIn("kvn-v5-observer.service", UNIT_FILES)
        self.assertNotIn("kvn-v5-observer.service", SERVICES + TRIGGERS)
        self.assertIn("kvn-v5-socket-observer.socket", TRIGGERS)
        proxy = _portal_proxy("127.0.0.1:8443")
        self.assertIn("location = /observability/history", proxy)
        self.assertIn("proxy_read_timeout 45s;", proxy)
        pair = SimpleNamespace(metadata=SimpleNamespace(identity=TLSIdentity("example.test", False)),
                               chain=Path("/fixture/cert.pem"), key=Path("/fixture/key.pem"))
        public = _vhost(pair, 443, ipv6=False, site_root="/fixture/site", loopback=False)
        admin = _vhost(pair, 8443, ipv6=False, site_root="/fixture/site", loopback=False)
        self.assertNotIn("/observability", public)
        self.assertNotIn("proxy_pass http://portal", public)
        self.assertIn("location = /observability/history", admin)

    @staticmethod
    def snapshot(stamp):
        return {"captured_at": stamp, "boot_id": "00000000-0000-0000-0000-000000000001",
                "ssh_partial": False, "tcp_partial": False, "processes_partial": False,
                "network": {"received_bytes": 12, "sent_bytes": 34, "secret": "not-stored"},
                "ssh": [{"id": "1", "user": "root", "ip": "192.0.2.2", "port": 2222, "tty": "pts/0",
                         "started_at": 1, "age_seconds": 1, "rx_bytes": 1, "tx_bytes": None,
                         "rx_per_second": None, "tx_per_second": 5, "command": "not-stored"}],
                "processes": [{"pid": 4, "name": "bash", "user": "root", "rss_bytes": 50,
                               "cpu_percent": None, "age_seconds": 5, "argv": "not-stored"}]}

    def test_windows_retention_and_sensitive_fields(self):
        with TemporaryDirectory() as temporary:
            history = History(Path(temporary) / "history")
            self.assertFalse(history.directory.exists())
            history.initialize()
            self.assertEqual(history.database.stat().st_mode & 0o777, 0o600)
            now = 200000
            for age in (0, 3600, 7200, 21600, 43200, 86400, 86401):
                history.append(self.snapshot(now - age))
            history.append(self.snapshot(now))
            for hours, expected in ((1, 2), (2, 3), (6, 4), (12, 5), (24, 6)):
                rows = history.read(hours, now)
                self.assertEqual(len(rows), expected)
                self.assertEqual(history.summary(hours, now)["captured_count"], expected)
                self.assertNotIn("not-stored", repr(rows))
            self.assertEqual(history.read(1, now + 7200), [])
            with self.assertRaises(ValueError):
                history.read(3, now)

    def test_refuses_symlink_and_invalid_data(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "history"
            directory.mkdir(mode=0o700)
            (directory / "history.sqlite3").symlink_to(root / "foreign")
            with self.assertRaises(OSError):
                History(directory).initialize()
            self.assertFalse((root / "foreign").exists())
            (directory / "history.sqlite3").unlink()
            history = History(directory)
            history.initialize()
            bad = self.snapshot(100)
            bad["processes"][0]["name"] = "bad\nname"
            with self.assertRaises(ValueError):
                history.append(bad)
            self.assertEqual(history.read(1, 100), [])

    def test_collector_keeps_network_failure_unknown(self):
        observer, history = Mock(), Mock()
        observer.snapshot.return_value = self.snapshot(100)
        observer.snapshot.return_value["network"] = None
        collect(observer, history)
        self.assertIsNone(history.append.call_args.args[0]["network"])

    def test_summary_reports_gaps_and_only_confirmed_session_changes(self):
        first = self.snapshot(1000)
        second = self.snapshot(1060)
        second["ssh"] = []
        partial = self.snapshot(1120)
        partial["ssh_partial"] = True
        after_gap = self.snapshot(1400)
        result = summarize([first, second, partial, after_gap], 1, 1450)
        self.assertEqual([(event["action"], event["at"]) for event in result["events"]], [("выход", 1060)])
        self.assertIn((1120, 1400), result["gaps"])
        self.assertEqual(result["captured_count"], 4)
        rows = [self.snapshot(1000 + 60 * index) for index in range(100)]
        reduced = summarize(rows, 6, 7000)
        self.assertEqual((reduced["captured_count"], len(reduced["samples"])), (100, 24))
        self.assertNotIn("boot_id", reduced["samples"][0])
        self.assertEqual((reduced["samples"][0]["captured_at"], reduced["samples"][-1]["captured_at"]),
                         (rows[0]["captured_at"], rows[-1]["captured_at"]))
        rebooted = self.snapshot(1060)
        rebooted["boot_id"] = "00000000-0000-0000-0000-000000000002"
        rebooted["ssh"] = []
        changed = summarize([first, rebooted], 1, 1070)
        self.assertEqual(changed["events"], [])
        self.assertIn((1000, 1060), changed["gaps"])
        address_lost = self.snapshot(1060)
        address_lost["ssh"][0]["ip"] = None
        self.assertEqual(summarize([first, address_lost], 1, 1070)["events"], [])

    def test_service_control_is_allowlisted_and_off_removes_only_history(self):
        lifecycle = LifecycleApplication(123)
        request = {"version": 1, "method": "lifecycle.history.configure", "params": {"enabled": True}}
        with patch.object(control, "configure", return_value={"enabled": True, "active": True}) as configure:
            self.assertTrue(lifecycle.dispatch(request)["enabled"])
            configure.assert_called_once_with(True)
        with TemporaryDirectory() as temporary:
            directory = Path(temporary) / "history"
            history = History(directory)
            history.initialize()
            history.append(self.snapshot(100))
            (directory / "unrelated").write_text("keep")
            with patch.object(control, "_run", return_value=Mock(returncode=0)), \
                    patch.object(control, "status", return_value={"enabled": False, "active": False}):
                self.assertFalse(control.configure(False, directory=directory)["enabled"])
            self.assertFalse(history.database.exists())
            self.assertTrue((directory / "unrelated").exists())
        with self.assertRaises(LifecycleError):
            control.configure("yes")

    def test_history_page_authentication_and_explicit_csrf_confirmation(self):
        backend, lifecycle = Mock(), Mock()
        sample = self.snapshot(10000)
        sample["processes"] *= 12
        backend.observe_history.return_value = summarize([sample], 1, 10000)
        lifecycle.history_status.return_value = {"enabled": True, "active": True}
        app = create_app({"session_key": "test-only", "allowed_hosts": ["localhost:8443"]},
                         client=backend, lifecycle_client=lifecycle)
        web, origin = app.test_client(), "https://localhost:8443"
        self.assertEqual(web.get("/observability/history", base_url=origin).status_code, 303)
        with web.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf="test-csrf")
        self.assertEqual(web.get("/observability/history?hours=3", base_url=origin).status_code, 400)
        page = web.get("/observability/history", base_url=origin)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Показать остальные (2)".encode(), page.data)
        headers = {"Origin": origin}
        self.assertEqual(web.post("/observability/history", base_url=origin, headers=headers,
                                  data={"csrf": "wrong", "action": "disable", "confirm": "yes"}).status_code, 403)
        self.assertEqual(web.post("/observability/history", base_url=origin, headers=headers,
                                  data={"csrf": "test-csrf", "action": "disable"}).status_code, 400)
        lifecycle.history_configure.assert_not_called()
        self.assertEqual(web.post("/observability/history", base_url=origin, headers=headers,
                                  data={"csrf": "test-csrf", "action": "disable", "confirm": "yes"}).status_code, 303)
        lifecycle.history_configure.assert_called_once_with(False)
