import json
import io
import os
import socket
import tarfile
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from portal.agent import (
    AgentApplication,
    AgentDispatcher,
    AgentRequestHandler,
    CommandResult,
    RootShellSession,
    ThreadingUnixServer,
)
from portal.agent_client import AgentClient, AgentClientError
from portal.agent_protocol import MAX_REQUEST_BYTES, PROTOCOL_VERSION, ProtocolError, RpcRequest, sanitize_text
from tests.test_offline_release import make_release


SECRET = "a" * 64


def write_deploy_member(archive, name, content=b""):
    info = tarfile.TarInfo(name)
    info.size = len(content)
    archive.addfile(info, io.BytesIO(content))


def make_safe_deploy_archive(path: Path, *, malicious: str = "", missing: str = "") -> None:
    schema = Path(__file__).resolve().parents[1] / "tools/canonical-files.txt"
    manifest_text = schema.read_text(encoding="utf-8")
    manifest = manifest_text.splitlines()
    with tarfile.open(path, "w:gz") as archive:
        root = tarfile.TarInfo("deploy")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        write_deploy_member(archive, "deploy/.kvn-canonical-files", manifest_text.encode())
        for relative in manifest:
            if relative == missing:
                continue
            payload = b"source\n"
            if relative == "tools/canonical-files.txt":
                payload = manifest_text.encode()
            if relative == "portal/Dockerfile":
                payload += os.urandom(2048)
            write_deploy_member(archive, f"deploy/{relative}", payload)
        write_deploy_member(
            archive,
            "deploy/users.json",
            b'{"server":"YOUR_SERVER_IP","users":[],"portal":{"enabled":false}}',
        )
        if malicious == "traversal":
            write_deploy_member(archive, "deploy/../../outside", b"x")
        elif malicious == "runtime":
            write_deploy_member(archive, "deploy/clients/unsafe", b"x")
        elif malicious in {"link", "device"}:
            info = tarfile.TarInfo("deploy/unsafe")
            info.type = tarfile.SYMTYPE if malicious == "link" else tarfile.CHRTYPE
            info.linkname = "../../outside"
            archive.addfile(info)


def request_line(method, params=None, secret=SECRET, version=PROTOCOL_VERSION, request_id="req-1"):
    return (
        json.dumps(
            {
                "version": version,
                "id": request_id,
                "secret": secret,
                "method": method,
                "params": params or {},
            }
        ).encode("utf-8")
        + b"\n"
    )


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run(self, argv, *, timeout=30, max_output=128 * 1024):
        self.calls.append((tuple(argv), timeout, max_output))
        stdout = ""
        if argv[:2] == ["docker", "stats"]:
            names = [item for item in argv[5:] if not item.startswith("{")]
            stdout = "".join(json.dumps({"Name": name, "CPUPerc": "0.1%"}) + "\n" for name in names)
        elif argv[:2] == ["docker", "inspect"]:
            stdout = "".join(f"/{name}\trunning\tnone\t0\n" for name in argv[4:])
        elif "ps" in argv:
            stdout = '{"Service":"xray","State":"running"}\n'
        elif argv[0] == "uptime":
            stdout = "up 1 day\n"
        elif argv[0] == "free":
            stdout = "Mem: 100 20 80\n"
        elif argv[0] == "df":
            stdout = "100 20 80 20%\n"
        elif argv[0] in {"awg", "wg"}:
            stdout = "awg0 private-key public-key 51820 off\n"
        return CommandResult(tuple(argv), 0, stdout, "", 1)


class FakeServiceControl:
    def __init__(self, preferences=None):
        self.preferences = dict(preferences or {})
        self.applied_services = []

    def service_preferences(self):
        return dict(self.preferences)

    def set_service_enabled(self, service, enabled):
        self.preferences[service] = enabled
        return {"changed": True, "enabled": enabled}

    def reconcile_state(self):
        return {"changed": False, "apply": {"outcome": "no-op"}}

    def apply_host_service(self, service):
        self.applied_services.append(service)
        return {
            "changed": True,
            "plan": {"changed": False, "changed_paths": [], "services": {}},
            "apply": {"outcome": "applied", "warnings": [], "fallbacks": []},
            "service": service,
        }

    def network_topology(self):
        return {
            "revision": "a" * 64,
            "ingress": [],
            "routes": [],
            "protocols": [],
            "infrastructure": [],
        }

    def apply_protocol(self, params):
        return {"changed": True, "protocol": {"system": params["system"], "xhttp_mode": params["mode"]}}

    def mtproto_status(self):
        return {"revision": "a" * 64, "services": {}, "origins": ["external", "local-site"]}

    def mtproto_diagnose(self, params):
        return {"system": params["system"], "status": "ready", "checks": []}

    def apply_mtproto(self, params):
        return {"changed": True, "system": params["system"], "origin": params["origin"]}

    def domain_advice(self, params):
        return {"zone": params["zone"], "status": "needs_attention", "hostnames": [], "protocols": []}

    def client_export_settings(self):
        return {
            "revision": "a" * 64,
            "address_mode": "server",
            "public_ip": "",
            "include_alternate": False,
        }

    def update_client_export(self, params):
        return {
            "changed": True,
            "revision": "b" * 64,
            "settings": {
                "address_mode": params["address_mode"],
                "public_ip": params["public_ip"],
                "include_alternate": params["include_alternate"],
            },
        }


class ActivityControl:
    def user_activity_subject(self, name):
        if name != "Alice":
            error = RuntimeError("missing")
            error.code = "not_found"
            raise error
        return {
            "name": "Alice",
            "enabled": True,
            "systems": [
                "tls", "reality-xhttp", "hysteria", "telemt", "mtg",
                "amneziawg", "wireguard", "ocserv",
            ],
            "services": {
                "xray": True, "hysteria": True, "telemt": True, "mtg": True,
                "amneziawg": True, "wireguard": True, "ocserv": True,
            },
            "amneziawg_public_key": "awg-public",
            "wireguard_public_key": "wg-public",
        }

    def observability_config(self):
        return {"hysteria_secret": "internal-hysteria-secret"}


class ActivityRunner(FakeRunner):
    def __init__(self, *, fail_telemt=False, slow_telemt=False, huge_telemt=False):
        super().__init__()
        self.fail_telemt = fail_telemt
        self.slow_telemt = slow_telemt
        self.huge_telemt = huge_telemt

    def run(self, argv, *, timeout=30, max_output=128 * 1024):
        self.calls.append((tuple(argv), timeout, max_output))
        if "statsquery" in argv:
            stdout = json.dumps({"stat": [
                {"name": "user>>>Alice-tls>>>traffic>>>uplink", "value": 120},
                {"name": "user>>>Alice-tls>>>traffic>>>downlink", "value": 340},
                {"name": "user>>>Alice-reality-xhttp>>>traffic>>>uplink", "value": 5},
                {"name": "user>>>Mallory-tls>>>traffic>>>uplink", "value": 999999},
            ]})
            return CommandResult(tuple(argv), 0, stdout, "", 1)
        if any(str(item).endswith("/traffic") for item in argv):
            return CommandResult(tuple(argv), 0, json.dumps({"Alice": {"rx": 11, "tx": 22}}), "", 1)
        if any(str(item).endswith("/online") for item in argv):
            return CommandResult(tuple(argv), 0, json.dumps({"Alice": 2}), "", 1)
        if argv and argv[0] == "curl":
            if self.slow_telemt:
                time.sleep(0.2)
            if self.fail_telemt:
                return CommandResult(tuple(argv), 1, "", "token=must-not-leak", 1)
            prefix = ("ignored_metric 1\n" * 10000) if self.huge_telemt else ""
            stdout = prefix + (
                'telemt_user_rx_bytes{username="Alice",endpoint="198.51.100.7:443"} 30\n'
                'telemt_user_tx_bytes{username="Alice",private_key="must-not-leak"} 40\n'
                'telemt_user_connections_active{username="Alice"} 1\n'
            )
            return CommandResult(tuple(argv), 0, stdout, "", 1)
        if argv[:3] == ["awg", "show", "awg0"]:
            now = int(time.time())
            return CommandResult(
                tuple(argv), 0,
                f"server-private\tserver-public\t51820\toff\nawg-public\tpreshared-secret\t198.51.100.7:555\t10.0.0.2/32\t{now}\t50\t60\t25\n",
                "", 1,
            )
        if argv[:3] == ["wg", "show", "wg0"]:
            return CommandResult(
                tuple(argv), 0,
                "server-private\tserver-public\t51821\toff\nwg-public\tpreshared-secret\t198.51.100.8:555\t10.0.0.3/32\t1\t70\t80\t25\n",
                "", 1,
            )
        if "occtl" in argv:
            return CommandResult(tuple(argv), 0, json.dumps({"users": [{
                "Username": "Alice", "RX": 90, "TX": 100,
                "Remote IP": "198.51.100.9", "password": "must-not-leak",
            }]}), "", 1)
        return CommandResult(tuple(argv), 1, "", "", 1)


class StatefulRunner(FakeRunner):
    def __init__(self, reload_failure=False, delay=0):
        super().__init__()
        self.active = {name: True for name in ["nginx", "portal", "xray", "hysteria", "telemt", "mtg", "ocserv"]}
        self.reload_failure = reload_failure
        self.delay = delay
        self.concurrent = 0
        self.max_concurrent = 0
        self.guard = threading.Lock()

    def run(self, argv, *, timeout=30, max_output=128 * 1024):
        with self.guard:
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
        try:
            if self.delay and any(action in argv for action in ["start", "stop", "restart"]):
                time.sleep(self.delay)
            self.calls.append((tuple(argv), timeout, max_output))
            if "ps" in argv:
                service = argv[-1]
                state = "running" if self.active.get(service, False) else "exited"
                return CommandResult(tuple(argv), 0, json.dumps({"Service": service, "State": state}), "", 1)
            if self.reload_failure and ("kill" in argv or "exec" in argv):
                return CommandResult(tuple(argv), 1, "", "password=HiddenValue", 1)
            service = argv[-1] if argv else ""
            if "stop" in argv or "disable" in argv:
                self.active[service] = False
            elif any(action in argv for action in ["start", "restart", "up", "enable"]):
                self.active[service] = True
            return CommandResult(tuple(argv), 0, "", "", 1)
        finally:
            with self.guard:
                self.concurrent -= 1


class PortalAgentProtocolTests(unittest.TestCase):
    def setUp(self):
        self.runner = FakeRunner()
        self.dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner)
        self.app = AgentApplication(SECRET, self.dispatcher)

    def test_client_converts_socket_oserror_to_agent_error(self):
        client_socket = mock.MagicMock()
        client_socket.__enter__.return_value = client_socket
        client_socket.connect.side_effect = PermissionError("denied")
        with (
            mock.patch("portal.agent_client.socket.AF_UNIX", 1, create=True),
            mock.patch("portal.agent_client.socket.socket", return_value=client_socket),
            self.assertRaisesRegex(AgentClientError, "ошибка Unix-сокета"),
        ):
            AgentClient(Path("/run/kvn-portal/control.sock"), SECRET).call("health.host", {})

    def test_client_uses_scoped_timeout_without_changing_default(self):
        client_socket = mock.MagicMock()
        client_socket.__enter__.return_value = client_socket
        client_socket.recv.return_value = (
            json.dumps({"version": 1, "id": "fixed", "ok": True, "data": {"pong": True}}).encode("utf-8")
            + b"\n"
        )
        client = AgentClient(Path("/run/kvn-portal/control.sock"), SECRET, timeout=10)
        with (
            mock.patch("portal.agent_client.uuid.uuid4", return_value=types.SimpleNamespace(hex="fixed")),
            mock.patch("portal.agent_client.socket.AF_UNIX", 1, create=True),
            mock.patch("portal.agent_client.socket.socket", return_value=client_socket),
        ):
            self.assertEqual(client.call("ping", {}, timeout=600), {"pong": True})
        client_socket.settimeout.assert_called_once_with(600)
        self.assertEqual(client.timeout, 10)

    def decode(self, line):
        return json.loads(self.app.handle_line(line).decode("utf-8"))

    def test_invalid_secret_version_method_and_schema_do_not_run_commands(self):
        cases = [
            request_line("ping", secret="wrong"),
            request_line("ping", version=99),
            request_line("arbitrary.shell"),
            json.dumps({"version": 1, "id": "x", "secret": SECRET, "method": "ping", "params": []}).encode() + b"\n",
            b"not-json\n",
        ]
        codes = [self.decode(line)["error"]["code"] for line in cases]
        self.assertEqual(
            codes,
            ["unauthorized", "invalid_version", "method_not_found", "invalid_params", "invalid_json"],
        )
        self.assertEqual(self.runner.calls, [])

    def test_user_activity_maps_adapters_and_redacts_runtime_identifiers(self):
        runner = ActivityRunner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, control=ActivityControl())
        response = dispatcher.dispatch(RpcRequest("activity", "user.activity", {"name": "Alice"}))
        systems = {item["system"]: item for item in response["systems"]}
        self.assertEqual(systems["tls"]["uplink_bytes"], 120)
        self.assertEqual(systems["hysteria"]["connections"], 2)
        self.assertEqual(systems["telemt"]["rx_bytes"], 30)
        self.assertEqual(systems["amneziawg"]["status"], "active")
        self.assertEqual(systems["wireguard"]["status"], "stale")
        self.assertEqual(systems["ocserv"]["status"], "active")
        self.assertEqual(systems["mtg"]["status"], "unsupported")
        serialized = json.dumps(response, ensure_ascii=False)
        for forbidden in [
            "198.51.100", "preshared-secret", "must-not-leak", "internal-hysteria-secret",
            "private_key", "password", "999999",
        ]:
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(response["privacy"]["client_endpoints"], "hidden")
        self.assertTrue(all(call[1] <= 3 and call[2] <= 32 * 1024 for call in runner.calls))

    def test_user_activity_partial_failure_does_not_hide_other_adapters(self):
        runner = ActivityRunner(fail_telemt=True)
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, control=ActivityControl())
        response = dispatcher.dispatch(RpcRequest("activity", "user.activity", {"name": "Alice"}))
        systems = {item["system"]: item for item in response["systems"]}
        self.assertEqual(systems["telemt"], {
            "system": "telemt", "status": "unavailable", "source": "telemt-metrics", "reason": "api_unavailable",
        })
        self.assertEqual(systems["wireguard"]["rx_bytes"], 70)
        self.assertEqual(systems["mtg"]["reason"], "shared_secret_has_no_attribution")
        self.assertNotIn("must-not-leak", json.dumps(response))

    def test_user_activity_rejects_unknown_or_extra_params_before_commands(self):
        runner = ActivityRunner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, control=ActivityControl())
        for params, code in [
            ({"name": "Alice", "command": "id"}, "invalid_params"),
            ({"name": "Missing"}, "not_found"),
        ]:
            with self.subTest(params=params), self.assertRaises(ProtocolError) as caught:
                dispatcher.dispatch(RpcRequest("activity", "user.activity", params))
            self.assertEqual(caught.exception.code, code)
        self.assertEqual(runner.calls, [])

    def test_user_activity_total_timeout_and_large_output_are_bounded(self):
        runner = ActivityRunner(slow_telemt=True, huge_telemt=True)
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, control=ActivityControl())
        with mock.patch("portal.agent.USER_ACTIVITY_TOTAL_TIMEOUT", 0.01):
            response = dispatcher.dispatch(RpcRequest("activity", "user.activity", {"name": "Alice"}))
        systems = {item["system"]: item for item in response["systems"]}
        self.assertEqual(systems["telemt"]["reason"], "total_timeout")
        self.assertLess(len(json.dumps(response)), 32 * 1024)

    def test_oversized_request_is_rejected_before_dispatch(self):
        response = self.decode(b"{" + b"x" * MAX_REQUEST_BYTES + b"}\n")
        self.assertEqual(response["error"]["code"], "request_too_large")
        self.assertEqual(self.runner.calls, [])

    def test_adversarial_parameter_matrix_never_becomes_subprocess_argv(self):
        payloads = [
            "../etc/passwd", "../../root", ";id", "$(id)", "`id`",
            "xray\nrestart", "xray\x00restart", "--project-directory=/tmp",
            "A" * 4096,
        ]
        for index, payload in enumerate(payloads):
            vectors = [
                ("service.status", {"service": payload}),
                ("service.action", {"service": payload, "action": "restart"}),
                ("service.action", {"service": "xray", "action": payload}),
                ("logs.tail", {"service": payload, "tail": 50, "since_minutes": 5}),
                ("certificate.action", {"action": payload, "target": "site"}),
                ("state.reconcile", {"command": payload}),
                ("maintenance.run", {"command": payload}),
                ("maintenance.run", {"command": "compose_ps", "argv": payload}),
                ("shell.open", {"root_password": "x", "session_owner": payload}),
                ("shell.read", {"shell_id": payload, "session_owner": "a" * 64}),
                ("shell.write", {"shell_id": "b" * 32, "session_owner": payload, "data": "id\n"}),
                ("shell.write", {"shell_id": "b" * 32, "session_owner": "a" * 64, "data": "id\n", "argv": payload}),
            ]
            for vector, (method, params) in enumerate(vectors):
                response = self.decode(request_line(method, params, request_id=f"fuzz-{index}-{vector}"))
                self.assertFalse(response["ok"], (method, payload, response))
        self.assertEqual(self.runner.calls, [])

    def test_maintenance_console_is_allowlisted_and_fixed_argv(self):
        listed = self.decode(request_line("maintenance.commands", request_id="maint-list"))
        self.assertTrue(listed["ok"])
        commands = {item["id"]: item for item in listed["data"]["commands"]}
        self.assertIn("compose_ps", commands)
        self.assertTrue(commands["kvn_reconcile"]["requires_confirmation"])
        self.assertFalse(commands["compose_ps"]["requires_confirmation"])
        self.assertNotIn("argv", json.dumps(listed))

        denied = self.decode(request_line("maintenance.run", {"command": ";id"}, request_id="maint-deny"))
        extra = self.decode(request_line("maintenance.run", {"command": "compose_ps", "extra": "x"}, request_id="maint-extra"))
        self.assertEqual(denied["error"]["code"], "policy_denied")
        self.assertEqual(extra["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

        ran = self.decode(request_line("maintenance.run", {"command": "compose_ps"}, request_id="maint-run"))
        self.assertTrue(ran["ok"])
        argv = self.runner.calls[-1][0]
        self.assertEqual(argv[:2], ("docker", "compose"))
        self.assertIn("ps", argv)
        self.assertNotIn(";id", " ".join(argv))
        self.assertEqual(ran["data"]["id"], "compose_ps")

    def test_root_shell_requires_password_and_never_exposes_it(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner)
        owner = "a" * 64
        password = "RootPassword-2026"
        fake = RootShellSession(
            "b" * 32, owner, 123456, -1, time.monotonic(), time.monotonic(), threading.Lock()
        )

        with (
            mock.patch.object(dispatcher, "_verify_root_password", return_value=False) as verify,
            mock.patch.object(dispatcher, "_spawn_root_shell") as spawn,
            self.assertRaises(ProtocolError) as denied,
        ):
            dispatcher._shell_open({"root_password": password, "session_owner": owner, "rows": 24, "cols": 100})
        self.assertEqual(denied.exception.code, "root_password_denied")
        verify.assert_called_once()
        spawn.assert_not_called()

        with self.assertRaises(ProtocolError) as extra:
            dispatcher._shell_open({"root_password": password, "session_owner": owner, "argv": ["id"]})
        self.assertEqual(extra.exception.code, "invalid_params")

        with (
            mock.patch.object(dispatcher, "_verify_root_password", return_value=True),
            mock.patch.object(dispatcher, "_spawn_root_shell", return_value=fake),
            mock.patch.object(dispatcher, "_read_shell_locked", return_value=("# ", True, None)),
        ):
            opened = dispatcher._shell_open({"root_password": password, "session_owner": owner, "rows": 24, "cols": 100})

        self.assertTrue(opened["ok"])
        self.assertEqual(opened["shell_id"], "b" * 32)
        encoded = json.dumps(opened)
        self.assertNotIn(password, encoded)
        self.assertNotIn("root_password", encoded)
        self.assertNotIn("argv", encoded)

    def test_root_password_verification_falls_back_to_systemd_su_after_crypt_miss(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner)
        fake_crypt = types.SimpleNamespace(crypt=mock.Mock(return_value="wrong-hash"))

        with (
            mock.patch.object(dispatcher, "_root_shadow_hash", return_value="$y$j9T$hash"),
            mock.patch.dict("sys.modules", {"crypt": fake_crypt}),
            mock.patch.object(dispatcher, "_verify_root_password_with_systemd_su", return_value=True) as systemd_su,
            mock.patch.object(dispatcher, "_verify_root_password_with_su") as local_su,
        ):
            self.assertTrue(dispatcher._verify_root_password("RootPassword-2026"))

        fake_crypt.crypt.assert_called_once_with("RootPassword-2026", "$y$j9T$hash")
        systemd_su.assert_called_once_with("RootPassword-2026")
        local_su.assert_not_called()

    def test_root_password_verification_tries_local_su_when_systemd_su_rejects(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner)
        fake_crypt = types.SimpleNamespace(crypt=mock.Mock(return_value="wrong-hash"))

        with (
            mock.patch.object(dispatcher, "_root_shadow_hash", return_value="$y$j9T$hash"),
            mock.patch.dict("sys.modules", {"crypt": fake_crypt}),
            mock.patch.object(dispatcher, "_verify_root_password_with_systemd_su", return_value=False) as systemd_su,
            mock.patch.object(dispatcher, "_verify_root_password_with_su", return_value=True) as local_su,
        ):
            self.assertTrue(dispatcher._verify_root_password("RootPassword-2026"))

        systemd_su.assert_called_once_with("RootPassword-2026")
        local_su.assert_called_once_with("RootPassword-2026")

    def test_sni_apply_rejects_extra_params_before_control(self):
        response = self.decode(request_line(
            "sni.apply",
            {"action": "add-alias", "revision": "a" * 64, "system": "tls", "sni": "example.com", "argv": ";id"},
        ))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

    def test_protocol_apply_is_exactly_allowlisted_and_typed(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner, FakeServiceControl())
        app = AgentApplication(SECRET, dispatcher)
        params = {"action": "set-xhttp-mode", "system": "reality-xhttp", "mode": "stream-up", "revision": "a" * 64}
        allowed = json.loads(app.handle_line(request_line("protocol.apply", params)).decode("utf-8"))
        denied = json.loads(app.handle_line(request_line("protocol.apply", {**params, "backend": "attacker:443"})).decode("utf-8"))
        self.assertTrue(allowed["ok"])
        self.assertEqual(allowed["data"]["protocol"]["xhttp_mode"], "stream-up")
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

    def test_mtproto_methods_are_typed_and_do_not_accept_command_fields(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner, FakeServiceControl())
        app = AgentApplication(SECRET, dispatcher)
        status = json.loads(app.handle_line(request_line("mtproto.status", {})).decode("utf-8"))
        diagnosis = json.loads(app.handle_line(request_line(
            "mtproto.diagnose", {"system": "mtg"}
        )).decode("utf-8"))
        applied = json.loads(app.handle_line(request_line(
            "mtproto.apply",
            {"system": "telemt", "origin": "local-site", "revision": "a" * 64},
        )).decode("utf-8"))
        denied = json.loads(app.handle_line(request_line(
            "mtproto.apply",
            {"system": "mtg", "origin": "external", "revision": "a" * 64, "argv": ";id"},
        )).decode("utf-8"))

        self.assertTrue(status["ok"])
        self.assertTrue(diagnosis["ok"])
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["data"]["origin"], "local-site")
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

    def test_network_topology_is_allowlisted_and_rejects_parameters(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner, FakeServiceControl())
        app = AgentApplication(SECRET, dispatcher)
        allowed = json.loads(app.handle_line(request_line("network.topology", {})).decode("utf-8"))
        denied = json.loads(
            app.handle_line(request_line("network.topology", {"path": "../../root"})).decode("utf-8")
        )
        self.assertTrue(allowed["ok"])
        self.assertEqual(allowed["data"]["revision"], "a" * 64)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

    def test_client_export_settings_and_update_are_exactly_typed(self):
        dispatcher = AgentDispatcher(
            Path("/srv/kvn"), self.runner, FakeServiceControl(),
        )
        app = AgentApplication(SECRET, dispatcher)
        settings = json.loads(app.handle_line(request_line(
            "client.export.settings", {},
        )).decode("utf-8"))
        denied_read = json.loads(app.handle_line(request_line(
            "client.export.settings", {"path": "../../users.json"},
        )).decode("utf-8"))
        params = {
            "revision": "a" * 64,
            "address_mode": "public-ip",
            "public_ip": "8.8.4.4",
            "include_alternate": True,
        }
        updated = json.loads(app.handle_line(request_line(
            "client.export.update", params,
        )).decode("utf-8"))
        denied_update = json.loads(app.handle_line(request_line(
            "client.export.update", {**params, "command": ";id"},
        )).decode("utf-8"))

        self.assertTrue(settings["ok"])
        self.assertTrue(updated["ok"])
        self.assertEqual(
            updated["data"]["settings"]["public_ip"],
            "8.8.4.4",
        )
        self.assertFalse(denied_read["ok"])
        self.assertFalse(denied_update["ok"])
        self.assertEqual(
            denied_read["error"]["code"], "invalid_params",
        )
        self.assertEqual(
            denied_update["error"]["code"], "invalid_params",
        )
        self.assertEqual(self.runner.calls, [])

    def test_domain_advice_is_read_only_and_exactly_allowlisted(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner, FakeServiceControl())
        app = AgentApplication(SECRET, dispatcher)
        allowed = json.loads(app.handle_line(request_line("domain.advice", {"zone": "gaer.loc.cc"})).decode("utf-8"))
        denied = json.loads(app.handle_line(request_line("domain.advice", {"zone": "gaer.loc.cc", "timeout": 99})).decode("utf-8"))
        self.assertTrue(allowed["ok"])
        self.assertEqual(allowed["data"]["zone"], "gaer.loc.cc")
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

    def test_reconcile_is_allowlisted_and_rejects_parameters(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner, FakeServiceControl())
        app = AgentApplication(SECRET, dispatcher)
        ok_response = json.loads(app.handle_line(request_line("state.reconcile")).decode("utf-8"))
        denied = json.loads(
            app.handle_line(request_line("state.reconcile", {"path": "../../root"})).decode("utf-8")
        )
        self.assertTrue(ok_response["ok"])
        self.assertEqual(ok_response["data"]["apply"]["outcome"], "no-op")
        self.assertEqual(denied["error"]["code"], "invalid_params")
        self.assertEqual(self.runner.calls, [])

    def test_project_update_inspect_returns_safe_metadata_without_runner_or_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            archive = upload_dir / "kvn-vpn-deploy-test.tar.gz"
            make_safe_deploy_archive(archive)
            dispatcher = AgentDispatcher(root, self.runner)
            app = AgentApplication(SECRET, dispatcher)

            response = json.loads(app.handle_line(request_line(
                "project.update.inspect",
                {"archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz"},
            )).decode("utf-8"))

            self.assertTrue(response["ok"])
            result = response["data"]
            self.assertTrue(result["ok"])
            self.assertEqual(result["archive_kind"], "deploy")
            self.assertEqual(result["archive_name"], archive.name)
            self.assertEqual(result["archive_size"], archive.stat().st_size)
            self.assertRegex(result["archive_sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(result["archive_members"], 0)
            encoded = json.dumps(result)
            self.assertNotIn(str(root), encoded)
            self.assertNotIn("password", encoded)
            self.assertEqual(self.runner.calls, [])

    def test_project_update_inspect_rejects_paths_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            outside = root / "outside.tar.gz"
            make_safe_deploy_archive(outside)
            symlink = upload_dir / "kvn-vpn-deploy-link.tar.gz"
            try:
                symlink.symlink_to(outside)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("создание symlink требует прав Windows")
                raise
            dispatcher = AgentDispatcher(root, self.runner)

            for archive, code in [
                (str(outside.resolve()), "policy_denied"),
                ("portal-data/updates/../outside.tar.gz", "policy_denied"),
                ("portal-data/updates/unknown.tar.gz", "invalid_params"),
                ("portal-data/updates/kvn-vpn-deploy-link.tar.gz", "policy_denied"),
            ]:
                with self.subTest(archive=archive), self.assertRaises(ProtocolError) as denied:
                    dispatcher._project_update_inspect({"archive": archive})
                self.assertEqual(denied.exception.code, code)
            self.assertEqual(self.runner.calls, [])

    def test_project_update_rejects_bad_archive_before_unit(self):
        for malicious in ("traversal", "runtime", "link", "device"):
            with self.subTest(malicious=malicious), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                upload_dir = root / "portal-data" / "updates"
                upload_dir.mkdir(parents=True)
                archive = upload_dir / "kvn-vpn-deploy-test.tar.gz"
                make_safe_deploy_archive(archive, malicious=malicious)
                dispatcher = AgentDispatcher(root, self.runner)
                with self.assertRaises(ProtocolError) as denied:
                    dispatcher._project_update_inspect({
                        "archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz",
                    })
                self.assertEqual(denied.exception.code, "invalid_archive")
                self.assertEqual(self.runner.calls, [])

    def test_project_update_reports_exact_missing_bootstrap_before_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            archive = upload_dir / "kvn-vpn-deploy-test.tar.gz"
            make_safe_deploy_archive(archive, missing="tools/canonical-files.txt")
            dispatcher = AgentDispatcher(root, self.runner)
            with self.assertRaises(ProtocolError) as denied:
                dispatcher._project_update_inspect({
                    "archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz",
                })
            self.assertEqual(denied.exception.code, "invalid_archive")
            self.assertIn("tools/canonical-files.txt", denied.exception.message)
            self.assertEqual(self.runner.calls, [])

    def test_project_update_requires_root_reauthentication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            archive = upload_dir / "kvn-vpn-deploy-test.tar.gz"
            make_safe_deploy_archive(archive)
            dispatcher = AgentDispatcher(root, self.runner)
            password = "RootPassword-2026"

            with mock.patch.object(dispatcher, "_verify_root_password", return_value=False):
                with self.assertRaises(ProtocolError) as denied:
                    dispatcher._project_update({
                        "archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz",
                        "root_password": password,
                        "session_owner": "a" * 64,
                    })
            self.assertEqual(denied.exception.code, "root_password_denied")
            self.assertEqual(self.runner.calls, [])

    def test_project_update_schedules_verified_archive_without_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            archive = upload_dir / "kvn-vpn-deploy-test.tar.gz"
            make_safe_deploy_archive(archive)
            dispatcher = AgentDispatcher(root, self.runner)
            password = "RootPassword-2026"
            inspected = dispatcher._project_update_inspect({
                "archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz",
            })

            with mock.patch.object(dispatcher, "_verify_root_password", return_value=True):
                result = dispatcher._project_update({
                    "archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz",
                    "root_password": password,
                    "session_owner": "a" * 64,
                    "expected_sha256": inspected["archive_sha256"].upper(),
                })

            self.assertTrue(result["ok"])
            self.assertEqual(result["archive"], "portal-data/updates/kvn-vpn-deploy-test.tar.gz")
            self.assertEqual(result["archive_name"], archive.name)
            self.assertEqual(result["archive_size"], archive.stat().st_size)
            self.assertRegex(result["archive_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(result["mode"], "full")
            self.assertIn("--bootstrap-only", result["recovery_command"])
            argv = self.runner.calls[-1][0]
            self.assertEqual(argv[0], "systemd-run")
            self.assertIn("-ceu", argv)
            command_text = "\n".join(argv)
            self.assertIn("tar --extract --gzip", command_text)
            self.assertIn("KVN_UPDATE_INSPECTOR", command_text)
            self.assertIn("canonical-files.txt", command_text)
            self.assertIn("KVN_UPDATE_ROOT=\"$project_root\"", command_text)
            self.assertIn(str(root), argv)
            self.assertIn(str(archive.resolve()), argv)
            self.assertNotIn(password, command_text)
            self.assertNotIn(password, json.dumps(result))
            self.assertNotIn("root_password", json.dumps(result))
            with mock.patch.object(dispatcher, "_verify_root_password", return_value=True):
                with self.assertRaisesRegex(Exception, "Абсолютный путь"):
                    dispatcher._project_update({
                        "archive": str(archive.resolve()),
                        "root_password": password,
                        "session_owner": "a" * 64,
                    })

    def test_project_update_rejects_changed_archive_before_unit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            archive = upload_dir / "kvn-vpn-deploy-test.tar.gz"
            make_safe_deploy_archive(archive)
            dispatcher = AgentDispatcher(root, self.runner)

            with mock.patch.object(dispatcher, "_verify_root_password", return_value=True):
                with self.assertRaises(ProtocolError) as denied:
                    dispatcher._project_update({
                        "archive": "portal-data/updates/kvn-vpn-deploy-test.tar.gz",
                        "root_password": "RootPassword-2026",
                        "session_owner": "a" * 64,
                        "expected_sha256": "0" * 64,
                    })
            self.assertEqual(denied.exception.code, "archive_changed")
            self.assertEqual(self.runner.calls, [])

    def test_project_update_accepts_full_release_and_reports_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upload_dir = root / "portal-data" / "updates"
            upload_dir.mkdir(parents=True)
            built = make_release(root / "builder")
            archive = upload_dir / "kvn-vpn-release-linux-amd64-test.tar.gz"
            archive.write_bytes(built.read_bytes())
            dispatcher = AgentDispatcher(root, self.runner)
            inspected = dispatcher._project_update_inspect({
                "archive": "portal-data/updates/kvn-vpn-release-linux-amd64-test.tar.gz",
            })
            self.assertEqual(inspected["archive_kind"], "release")
            self.assertEqual(inspected["release_source"]["name"], "kvn-vpn-deploy.tar.gz")
            self.assertEqual(self.runner.calls, [])
            with mock.patch.object(dispatcher, "_verify_root_password", return_value=True):
                result = dispatcher._project_update({
                    "archive": "portal-data/updates/kvn-vpn-release-linux-amd64-test.tar.gz",
                    "mode": "full",
                    "root_password": "RootPassword-2026",
                    "session_owner": "a" * 64,
                })
            self.assertTrue(result["ok"])
            self.assertEqual(result["archive_kind"], "release")
            self.assertEqual(result["release_source"]["name"], "kvn-vpn-deploy.tar.gz")
            self.assertEqual(result["release_images"]["name"], "kvn-vpn-images-linux-amd64.tar")
            argv = self.runner.calls[-1][0]
            self.assertIn("release", argv)
            self.assertIn(str(archive), argv)

    def test_project_backup_is_allowlisted_and_uses_server_defined_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "tools" / "project-backup.sh"
            script.parent.mkdir(parents=True)
            script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            dispatcher = AgentDispatcher(root, self.runner)

            with self.assertRaises(ProtocolError) as denied:
                dispatcher._project_backup({"archive": "../../root"})
            self.assertEqual(denied.exception.code, "invalid_params")
            self.assertEqual(self.runner.calls, [])

            response = self.decode(request_line("project.backup", request_id="backup"))
            self.assertFalse(response["ok"])
            # The dispatcher instance used by self.app points to /srv/kvn and has no script.
            self.runner.calls.clear()
            result = dispatcher._project_backup({})

            self.assertTrue(result["ok"])
            self.assertEqual(result["action"], "backup")
            self.assertIn("kvn-project-backup-", result["unit"])
            argv = self.runner.calls[-1][0]
            self.assertEqual(argv[0], "systemd-run")
            self.assertIn(f"--property=WorkingDirectory={root.resolve()}", argv)
            self.assertIn("/bin/bash", argv)
            self.assertIn(str(script.resolve()), argv)
            self.assertNotIn("../../root", " ".join(argv))

    def test_backup_list_returns_safe_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            backup_dir = Path(tmp) / "backup"
            backup_dir.mkdir()
            good = backup_dir / "kvn-vpn-backup-20260702-host.tar"
            good.write_bytes(b"tar-content")
            (backup_dir / "kvn-vpn-backup-20260702-host.tar.gz").write_bytes(b"wrong")
            (backup_dir / "notes.txt").write_text("ignore", encoding="utf-8")
            dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner)

            with mock.patch.dict(os.environ, {"KVN_BACKUP_DIR": str(backup_dir)}):
                result = dispatcher._backup_list({})

            self.assertTrue(result["available"])
            self.assertEqual(len(result["backups"]), 1)
            item = result["backups"][0]
            self.assertEqual(item["name"], good.name)
            self.assertEqual(item["size"], len(b"tar-content"))
            self.assertEqual(set(item), {"name", "size", "mtime", "readable"})
            self.assertNotIn("content", json.dumps(result))
            self.assertNotIn("members", json.dumps(result))
            with self.assertRaises(ProtocolError):
                dispatcher._backup_list({"path": "../../root"})

    def test_service_status_and_actions_use_server_defined_argv(self):
        status = self.decode(request_line("service.status", {"service": "xray"}))
        restart = self.decode(request_line("service.action", {"service": "xray", "action": "restart"}, request_id="req-2"))
        self.assertTrue(status["ok"])
        self.assertTrue(status["data"]["enabled"])
        self.assertTrue(restart["data"]["ok"])
        argv = [call[0] for call in self.runner.calls]
        compose_file = str(Path("/srv/kvn").resolve() / "docker-compose.yml")
        compose_prefix = ("docker", "compose", "--project-directory", str(Path("/srv/kvn").resolve()), "-f", compose_file)
        self.assertIn((*compose_prefix, "ps", "--format", "json", "xray"), argv)
        self.assertIn((*compose_prefix, "restart", "xray"), argv)
        data = restart["data"]
        for field in ["before", "after", "health", "duration_ms", "correlation_id"]:
            self.assertIn(field, data)
        self.assertTrue(data["health"]["ok"])

    def test_wireguard_apply_uses_control_force_sync_path(self):
        control = FakeServiceControl()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), self.runner, control)
        result = dispatcher._service_action({"service": "wireguard", "action": "apply"})

        self.assertTrue(result["ok"])
        self.assertEqual(control.applied_services, ["wireguard"])
        self.assertEqual(result["apply"]["outcome"], "applied")
        self.assertEqual(result["health"], {"ok": True, "expected_active": True})

    def test_apply_action_is_denied_for_non_host_vpn_service(self):
        response = self.decode(request_line("service.action", {"service": "xray", "action": "apply"}))

        self.assertEqual(response["error"]["code"], "policy_denied")

    def test_self_lockout_and_unknown_service_are_denied_before_runner(self):
        for index, params in enumerate(
            [
                {"service": "nginx", "action": "stop"},
                {"service": "portal", "action": "disable"},
                {"service": "agent", "action": "stop"},
                {"service": "../../root", "action": "restart"},
            ]
        ):
            response = self.decode(request_line("service.action", params, request_id=f"deny-{index}"))
            self.assertEqual(response["error"]["code"], "policy_denied")
        self.assertEqual(self.runner.calls, [])

    def test_reload_success_has_no_restart_and_failure_has_one_fallback(self):
        for fails, expected in [(False, 0), (True, 1)]:
            with self.subTest(fails=fails):
                runner = StatefulRunner(reload_failure=fails)
                dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, FakeServiceControl())
                result = dispatcher._service_action({"service": "nginx", "action": "reload"})
                restarts = [call for call, _timeout, _max in runner.calls if "restart" in call]
                self.assertEqual(len(restarts), expected)
                self.assertEqual(result["fallback"] is not None, fails)
                self.assertTrue(result["health"]["ok"])

    def test_disable_is_persistent_and_reconcile_keeps_service_stopped(self):
        control = FakeServiceControl()
        runner = StatefulRunner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, control)
        result = dispatcher._service_action({"service": "xray", "action": "disable"})
        self.assertTrue(result["ok"])
        self.assertFalse(control.preferences["xray"])
        calls = [call for call, _timeout, _max in runner.calls]
        self.assertIn(("docker", "update", "--restart=no", "xray"), calls)
        runner.calls.clear()
        reconciled = AgentDispatcher(Path("/srv/kvn"), runner, control).reconcile_services()
        self.assertFalse(runner.active["xray"])
        self.assertTrue(reconciled[0]["ok"])
        self.assertFalse(any("start" in call or "up" in call for call, _timeout, _max in runner.calls))

    def test_self_restart_returns_warning_and_delayed_agent_command(self):
        runner = StatefulRunner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner, FakeServiceControl())
        nginx = dispatcher._service_action({"service": "nginx", "action": "restart"})
        agent = dispatcher._service_action({"service": "agent", "action": "restart"})
        self.assertTrue(nginx["warning"])
        self.assertTrue(agent["warning"])
        self.assertEqual(agent["command"]["argv"][0], "systemd-run")

    def test_typed_logs_stats_health_and_awg_responses(self):
        responses = [
            self.decode(request_line("logs.tail", {"service": "xray", "tail": 50, "since_minutes": 5}, request_id="logs")),
            self.decode(request_line("stats.containers", request_id="stats")),
            self.decode(request_line("health.host", request_id="health")),
            self.decode(request_line("amneziawg.status", request_id="awg")),
        ]
        self.assertTrue(all(response["ok"] for response in responses))
        self.assertEqual(responses[0]["data"]["tail"], 50)
        containers = {item["Name"]: item for item in responses[1]["data"]["containers"]}
        self.assertIn("xray", containers)
        self.assertEqual(containers["xray"]["state"], "running")
        self.assertEqual(set(responses[2]["data"]), {"uptime", "memory", "disk"})
        self.assertTrue(responses[3]["data"]["available"])

    def test_container_stats_include_missing_container_without_failing_all(self):
        class MissingOneRunner(FakeRunner):
            def run(self, argv, *, timeout=30, max_output=128 * 1024):
                if argv[:2] == ["docker", "inspect"] and "xray" in argv[4:]:
                    self.calls.append((tuple(argv), timeout, max_output))
                    stdout = "".join(
                        f"/{name}\trunning\tnone\t0\n" for name in argv[4:] if name != "xray"
                    )
                    return CommandResult(tuple(argv), 1, stdout, "not found", 1)
                return super().run(argv, timeout=timeout, max_output=max_output)

        dispatcher = AgentDispatcher(Path("/srv/kvn"), MissingOneRunner())
        data = dispatcher._container_stats({})
        rows = {item["Name"]: item for item in data["containers"]}

        self.assertTrue(data["available"])
        self.assertEqual(rows["xray"]["state"], "missing")
        self.assertEqual(len(rows), 7)
        inspect_calls = [call for call, _timeout, _max in dispatcher.runner.calls if call[:2] == ("docker", "inspect")]
        self.assertEqual(len(inspect_calls), 1)

    def test_container_inspect_template_uses_real_tabs(self):
        dispatcher = AgentDispatcher(Path("/srv/kvn"), FakeRunner())
        dispatcher._container_stats({})
        inspect_call = next(call for call, _timeout, _max in dispatcher.runner.calls if call[:2] == ("docker", "inspect"))
        self.assertIn("\t", inspect_call[3])
        self.assertNotIn("\\t", inspect_call[3])

    def test_output_redaction_removes_ansi_controls_and_secrets(self):
        source = "\x1b[31mpassword=TopSecret\x00 token:abc private_key=xyz uuid=123\x1b[0m"
        cleaned = sanitize_text(source)
        self.assertNotIn("TopSecret", cleaned)
        self.assertNotIn("abc", cleaned)
        self.assertNotIn("xyz", cleaned)
        self.assertNotIn("uuid=123", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x00", cleaned)

    def test_agent_uses_unix_socket_not_tcp(self):
        if not hasattr(socket, "AF_UNIX"):
            self.skipTest("AF_UNIX недоступен")
        with tempfile.TemporaryDirectory() as tmp:
            socket_path = Path(tmp) / "control.sock"
            with ThreadingUnixServer(socket_path, self.app) as server:
                self.assertEqual(server.socket.family, socket.AF_UNIX)
                self.assertTrue(socket_path.exists())

    def test_request_handler_ignores_client_disconnect_on_response(self):
        class BrokenWriter:
            def write(self, _data):
                raise BrokenPipeError(32, "Broken pipe")

        handler = AgentRequestHandler.__new__(AgentRequestHandler)
        handler.rfile = io.BytesIO(request_line("ping"))
        handler.wfile = BrokenWriter()
        handler.server = types.SimpleNamespace(application=self.app)

        handler.handle()


class ConcurrencyDispatcher:
    def __init__(self):
        self.lock = threading.Lock()
        self.active_mutations = 0
        self.max_mutations = 0
        self.active_reads = 0
        self.max_reads = 0

    def dispatch(self, request: RpcRequest):
        is_mutation = request.method == "service.action"
        with self.lock:
            if is_mutation:
                self.active_mutations += 1
                self.max_mutations = max(self.max_mutations, self.active_mutations)
            else:
                self.active_reads += 1
                self.max_reads = max(self.max_reads, self.active_reads)
        time.sleep(0.05)
        with self.lock:
            if is_mutation:
                self.active_mutations -= 1
            else:
                self.active_reads -= 1
        return {"ok": True}


class PortalAgentConcurrencyTests(unittest.TestCase):
    def test_mutations_are_serialized_and_reads_can_overlap(self):
        dispatcher = ConcurrencyDispatcher()
        app = AgentApplication(SECRET, dispatcher)
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(app.handle_line, [request_line("service.action"), request_line("service.action", request_id="m2")]))
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(app.handle_line, [request_line("ping"), request_line("ping", request_id="r2")]))
        self.assertEqual(dispatcher.max_mutations, 1)
        self.assertEqual(dispatcher.max_reads, 2)

    def test_different_service_actions_are_not_globally_serialized(self):
        dispatcher = ConcurrencyDispatcher()
        app = AgentApplication(SECRET, dispatcher)
        lines = [
            request_line("service.action", {"service": "xray"}, request_id="x"),
            request_line("service.action", {"service": "hysteria"}, request_id="h"),
        ]
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(app.handle_line, lines))
        self.assertEqual(dispatcher.max_mutations, 2)


class PortalAgentInstallTests(unittest.TestCase):
    def test_install_script_hardens_unit_and_restarts_active_service(self):
        script = Path("portal/install-host-agent.sh").read_text(encoding="utf-8")
        required = [
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "Group=kvn-portal",
            "ProtectHome=tmpfs",
            "BindPaths=$ROOT_DIR",
            "/etc/amnezia/amneziawg",
            "/etc/wireguard",
            "/etc/letsencrypt",
            "/var/lib/letsencrypt",
            "/var/log/letsencrypt",
            "/etc/systemd/system",
            "MemoryDenyWriteExecute=true",
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK",
            "RuntimeDirectory=kvn-portal",
            "StateDirectory=kvn-portal",
            "--metrics-db /var/lib/kvn-portal/metrics.db",
            "chmod 0640",
            "systemctl is-active --quiet kvn-portal-agent.service",
            "systemctl restart kvn-portal-agent.service",
            "stat -c '%G' /run/kvn-portal",
            "rm -f /run/kvn-portal/control.sock",
            "Unix-сокет и RPC работают",
        ]
        for value in required:
            self.assertIn(value, script)

    def test_agent_source_has_no_arbitrary_execution_primitives(self):
        source = Path("portal/agent.py").read_text(encoding="utf-8")
        for forbidden in ["shell=True", "os.system(", "eval(", "exec("]:
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
