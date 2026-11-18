"""Проверки границы SSH-учёток без изменения хоста."""

from base64 import b64encode
from io import BytesIO
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.contracts import CORE_API_VERSION
from v5.core.maintenance.portal_rpc import PortalUpdateApplication, UpdateStoreError, _ssh_accounts
from v5.core.maintenance.ssh_accounts import AccountError, Accounts, _login, _password, _public_key, parse_transfer
from v5.portal.app import create_app


class SSHAccountsTests(TestCase):
    def test_transfer_validates_whole_file_and_imports_only_disabled(self):
        accounts = Accounts()
        sample = {"format": "ssh-accounts/v1", "accounts": [
            {"login": "existing", "status": "active", "key": ""},
            {"login": "restored", "status": "active", "key": ""},
        ]}
        rows = {"existing": {}}
        with patch.object(accounts, "load", return_value=rows), patch.object(accounts, "create") as create:
            invalid = {**sample, "accounts": [*sample["accounts"], {"login": "root", "status": "active", "key": ""}]}
            with self.assertRaises(AccountError):
                accounts.execute("import", {"archive": invalid})
            create.assert_not_called()
            create.side_effect = [AccountError("ssh_name_taken"), None]
            self.assertEqual(accounts.execute("import", {"archive": sample}),
                             {"added": ["restored"], "skipped": ["existing"], "failed": []})
            create.assert_called_with(rows, "restored", "", "", disabled=True)
        with self.assertRaises(AccountError):
            parse_transfer({**sample, "accounts": [sample["accounts"][0]] * 2})

    def test_password_change_keeps_disabled_password_locked(self):
        digest = b"$6$fixture$" + b"X" * 86
        with patch("subprocess.run", return_value=SimpleNamespace(stdout=digest + b"\n")), \
             patch("v5.core.maintenance.ssh_accounts._run", return_value=True) as run:
            Accounts.set_password("operator", "fixture-password", disabled=True)
        run.assert_called_once_with("/usr/sbin/chpasswd", "--encrypted", data=b"operator:!" + digest + b"\n")

    def test_strict_user_and_key_input(self):
        key = b64encode(b"\0\0\0\x0bssh-ed25519\0\0\0\x20" + bytes(range(32))).decode()
        self.assertEqual(_public_key(f"ssh-ed25519 {key} comment"), f"ssh-ed25519 {key}\n".encode())
        for value in ("root", "kvn-v5-web", "-a", "foo/bar", "TEST"):
            with self.assertRaises(AccountError):
                _login(value)
        for value in (f"command=x ssh-ed25519 {key}", "ssh-ed25519 YQ==", f"ssh-ed25519 {key}\nfoo"):
            with self.assertRaises(AccountError):
                _public_key(value)
        for value in ("short", "a" * 12 + "\n", "a" * 12 + ":", "a" * 12 + "\ud800"):
            with self.assertRaises(AccountError):
                _password(value)

    def test_cannot_manage_external_or_elevated_account(self):
        accounts = Accounts()
        with patch.object(accounts, "load", return_value={}):
            with self.assertRaisesRegex(AccountError, "ssh_not_managed"):
                accounts.execute("disable", {"login": "operator"})
        entry = SimpleNamespace(pw_uid=1001, pw_gid=1001, pw_gecos="tag", pw_dir="/home/operator", pw_shell="/bin/bash")
        with patch("pwd.getpwnam", return_value=entry), patch("grp.getgrgid", return_value=SimpleNamespace(gr_name="operator")), \
             patch("os.getgrouplist", return_value=[1001, 27]):
            with self.assertRaisesRegex(AccountError, "ssh_account_changed"):
                accounts.account("operator", {"uid": 1001, "gid": 1001, "mark": "tag"})

    def test_rpc_only_accepts_allowed_commands_and_exact_arguments(self):
        worker = Mock(return_value={})
        app = PortalUpdateApplication(1001, Mock(), ssh_accounts=worker)
        request = {"version": CORE_API_VERSION, "method": "ssh.disable", "params": {"login": "operator"}}
        self.assertEqual(app.dispatch(request, BytesIO()), {})
        worker.assert_called_once_with("disable", {"login": "operator"})
        for bad, body in ((request, b"extra"), ({**request, "method": "ssh.sudo"}, b""),
                          ({**request, "params": {"login": "operator", "sudo": True}}, b"")):
            with self.assertRaises(UpdateStoreError):
                app.dispatch(bad, BytesIO(body))

    def test_secret_is_only_sent_on_stdin(self):
        marker = "password-fixture-only"
        with patch("subprocess.run", return_value=SimpleNamespace(stdout=b'{"ok":true,"result":{}}')) as command:
            self.assertEqual(_ssh_accounts("create", {"login": "operator", "password": marker, "key": ""}), {})
            self.assertNotIn(marker, " ".join(command.call_args.args[0]))
            self.assertIn(marker.encode(), command.call_args.kwargs["input"])

    def test_portal_requires_admin_csrf_and_repeat_password(self):
        rpc = Mock()
        rpc.ssh_accounts.return_value = {"accounts": []}
        config = {"session_key": "synthetic", "login": "admin", "password_hash": "fixture",
                  "allowed_hosts": ["localhost:8443"], "agent_socket": "/fixture"}
        app = create_app(config, core_update_client=rpc)
        client = app.test_client()
        origin = "https://localhost:8443"
        self.assertEqual(client.get("/users/ssh-accounts", base_url=origin).status_code, 303)
        with client.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf="fixture")
        row = {"action": "disable", "login": "operator", "admin_password": "test"}
        def post(data):
            return client.post("/users/ssh-accounts", base_url=origin, headers={"Origin": origin}, data=data)
        self.assertEqual(post(row).status_code, 403)
        self.assertEqual(post({**row, "csrf": "fixture"}).status_code, 303)
        rpc.ssh_accounts.assert_not_called()
        with patch("v5.portal.app.verify_admin_password", return_value=True):
            self.assertEqual(post({**row, "csrf": "fixture"}).status_code, 303)
        rpc.ssh_accounts.assert_called_once_with("disable", login="operator")
        self.assertEqual(client.get("/users/ssh-accounts", base_url=origin).status_code, 200)

    def test_portal_transfer_and_overview(self):
        rpc, host = Mock(), Mock()
        archive = {"format": "ssh-accounts/v1", "accounts": [{"login": "operator", "status": "active", "key": ""}]}
        rpc.ssh_accounts.return_value = archive
        host.status.return_value = None
        host.package_status.side_effect = OSError
        host.observe_ssh.return_value = {"ssh": [{"user": "operator", "ip": "192.0.2.15",
                                                 "started_at": 0, "age_seconds": 3670}], "ssh_partial": False}
        config = {"session_key": "synthetic", "login": "admin", "password_hash": "fixture",
                  "allowed_hosts": ["localhost:8443"], "agent_socket": "/fixture"}
        client = create_app(config, client=host, core_update_client=rpc).test_client()
        origin = "https://localhost:8443"
        url = "/users/migration/ssh-accounts"
        with client.session_transaction(base_url=origin) as session:
            session.update(admin=True, csrf="fixture")
        with patch("v5.portal.app.verify_admin_password", return_value=True):
            exported = client.post(url, base_url=origin, headers={"Origin": origin},
                                   data={"action": "export", "csrf": "fixture", "admin_password": "demo"})
            self.assertEqual(exported.json, archive)
            self.assertIn("attachment", exported.headers["Content-Disposition"])
            rpc.ssh_accounts.return_value = {"added": ["operator"], "skipped": [], "failed": []}
            imported = client.post(url, base_url=origin, headers={"Origin": origin},
                                   data={"action": "import", "csrf": "fixture", "admin_password": "demo",
                                         "archive": (BytesIO(exported.data), "ssh-users.json")})
            self.assertEqual(imported.status_code, 303)
            rpc.ssh_accounts.assert_called_with("import", archive=archive)
        from v5.portal.rpc import AgentUnavailable
        host.package_status.side_effect = AgentUnavailable
        overview = client.get("/", base_url=origin)
        self.assertEqual(overview.status_code, 200)
        for marker in ("SSH-пользователи", "operator", "192.0.2.15", "01.01.1970 00:00:00 UTC", "1 ч 1 мин"):
            self.assertIn(marker.encode(), overview.data)
        self.assertNotIn(b"KVN", overview.data)
