"""Проверки границы SSH-учёток без изменения хоста."""

from base64 import b64encode
from io import BytesIO
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.contracts import CORE_API_VERSION
from v5.core.maintenance.portal_rpc import PortalUpdateApplication, UpdateStoreError, _ssh_accounts
from v5.core.maintenance.ssh_accounts import AccountError, Accounts, _login, _password, _public_key
from v5.portal.app import create_app


class SSHAccountsTests(TestCase):
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
