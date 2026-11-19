"""Границы доверия ZeroSSL и сохранение активного центра выпуска."""

import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from v5.core.agent import AgentApplication
from v5.core.tls.acme import AcmeMode, AcmePlan, zerossl_ready
from v5.core.tls.acme_service import AcmeError, AcmeService, CertbotClient
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.queue import TLSJob, TLSQueue
from v5.core.tls.transaction import _pair_digest
from v5.core.tls.zerossl import register


HOST = TLSIdentity("portal.example", False)
IP = TLSIdentity("1.1.1.1", True)


class ZeroSSLTests(TestCase):
    def test_acme_endpoint_is_fixed_and_ip_is_not_supported(self):
        plan = AcmePlan(HOST, AcmeMode.ZEROSSL)
        public = AcmePlan(HOST, AcmeMode.PUBLIC)
        self.assertNotEqual(plan.configuration, public.configuration)
        self.assertEqual(plan.webroot, public.webroot)
        for argv in (plan.issue(""), plan.renew()):
            self.assertIn("https://acme.zerossl.com/v2/DV90", argv)
            self.assertNotIn("--eab-hmac-key", argv)
        with self.assertRaises(ValueError):
            AcmePlan(IP, AcmeMode.ZEROSSL)

    def test_existing_public_queue_is_accepted_and_new_provider_requires_an_account(self):
        with TemporaryDirectory() as directory:
            queue = TLSQueue(Path(directory))
            app = AgentApplication(1001, tls=queue, tls_registry=lambda: ((IP, HOST), False))
            payload = {"name": HOST.name, "mode": "zerossl", "email": ""}
            with patch("v5.core.agent.zerossl_ready", return_value=False):
                self.assertEqual(app._tls_dispatch("tls.issue", payload, None)["error"], "zerossl_not_configured")
                self.assertFalse(queue.pending.exists())
            with patch("v5.core.agent.zerossl_ready", return_value=True):
                self.assertEqual(app._tls_dispatch("tls.issue", {**payload, "name": IP.name}, None)["error"],
                                 "invalid_request")
                self.assertTrue(app._tls_dispatch("tls.issue", payload, None)["ok"])
                self.assertEqual(queue.take((IP, HOST)), TLSJob(HOST, AcmeMode.ZEROSSL, ""))
                public = {**payload, "name": IP.name, "mode": "public"}
                self.assertTrue(app._tls_dispatch("tls.issue", public, None)["ok"])
                self.assertEqual(queue.take((IP, HOST)), TLSJob(IP, AcmeMode.PUBLIC, ""))

    def test_registration_cleans_secrets_and_keeps_only_certbot_account(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            client = CertbotClient(root=root)
            account = root / "zerossl/config/accounts/acme.zerossl.com/v2/DV90" / ("a" * 32)
            key = "fake-hmac-for-unit-test"
            paths = []

            def command(argv, timeout):
                self.assertEqual(argv[1], "register")
                self.assertIn(AcmeMode.ZEROSSL.endpoint, argv)
                self.assertFalse(any(key in item for item in argv))
                config = Path(argv[argv.index("--config") + 1])
                paths.append(config)
                self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(config.parent.stat().st_mode), 0o700)
                self.assertIn(key, config.read_text())
                account.mkdir(parents=True)
                for name in ("private_key.json", "regr.json", "meta.json"):
                    (account / name).touch()

            with patch.object(client, "_require_version"), patch.object(client, "_call", side_effect=command):
                self.assertFalse(zerossl_ready(root))
                register(client, "fixture-kid", key, "")
                self.assertTrue(zerossl_ready(root))
                self.assertFalse(paths[0].exists())
                with self.assertRaises(ValueError):
                    register(client, "injected\nserver=other", key, "")
            self.assertFalse((root / "public").exists())

    def test_failed_apply_preserves_active_ca_and_renewals_use_only_active_provider(self):
        material = b"test-chain", b"test-key"
        candidate = _pair_digest(*material)
        previous = "0" * 64
        with TemporaryDirectory() as directory:
            root = Path(directory)
            markers = root / "provider.json"
            gateway = Mock(identities=(HOST,))
            gateway.generation.return_value = previous
            client = Mock(spec=CertbotClient)
            client.plan.side_effect = lambda name, mode: AcmePlan(name, mode, root=root)
            client.issue.return_value = material
            client.renew.return_value = material
            manager = AcmeService(gateway, client, zerossl_path=markers)
            with patch.object(manager, "_activate", side_effect=AcmeError("fixture_failure")), self.assertRaises(AcmeError):
                manager.issue(HOST, AcmeMode.ZEROSSL, "")
            manager = AcmeService(gateway, client, zerossl_path=markers)
            self.assertIs(manager.renewal_mode(HOST), AcmeMode.PUBLIC)
            for mode in (AcmeMode.PUBLIC, AcmeMode.ZEROSSL):
                lineage = AcmePlan(HOST, mode, root=root).candidate[0]
                lineage.parent.mkdir(parents=True)
                lineage.touch()
            with patch.object(manager, "_activate"):
                manager.renew_due()
                self.assertIs(client.renew.call_args.args[0].mode, AcmeMode.PUBLIC)
                gateway.generation.return_value = candidate
                manager.renew_due()
                self.assertIs(client.renew.call_args.args[0].mode, AcmeMode.ZEROSSL)
                client.renew.reset_mock()
                self.assertEqual(manager.renew_due({HOST.slot: [candidate]}), {})
                client.renew.assert_not_called()
