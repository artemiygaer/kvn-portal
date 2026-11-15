"""Проверки TLS на настоящих X.509, без production-ключей и CA."""

from ipaddress import ip_address
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from v5.core.tls.acme import AcmeMode, AcmePlan, require_certbot_version
from v5.core.tls.acme_service import AcmeError, AcmeService, CertbotClient
from v5.core.tls.certificates import CertificateError, validate_pair
from v5.core.tls.controller import GatewayController
from v5.core.tls.gateway import render_gateway
from v5.core.tls.http01 import render_http01
from v5.core.tls.identity import TLSIdentity
from v5.core.tls.transaction import CertificateStore, GatewayApplyError, StoredPair, publish_gateway


def openssl(*arguments: str) -> None:
    subprocess.run(["/usr/bin/openssl", *arguments], check=True, capture_output=True, timeout=15)


class TLSIdentityTests(unittest.TestCase):
    def test_gateway_module_actions_keep_timeout_after_future_core_updates(self):
        config = render_gateway((TLSIdentity('portal.example', False),), ipv6=False)
        self.assertIn('location ~ "^/modules/[a-z_]+$"', config)
        self.assertIn('location = /modules/upload', config)
        self.assertIn('proxy_read_timeout 350s;', config)

    def test_gateway_rewriters_may_check_privileged_listeners(self):
        units = Path(__file__).resolve().parents[2] / 'v5/install/systemd'
        for name in ('kvn-v5-tls.service', 'kvn-v5-tls-renew.service',
                     'kvn-v5-lifecycle@.service', 'kvn-v5-reconcile.service'):
            with self.subTest(unit=name):
                row = next(line for line in (units / name).read_text().splitlines()
                           if line.startswith('CapabilityBoundingSet='))
                self.assertIn('CAP_NET_BIND_SERVICE', row.split('=', 1)[1].split())

    def test_dns_ip_and_authority_are_canonical(self):
        self.assertEqual(TLSIdentity("BÜCHER.Example.", False).name, "xn--bcher-kva.example")
        address = TLSIdentity("2001:0DB8:0:0::5", True)
        self.assertEqual(address.name, "2001:db8::5")
        self.assertEqual(address.authority, "[2001:db8::5]")
        self.assertEqual(address.slot, "ip-2001_db8__5")

    def test_rejects_wildcards_injection_and_non_unicast(self):
        invalid = (("*.example.net", False), ("a.example\n;return", False), ("a.example:8443", False),
                   ("192.0.2.1", False), ("fe80::2%eth0", True), ("::", True), ("224.1.2.3", True))
        for name, is_ip in invalid:
            with self.subTest(name=name), self.assertRaises(ValueError):
                TLSIdentity(name, is_ip)

    def test_maximum_dns_name_keeps_a_bounded_acme_lineage(self):
        name = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        self.assertEqual(len(name), 253)
        self.assertTrue(TLSIdentity(name, False).slot.startswith("dns-sha256-"))
        self.assertNotEqual(TLSIdentity(name, False).slot, TLSIdentity(name[:-1] + "z", False).slot)


class AcmeTests(unittest.TestCase):
    def test_staging_and_public_use_distinct_lineages_and_pinned_endpoints(self):
        identity = TLSIdentity("one.example", False)
        staging, public = (AcmePlan(identity, mode) for mode in (AcmeMode.STAGING, AcmeMode.PUBLIC))
        self.assertEqual(staging.webroot, public.webroot)
        self.assertNotEqual(staging.candidate, public.candidate)
        for plan in (staging, public):
            issue = plan.issue("operator@example.net")
            self.assertIn(plan.mode.endpoint, issue)
            self.assertIn(str(plan.configuration), issue)
            self.assertEqual(issue[-2:], ("--domains", identity.name))
            self.assertNotIn("--standalone", issue)
            self.assertEqual(plan.renew()[1], "renew")
            self.assertIn(identity.slot, plan.renew())

    def test_acme_email_is_optional_without_losing_validation(self):
        for mode in (AcmeMode.STAGING, AcmeMode.PUBLIC):
            plan = AcmePlan(TLSIdentity('one.example', False), mode)
            command = plan.issue('')
            self.assertIn('--register-unsafely-without-email', command)
            self.assertNotIn('--email', command)
            self.assertIn('--email', plan.issue('operator@example.net'))
            with self.assertRaises(ValueError):
                plan.issue('invalid email')

    def test_ip_requires_shortlived_profile_and_rejects_private_ip(self):
        plan = AcmePlan(TLSIdentity("1.1.1.1", True), AcmeMode.PUBLIC)
        self.assertEqual(plan.issue("operator@example.net")[-4:],
                         ("--preferred-profile", "shortlived", "--ip-address", "1.1.1.1"))
        with self.assertRaises(ValueError):
            AcmePlan(TLSIdentity("192.0.2.10", True), AcmeMode.STAGING)
        with self.assertRaises(ValueError):
            plan.issue("x@example.net\n--staging")

    def test_webroot_ip_requires_supported_certbot_version(self):
        for version in ("certbot 5.4.0", "certbot 5.9.0", "certbot 6.0.0\n"):
            require_certbot_version(version)
        for version in ("certbot 5.3.1", "certbot 2.1.0", "unknown"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                require_certbot_version(version)

    def test_failed_dns_has_safe_reason_and_does_not_read_lineage(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            client = CertbotClient(root=root, executable=Path("/usr/bin/certbot"))
            plan = client.plan(TLSIdentity("one.example", False), AcmeMode.PUBLIC)
            commands = [subprocess.CompletedProcess([], 0, b"certbot 5.4.0\n", b""),
                        subprocess.CompletedProcess([], 1, b"", b"DNS problem: NXDOMAIN; detail not for UI")]
            with patch("v5.core.tls.acme_service.subprocess.run", side_effect=commands), \
                    patch.object(client, "material") as material, self.assertRaises(AcmeError) as caught:
                client.issue(plan, "operator@example.net")
            self.assertEqual(caught.exception.code, "dns_failed")
            self.assertEqual(str(caught.exception), "dns_failed")
            material.assert_not_called()

    def test_certbot_lineage_can_only_read_own_root_and_private_key(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            client = CertbotClient(root=root, executable=Path("/usr/bin/certbot"))
            plan = client.plan(TLSIdentity("one.example", False), AcmeMode.PUBLIC)
            chain, key = plan.candidate
            chain.parent.mkdir(parents=True)
            archive = plan.configuration / "archive" / plan.identity.slot
            archive.mkdir(parents=True)
            real_chain, real_key = archive / "fullchain1.pem", archive / "privkey1.pem"
            real_chain.write_bytes(b"fixture chain")
            real_key.write_bytes(b"fixture key")
            real_key.chmod(0o600)
            chain.symlink_to(real_chain)
            key.symlink_to(real_key)
            self.assertEqual(client.material(plan), (b"fixture chain", b"fixture key"))
            key.unlink()
            key.symlink_to(root / "outside.pem")
            (root / "outside.pem").write_bytes(b"outside")
            with self.assertRaises(AcmeError) as caught:
                client.material(plan)
            self.assertEqual(caught.exception.code, "lineage_invalid")


class HTTP01Tests(unittest.TestCase):
    def test_renders_known_hosts_and_dedicated_challenge_without_proxy(self):
        identities = (TLSIdentity("One.Example.", False), TLSIdentity("two.example", False),
                      TLSIdentity("2001:db8::10", True))
        configuration = render_http01(identities)
        self.assertIn('"one.example:80" "one.example";', configuration)
        self.assertIn('"two.example" "two.example";', configuration)
        self.assertIn('"[2001:db8::10]:80" "[2001:db8::10]";', configuration)
        self.assertIn('if ($kvn_public_authority = "") { return 421; }', configuration)
        self.assertIn("listen [::]:80 default_server", configuration)
        self.assertIn("try_files $uri =404;", configuration)
        self.assertIn("disable_symlinks on", configuration)
        self.assertIn("return 308 https://$kvn_public_authority$request_uri;", configuration)
        self.assertNotIn("proxy_pass", configuration)
        self.assertNotIn(":8443", configuration)

    def test_refuses_invalid_registry_paths_and_ipv6_when_disabled(self):
        dns, ip = TLSIdentity("one.example", False), TLSIdentity("2001:db8::10", True)
        self.assertNotIn("[::]:80", render_http01((dns,), ipv6=False))
        for call in (lambda: render_http01(()), lambda: render_http01((dns, dns)),
                     lambda: render_http01((dns,), webroot=Path("/a; return 200")),
                     lambda: render_http01((dns, ip), ipv6=False)):
            with self.assertRaises(ValueError):
                call()


@unittest.skipUnless(Path("/usr/bin/openssl").is_file(), "Нужен OpenSSL")
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workspace = TemporaryDirectory(prefix="kvn-v5-x509-test-")
        cls.addClassCleanup(workspace.cleanup)
        cls.root = Path(workspace.name)
        cls.ca = cls.root / "root.pem"
        cls.ca_key = cls.root / "root-key.pem"
        cls.other_ca = cls.root / "other-root.pem"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-subj", "/CN=KVN test root", "-days", "7", "-keyout", str(cls.ca_key), "-out", str(cls.ca))
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-subj", "/CN=KVN other test root", "-days", "7", "-keyout", str(cls.root / "other-key.pem"),
                "-out", str(cls.other_ca))
        cls.one = cls._pair(1, "DNS:one.example")
        cls.two = cls._pair(2, "DNS:two.example")
        cls.ipv4 = cls._pair(3, "IP:192.0.2.10")
        cls.ipv6 = cls._pair(4, "IP:2001:db8::10")
        cls.wildcard = cls._pair(5, "DNS:*.example")
        cls.multisan = cls._pair(6, "DNS:one.example,DNS:two.example")
        cls.expired = cls._pair(7, "DNS:one.example", days=0)

    @classmethod
    def _pair(cls, serial: int, san: str, *, days: int = 1) -> tuple[bytes, bytes]:
        key = cls.root / f"leaf-{serial}.key"
        csr = cls.root / f"leaf-{serial}.csr"
        cert = cls.root / f"leaf-{serial}.pem"
        extension = cls.root / f"leaf-{serial}.ext"
        extension.write_text("basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\n",
                             encoding="ascii")
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-subj", "/CN=one.example", "-keyout", str(key), "-out", str(csr))
        openssl("x509", "-req", "-in", str(csr), "-CA", str(cls.ca), "-CAkey", str(cls.ca_key),
                "-set_serial", str(serial), "-days", str(days), "-extfile", str(extension), "-out", str(cert))
        return cert.read_bytes(), key.read_bytes()

    def assert_invalid(self, code, identity, pair, ca=None):
        with self.assertRaises(CertificateError) as caught:
            validate_pair(identity, *pair, ca_file=ca or self.ca)
        self.assertEqual(caught.exception.code, code)

    def test_separate_exact_dns_and_ip_pairs(self):
        self.assertNotEqual(self.one[0], self.two[0])
        cases = (("one.example", False, self.one), ("two.example", False, self.two),
                 ("192.0.2.10", True, self.ipv4), (ip_address("2001:db8::10").exploded, True, self.ipv6))
        for name, is_ip, pair in cases:
            with self.subTest(name=name):
                identity = TLSIdentity(name, is_ip)
                result = validate_pair(identity, *pair, ca_file=self.ca)
                self.assertEqual(result.identity, identity)
                self.assertGreater(result.not_after, result.not_before)

    def test_rejects_other_name_wildcard_multi_san_and_ip_mismatch(self):
        identity = TLSIdentity("one.example", False)
        for pair in (self.two, self.wildcard, self.multisan, self.ipv4):
            self.assert_invalid("san_mismatch", identity, pair)
        self.assert_invalid("san_mismatch", TLSIdentity("192.0.2.11", True), self.ipv4)

    def test_rejects_wrong_chain_key_expiry_and_extra_pem_data(self):
        identity = TLSIdentity("one.example", False)
        self.assert_invalid("untrusted_chain", identity, self.one, self.other_ca)
        self.assert_invalid("expires_too_soon", identity, self.expired)
        self.assert_invalid("key_mismatch", identity, (self.one[0], self.two[1]))
        self.assert_invalid("invalid_key", identity, (self.one[0], self.one[1] + self.two[1]))
        self.assert_invalid("invalid_certificate", identity, (self.one[0] + b"not a PEM", self.one[1]))

    def test_store_keeps_a_valid_pair_private_and_rejects_bad_candidate_without_writes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = CertificateStore(root, ca_file=self.ca)
            identity = TLSIdentity("one.example", False)
            first = store.stage(identity, *self.one)
            self.assertEqual(store.stage(identity, *self.one), first)
            self.assertEqual(first.chain.parent, first.key.parent)
            self.assertEqual(first.key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(first.key.parent.stat().st_mode & 0o777, 0o700)
            before = sorted(root.rglob("*"))
            with self.assertRaises(CertificateError):
                store.stage(identity, *self.expired)
            self.assertEqual(sorted(root.rglob("*")), before)
            self.assertEqual(first.chain.read_bytes(), self.one[0])

    def test_controller_keeps_existing_pairs_and_index_on_rollback(self):
        one, two = TLSIdentity("one.example", False), TLSIdentity("two.example", False)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "nginx.conf"
            config.write_text(render_gateway((one, two), ipv6=False), encoding="utf-8")
            config.chmod(0o600)
            store = CertificateStore(root, ca_file=self.ca)
            controller = GatewayController(config, store, (one, two), ipv6=False)
            checks = []
            first = controller.activate(one, *self.one, check=lambda path: checks.append(path.read_bytes()),
                                        reload=lambda: None, verify_live=lambda pair: self.assertEqual(pair.metadata.identity, one),
                                        verify_restored=lambda: self.fail("Лишний откат"))
            self.assertEqual(controller.active(), (first,))
            snapshot = config.read_bytes()
            with self.assertRaises(CertificateError):
                controller.activate(two, *self.one, check=lambda _: self.fail("Кандидат неверен"),
                                    reload=lambda: None, verify_live=lambda _: None, verify_restored=lambda: None)
            self.assertEqual(config.read_bytes(), snapshot)

            def fail(_):
                raise OSError("fixture")

            with self.assertRaises(GatewayApplyError):
                controller.activate(two, *self.two, check=lambda path: checks.append(path.read_bytes()),
                                    reload=lambda: None, verify_live=fail, verify_restored=lambda: None)
            self.assertEqual(controller.active(), (first,))
            self.assertEqual(config.read_bytes(), snapshot)
            self.assertNotIn(b"-----BEGIN", b"".join(checks))

    def test_staging_issue_never_activates_and_only_public_lineage_renews(self):
        identity = TLSIdentity("one.example", False)
        with TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = Mock(identities=(identity,), config=root / "nginx.conf")
            client = Mock(spec=CertbotClient)
            client.plan.side_effect = lambda name, mode: AcmePlan(name, mode, root=root)
            client.issue.return_value = self.one
            manager = AcmeService(gateway, client)
            outcome = manager.issue(identity, AcmeMode.STAGING, "operator@example.net")
            self.assertEqual(outcome.status, "staging_issued")
            self.assertIsNotNone(outcome.expires_at)
            gateway.activate.assert_not_called()
            staging = AcmePlan(identity, AcmeMode.STAGING, root=root)
            staging.candidate[0].parent.mkdir(parents=True)
            staging.candidate[0].touch()
            self.assertEqual(manager.renew_due(), {})
            client.renew.assert_not_called()

    def test_renewal_without_new_certificate_is_reported_as_unchanged(self):
        identity = TLSIdentity("one.example", False)
        info = validate_pair(identity, *self.one, ca_file=self.ca)
        gateway = Mock(config=self.root / "nginx.conf")
        gateway.generation.return_value = "same"
        gateway.activate.return_value = StoredPair(info, self.root / "same/fullchain.pem", self.root / "same/privkey.pem")
        manager = AcmeService(gateway)
        self.assertEqual(manager._activate(identity, self.one).status, "unchanged")
        gateway.generation.return_value = "old"
        self.assertEqual(manager._activate(identity, self.one).status, "active")


class GatewayTransactionTests(unittest.TestCase):
    def test_candidate_checked_before_activation_and_restore_on_failed_readiness(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "nginx.conf"
            config.write_bytes(b"old")
            config.chmod(0o600)
            events = []

            def check(path):
                events.append(("check", path.read_bytes(), config.read_bytes()))

            def reload():
                events.append(("reload", config.read_bytes()))

            def fail_live():
                raise OSError("fixture: новый listener не отвечает")

            with self.assertRaises(GatewayApplyError) as caught:
                publish_gateway(config, b"new", check=check, reload=reload, verify_live=fail_live,
                                verify_restored=lambda: events.append(("restored", config.read_bytes())))
            self.assertEqual(caught.exception.code, "apply_rolled_back")
            self.assertEqual(events, [("check", b"new", b"old"), ("reload", b"new"), ("reload", b"old"),
                                      ("restored", b"old")])
            self.assertEqual(config.read_bytes(), b"old")
            self.assertEqual(list(config.parent.glob(".nginx-*")), [])

    def test_invalid_config_never_reloads_and_valid_config_commits(self):
        with TemporaryDirectory() as directory:
            config = Path(directory) / "nginx.conf"
            config.write_bytes(b"old")
            config.chmod(0o600)
            events = []

            def reject(_):
                raise ValueError("fixture: nginx -t")

            with self.assertRaises(GatewayApplyError) as caught:
                publish_gateway(config, b"bad", check=reject, reload=lambda: events.append("reload"),
                                verify_live=lambda: None, verify_restored=lambda: None)
            self.assertEqual(caught.exception.code, "config_invalid")
            self.assertEqual(events, [])
            self.assertEqual(config.read_bytes(), b"old")
            publish_gateway(config, b"good", check=lambda path: self.assertEqual(path.read_bytes(), b"good"),
                            reload=lambda: events.append("reload"), verify_live=lambda: events.append("live"),
                            verify_restored=lambda: self.fail("Лишний откат"))
            self.assertEqual(config.read_bytes(), b"good")
            self.assertEqual(events, ["reload", "live"])
