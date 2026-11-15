"""Реальный ACME HTTP-01 в изолированной VM; тестовые CA не добавляются в систему."""

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
from tempfile import TemporaryDirectory
import time
from unittest.mock import patch

from v5.core.tls.acme import CERTBOT, AcmeMode, AcmePlan
from v5.core.tls.acme_service import AcmeError, AcmeService, CertbotClient
from v5.core.tls.controller import GatewayController
from v5.core.tls.probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from v5.core.tls.queue import GATEWAY_ROOT, registry
from v5.core.tls.transaction import CertificateStore, publish_gateway


SCRATCH = Path("/var/tmp/kvn-v5-pebble")
ENDPOINT = "https://127.0.0.1:14000/dir"
IP = "192.0.2.8"


class TestPlan(AcmePlan):
    def __post_init__(self):
        assert not self.identity.is_ip or self.identity.name == IP

    def _command(self, action):
        values = super()._command(action)
        values[values.index("--server") + 1] = ENDPOINT
        return values

    def renew(self):
        # Реальное переиздание тестовой CA без ожидания окна; production-флаг не меняется.
        return (*super().renew(), "--force-renewal")


class TestClient(CertbotClient):
    def __init__(self, root, endpoint_ca):
        super().__init__(root=root)
        self.endpoint_ca = endpoint_ca

    def plan(self, identity, mode):
        return TestPlan(identity, mode, root=self.root)

    def _call(self, argv, timeout):
        assert argv[0] == str(CERTBOT)
        if "--server" in argv:
            assert argv[argv.index("--server") + 1] == ENDPOINT
        environment = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(self.root),
                       "REQUESTS_CA_BUNDLE": str(self.endpoint_ca), "SSL_CERT_FILE": str(self.endpoint_ca)}
        result = subprocess.run(argv, capture_output=True, check=False, timeout=max(timeout, 90), env=environment)
        if result.returncode:
            tail = (result.stdout + result.stderr).decode(errors="replace").strip().splitlines()[-8:]
            raise AcmeError("\n".join(tail))
        return result.stdout


@contextmanager
def server(arguments, env=None):
    with subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env) as process:
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()


def _ca(process, context):
    until = time.monotonic() + 40
    while time.monotonic() < until:
        assert process.poll() is None, "Локальный Pebble завершился"
        connection = http.client.HTTPSConnection("127.0.0.1", 15000, timeout=4, context=context)
        try:
            connection.request("GET", "/roots/0")
            response = connection.getresponse()
            if response.status == 200:
                payload = response.read(65536)
                assert payload.startswith(b"-----BEGIN CERTIFICATE-----")
                return payload
        except OSError:
            time.sleep(1)
        finally:
            connection.close()
    raise RuntimeError("Не дождались локального Pebble")


def _probe(ca, directory):
    names, ipv6 = registry()
    assert {name.name for name in names} == {IP, "portal.example", "www.portal.example"}
    config = GATEWAY_ROOT / "nginx.conf"
    previous = config.read_bytes()
    store = CertificateStore(GATEWAY_ROOT / "certs", ca_file=ca)
    gateway = GatewayController(config, store, names, ipv6=ipv6)
    prior = gateway.active()
    # Сертификат тестового ACME-сервера и выпускающий корень Pebble — разные.
    service = AcmeService(gateway, TestClient(directory / "state", directory / "endpoint.crt"))
    root = service.client.root
    root.mkdir(mode=0o700)
    (root / "webroot").symlink_to("/var/lib/kvn-v5/acme/webroot", target_is_directory=True)

    def boot():
        verify_bootstrap(GATEWAY_ROOT / "bootstrap.crt")

    master = Path("/run/kvn-v5-gateway/nginx.pid").read_text()
    try:
        with patch("v5.core.tls.acme_service.verify_pair", lambda pair: verify_pair(pair, ca_file=ca)):
            for identity in names:
                outcome = service.issue(identity, AcmeMode.STAGING, "lab@example.net")
                assert outcome.status == "staging_issued" and config.read_bytes() == previous
            print("Pebble: HTTP-01 и проверочный выпуск для двух DNS и IP; nginx не изменён.", flush=True)
            for identity in names:
                outcome = service.issue(identity, AcmeMode.PUBLIC, "lab@example.net")
                assert outcome.status == "active"
            first = {pair.metadata.identity: pair.chain.read_bytes() for pair in gateway.active()}
            print("Pebble: выпуск, проверка цепочки, активация nginx на 443/8443 для всех имён.", flush=True)
            results = service.renew_due()
            assert set(results) == set(names) and all(item.status == "active" for item in results.values()), results
            for pair in gateway.active():
                assert pair.chain.read_bytes() != first[pair.metadata.identity]
                verify_pair(pair, ca_file=ca)
            assert Path("/run/kvn-v5-gateway/nginx.pid").read_text() == master
            print("Pebble: фактическое принудительное переиздание тестовых lineages, master nginx не менялся.", flush=True)
    finally:
        if config.read_bytes() != previous:
            publish_gateway(config, previous, check=check_nginx, reload=reload_nginx, verify_live=boot, verify_restored=boot)
        assert gateway.active() == prior


def main():
    assert os.geteuid() == 0 and Path("/var/lib/cloud/data/instance-id").read_text().strip() == "kvn-v5-isolated-001"
    assert CERTBOT.is_file()
    with TemporaryDirectory(prefix="run-", dir=SCRATCH) as value:
        directory = Path(value)
        endpoint, key = directory / "endpoint.crt", directory / "endpoint.key"
        subprocess.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-subj", "/CN=KVN fixture endpoint", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-days", "1", "-out", str(endpoint), "-keyout", str(key)], check=True, capture_output=True, timeout=30)
        config = directory / "pebble.json"
        config.write_text(json.dumps({"pebble": {"listenAddress": "127.0.0.1:14000",
                          "managementListenAddress": "127.0.0.1:15000", "certificate": str(endpoint), "privateKey": str(key),
                          "httpPort": 80, "tlsPort": 443, "keyAlgorithm": "ecdsa",
                          "profiles": {"default": {"validityPeriod": 86400}, "shortlived": {"validityPeriod": 21600}}}}),
                          encoding="ascii")
        dns = [str(SCRATCH / "pebble-challtestsrv"), "-dnsserver", "127.0.0.1:8053", "-management", "127.0.0.1:8055",
               "-defaultIPv6", "", "-http01", "", "-https01", "", "-tlsalpn01", ""]
        pebble = [str(SCRATCH / "pebble"), "-config", str(config), "-dnsserver", "127.0.0.1:8053"]
        subprocess.run(["/usr/sbin/ip", "address", "add", IP + "/32", "dev", "lo"], check=True, timeout=10)
        try:
            env = {"PATH": "/usr/bin:/bin", "PEBBLE_VA_NOSLEEP": "1", "PEBBLE_AUTHZREUSE": "0", "PEBBLE_WFE_NONCEREJECT": "0"}
            with server(dns), server(pebble, env) as process:
                issuing_ca = directory / "issuing.pem"
                issuing_ca.write_bytes(_ca(process, ssl.create_default_context(cafile=str(endpoint))))
                _probe(issuing_ca, directory)
        finally:
            subprocess.run(["/usr/sbin/ip", "address", "del", IP + "/32", "dev", "lo"], check=True, timeout=10)


if __name__ == "__main__":
    main()
