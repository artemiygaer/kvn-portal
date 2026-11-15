"""Настоящие Xray-клиенты и сервер в Docker-сети none; рабочих портов нет."""

from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from uuid import uuid4

from tests.v5.fixtures.check_tls_gateway import make_ca, make_pair
from v5.core.private_files import write_private
from v5.core.tls.identity import TLSIdentity
from v5.modules.xray.clients import client_profiles
from v5.modules.xray.config import Settings, render_server
from v5.modules.xray.credentials import Account, load_reality
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles, Reality

IMAGE = ("ghcr.io/xtls/xray-core@sha256:"
         "db94b52238af7311f30044a1ef64e77b0edf285a302c276a7f4d7b368e6a17ab")
MOUNT = "/etc/kvn-xray"
ORIGIN = "origin.kvn.test"
SITE = "portal.kvn.test"
# Freedom блокирует TEST-NET. Этот адрес назначается только lo контейнера без внешнего интерфейса.
ECHO = "93.184.216.34"


class Response(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.response
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


def fixture_servers(root: Path):
    server = ThreadingHTTPServer((ECHO, 18080), Response)
    server.response = b"authorized-vless"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    (root / "fixture.ready").touch()
    threading.Event().wait()


def call(*args, timeout=30, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"Команда {Path(args[0]).name} завершилась с кодом {result.returncode}")
    return result


def _stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=8)


def _ready(condition, what, process=None):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"Процесс завершился до готовности: {what}")
        if condition():
            return
        time.sleep(0.25)
    raise RuntimeError(f"Не подтверждена готовность: {what}")


def run_trial(root, container, ns, settings, account, key):
    address = "127.0.0.1" if settings.ipv4 == "0.0.0.0" else settings.ipv4
    profiles = client_profiles(settings, account.id, address, key.public, active=True, prefer_direct=True)
    server = render_server(settings, key, site_names=(SITE,))
    server["log"]["loglevel"] = "debug"
    write_private(root / "server.json", json.dumps(server).encode())
    for index, item in enumerate(profiles):
        outbound = item.outbound()
        if item.profile.kind is Kind.TLS:
            outbound["streamSettings"]["tlsSettings"]["certificates"] = [
                {"certificateFile": f"{MOUNT}/ca.pem", "usage": "verify"},
            ]
        document = {"log": {"access": "none", "loglevel": "debug"},
                    "inbounds": [{"listen": "127.0.0.1", "port": 16001 + index,
                                  "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
                    "outbounds": [outbound]}
        write_private(root / f"client-{index}.json", json.dumps(document).encode())
    binary = "/usr/local/bin/xray"
    launch = ("docker", "exec", "-e", f"SSL_CERT_FILE={MOUNT}/ca.pem", container, binary, "run")
    files = ("server.json", *(f"client-{index}.json" for index in range(len(profiles))))
    def report_failure(result, subject):
        output = (result.stdout + result.stderr).decode(errors="replace")[-1800:]
        for log in sorted(root.glob("*.log")):
            output += f"\n{log.name}: " + log.read_text(errors="replace")[-1500:]
        for secret in (account.id, key.private, key.public.key, key.public.short_id):
            output = output.replace(secret, "<скрыто>")
        raise RuntimeError(f"{subject}: {output}")

    for name in files:
        result = call(*launch, "-test", "-config", f"{MOUNT}/{name}", check=False)
        if result.returncode:
            report_failure(result, "Проверка конфигурации Xray")

    def listening(port, *family):
        rows = call(*ns, "/usr/bin/ss", "-H", "-lnt", *family).stdout.decode()
        return any(line.split()[3].endswith(f":{port}") for line in rows.splitlines())

    with ExitStack() as scope:
        for name in files:
            log = scope.enter_context((root / f"{name}.log").open("xb"))
            process = subprocess.Popen((*launch, "-config", f"{MOUNT}/{name}"),
                                       stdout=log, stderr=subprocess.STDOUT)
            scope.callback(_stop, process)
        for index, item in enumerate(profiles):
            port = 16001 + index
            _ready(lambda: listening(port) and listening(item.port), "Xray ingress/SOCKS")
            result = call(*ns, "/usr/bin/curl", "-fsS", "--max-time", "8", "--noproxy", "",
                          "--socks5-hostname", f"127.0.0.1:{port}", f"http://{ECHO}:18080/", check=False)
            if result.returncode:
                report_failure(result, f"Клиент {item.profile.kind}")
            assert result.stdout == b"authorized-vless"
            print(f"{item.profile.kind.value}: настоящий клиент Xray передал HTTP через VLESS", flush=True)
            if item.profile.reality is not None:
                marker = b"self-steal-site" if item.profile.reality is Reality.SELF_STEAL else b"external-fallback"
                result = call(*ns, "/usr/bin/curl", "-fsS", "--max-time", "8", "--noproxy", "*",
                              "--cacert", str(root / "ca.pem"), "--resolve",
                              f"{item.profile.sni}:{item.port}:{address}",
                              f"https://{item.profile.sni}:{item.port}/", check=False)
                if result.returncode:
                    report_failure(result, f"HTTPS fallback {item.profile.kind}")
                assert result.stdout == marker
        for port in (2443, 2444, 2445):
            assert listening(port) is any(item.port == port for item in profiles)
            expected_v6 = settings.ipv4 == "0.0.0.0" and any(item.port == port and item.direct for item in profiles)
            assert listening(port, "-6") is expected_v6, f"IPv6 listener {port} не совпадает с планом"
        assert not listening(8443)


def main(*, ipv4_only=False):
    if os.geteuid() != 0:
        raise RuntimeError("Тест nsenter выполняется только от root в WSL")
    with tempfile.TemporaryDirectory(prefix="kvn-v5-xray-", dir="/var/tmp") as directory, ExitStack() as scope:
        root = Path(directory)
        ca, ca_key = make_ca(root)
        for label, name, serial in (("site", SITE, 601), ("origin", ORIGIN, 602), ("tls", SITE, 603)):
            cert, key_bytes = make_pair(ca, ca_key, TLSIdentity(name, False), serial)
            write_private(root / f"{label}.crt", cert)
            write_private(root / f"{label}.key", key_bytes)
        servers = "".join(
            f"server {{ listen 127.0.0.1:{port} ssl; http2 on; ssl_protocols TLSv1.3; "
            f"ssl_certificate {MOUNT}/{label}.crt; ssl_certificate_key {MOUNT}/{label}.key; "
            f'location / {{ return 200 "{body}"; }} }}\n'
            for port, label, body in ((443, "origin", "external-fallback"), (10443, "site", "self-steal-site"))
        )
        write_private(root / "nginx.conf", ("events {}\nhttp { access_log off; " + servers + "}\n").encode())
        key = load_reality(root / "reality.json", create=True)
        account = Account("Учебный профиль", str(uuid4()), tuple(Kind))
        write_private(root / "anchor.json", b'{"log":{"loglevel":"none"},"inbounds":['
                      b'{"listen":"127.0.0.1","port":15999,"protocol":"socks"}],'
                      b'"outbounds":[{"protocol":"blackhole"}]}')
        name = "kvn-v5-xray-e2e-" + uuid4().hex
        container = call("docker", "run", "--rm", "-d", "--name", name, "--network", "none",
                         "--pull", "never", "--user", "0:0", "--cap-drop", "ALL",
                         "--add-host", f"{ORIGIN}:127.0.0.1",
                         "--mount", f"type=bind,source={root},target={MOUNT},readonly",
                         IMAGE, "run", "-config", f"{MOUNT}/anchor.json").stdout.decode().strip()
        scope.callback(call, "docker", "rm", "-f", container, check=False)
        info = call("docker", "inspect", "--format", "{{.State.Pid}} {{.HostConfig.NetworkMode}}",
                    container).stdout.decode().split()
        assert info[1] == "none" and info[0].isdigit()
        namespace = Path(f"/proc/{info[0]}/ns/net")
        assert namespace.stat().st_ino != Path("/proc/self/ns/net").stat().st_ino
        ns = ("/usr/bin/nsenter", f"--net={namespace}", "--")
        call(*ns, "/usr/sbin/ip", "addr", "add", f"{ECHO}/32", "dev", "lo")
        target = call("docker", "run", "--rm", "-d", "--network", f"container:{container}", "--pull", "never",
                      "--mount", f"type=bind,source={root},target={MOUNT},readonly",
                      "--entrypoint", "/usr/sbin/nginx", "nginx:1.31.8-alpine", "-g", "daemon off;",
                      "-c", f"{MOUNT}/nginx.conf").stdout.decode().strip()
        scope.callback(call, "docker", "rm", "-f", target, check=False)
        _ready(lambda: call(*ns, "/usr/bin/curl", "-fsS", "--max-time", "1", "--noproxy", "*",
                            "--cacert", str(ca), "--resolve", f"{SITE}:10443:127.0.0.1",
                            f"https://{SITE}:10443/", check=False).stdout == b"self-steal-site",
               "nginx TLS-цели Reality")
        fixture = subprocess.Popen((*ns, sys.executable, "-m", "tests.v5.xray_protocol_e2e", "--fixture", str(root)))
        scope.callback(_stop, fixture)
        _ready(lambda: (root / "fixture.ready").exists(), "изолированные TLS/HTTP цели", fixture)
        common = (
            Profile(Kind.TLS, Exposure.DIRECT, SITE),
            Profile(Kind.REALITY_TCP, Exposure.BOTH, SITE, Reality.SELF_STEAL),
            Profile(Kind.REALITY_XHTTP, Exposure.DIRECT, ORIGIN, Reality.EXTERNAL, ORIGIN, "/download"),
        )
        settings = (Settings(Profiles(common[:1]), (account,), ipv4=ECHO) if ipv4_only
                    else Settings(Profiles(common), (account,)))
        run_trial(root, container, ns, settings, account, key)
        assert load_reality(root / "reality.json") == key
        mode = "конкретный IPv4, нет IPv6 listener" if ipv4_only else "dual-stack и fallback"
        print(f"Проверено: {mode}; ключ Reality не изменился.", flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        fixture_servers(Path(sys.argv[2]))
    else:
        assert sys.argv[1:] in ([], ["--ipv4-only"]), "Неизвестный режим E2E"
        main(ipv4_only=bool(sys.argv[1:]))
