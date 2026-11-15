"""Быстрая проверка VLESS на закреплённой сборке Xray в закрытом netns WSL."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory, TemporaryFile
import time

from tests.v5.xray_lab_e2e import DIGEST
from v5.core.packages.manifest import canonical_json
from v5.core.private_files import write_private
from v5.core.tls.identity import TLSIdentity
from v5.modules.xray.config import Settings, render_server
from v5.modules.xray.profiles import Exposure, Kind, Profile, Profiles
from v5.modules.xray.users import set_user, subscription_uris

sys.path.insert(0, str(Path(__file__).parent))
import check_users_vm as probe
from check_tls_gateway import make_ca, make_pair


@contextmanager
def serve(binary, path):
    with TemporaryFile(dir=path.parent) as diagnostic, subprocess.Popen(
            [binary, "run", "-config", path], stdout=diagnostic, stderr=diagnostic) as process:
        try:
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection((probe.ADDRESS, 2443), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("Тестовый Xray не слушает порт")
            yield
        except AssertionError:
            diagnostic.seek(0)
            observed = diagnostic.read(64 * 1024).lower()
            markers = {b"received request for": "vless_accepted", b"invalid request user id": "uuid_rejected",
                       b"taking detour": "route_selected", b"connection opened to": "origin_dial",
                       b"failed to open connection": "origin_dial_failed", b"firstlen": "got_request",
                       b"blocked target": "blocked_target", b"invalid request": "invalid_request",
                       b"failed to read request": "bad_header", b"failed to transfer response": "response_failed"}
            print("Xray-сервер, признаки: " + ",".join(code for marker, code in markers.items() if marker in observed),
                  flush=True)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=6)


def exercise(root, parent_net):
    assert os.readlink("/proc/self/ns/net") != parent_net
    assert [item["ifname"] for item in json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))] == ["lo"]
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", f"{probe.ADDRESS}/32", "dev", "lo"], check=True)
    ca, key = make_ca(root)
    identity = TLSIdentity(probe.SITE, False)
    certificate, private = make_pair(ca, key, identity, 7)
    cert_path, key_path = root / "tls.crt", root / "tls.key"
    write_private(cert_path, certificate)
    write_private(key_path, private)
    settings = Settings(Profiles((Profile(Kind.TLS, Exposure.DIRECT, probe.SITE),)), ipv4=probe.ADDRESS)
    settings = set_user(settings, "phase10-probe", True)
    uri, = subscription_uris(settings, "phase10-probe", probe.SITE, None)
    server_config = root / "xray-server.json"
    probe.BASE = root
    probe.client_ns = lambda *argv: argv
    with probe.xray_origin():
        for allowed in (True, False):
            current = set_user(settings, "phase10-probe", allowed)
            document = render_server(current, None, site_names=(probe.SITE,))
            document["log"]["loglevel"] = "debug"
            tls = document["inbounds"][0]["streamSettings"]["tlsSettings"]
            tls["certificates"] = [{"certificateFile": str(cert_path), "keyFile": str(key_path)}]
            write_private(server_config, canonical_json(document))
            with serve(root / "xray", server_config):
                probe.xray(uri, ca, root, allowed=allowed, diagnose=True)
    print("WSL: штатный Xray передал HTTP по выданному URI и не принял отозванный UUID.", flush=True)


def main():
    if len(sys.argv) == 3:
        exercise(Path(sys.argv[1]), sys.argv[2])
        return
    assert len(sys.argv) == 1
    image = f"ghcr.io/xtls/xray-core@sha256:{DIGEST}"
    with TemporaryDirectory(prefix="kvn-v5-xray-users-") as folder:
        root = Path(folder)
        container = subprocess.check_output(["docker", "create", "--network", "none", "--pull=never", image],
                                            text=True, timeout=15).strip()
        try:
            subprocess.run(["docker", "cp", f"{container}:/usr/local/bin/xray", root / "xray"], check=True, timeout=20)
            subprocess.run(["unshare", "--net", "--", sys.executable, "-m", __spec__.name, str(root),
                            os.readlink("/proc/self/ns/net")], check=True, timeout=75)
        finally:
            subprocess.run(["docker", "rm", container], check=True, stdout=subprocess.DEVNULL, timeout=15)


if __name__ == "__main__":
    main()
