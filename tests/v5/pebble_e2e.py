"""Запуск ACME Pebble v2.10.1 на отдельной VM Debian 12 в WSL."""

import argparse
from contextlib import contextmanager
import hashlib
import http.client
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import threading

from tests.v5.debian_core_e2e import Lab


HASHES = {
    "pebble": "4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed",
    "pebble-challtestsrv": "e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92",
}
SCRATCH = "/var/tmp/kvn-v5-pebble"
SOURCE = "/var/tmp/kvn-v5-acme-candidate"


@contextmanager
def watch_http80():
    stop = threading.Event()
    counts = {"ok": 0, "fail": 0}

    def poll():
        while not stop.is_set():
            conn = http.client.HTTPConnection("127.0.0.1", 22881, timeout=4)
            try:
                conn.request("GET", "/", headers={"Host": "portal.example", "Connection": "close"})
                reply = conn.getresponse()
                key = "ok" if reply.status == 200 and reply.getheader("Content-Security-Policy") else "fail"
                counts[key] += 1
            except (OSError, http.client.HTTPException):
                counts["fail"] += 1
            finally:
                conn.close()
            stop.wait(1)

    thread = threading.Thread(target=poll, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(5)
        print(f"TCP/80 со стороны WSL: {counts['ok']} ответов 200, {counts['fail']} ошибок.", flush=True)
    if not counts["ok"] or counts["fail"]:
        raise RuntimeError("Непрерывность HTTP/80 не подтверждена")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--watch", type=int, help="Только контролировать TCP/80 указанное число секунд")
    args = parser.parse_args()
    if args.watch is not None:
        if not 1 <= args.watch <= 900:
            parser.error("Интервал должен быть от 1 до 900 секунд")
        with watch_http80():
            threading.Event().wait(args.watch)
        return
    lab_root = Path("/var/tmp/kvn-v5-lab")
    lab = Lab(22056, lab_root)
    lab.wait()
    lab.run(f"test -x /usr/local/lib/kvn-v5-acme/bin/certbot && test -f {SOURCE}/v5/core/tls/acme_service.py && "
            f"install -d -m 0700 {SCRATCH}")
    with TemporaryDirectory(prefix="kvn-v5-pebble-binary-") as directory:
        for name, digest in HASHES.items():
            archive = lab_root / "pebble-2.10.1" / f"{name}-linux-amd64.tar.gz"
            with archive.open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == digest
            local = Path(directory) / name
            with tarfile.open(archive, "r:gz") as source:
                member = source.getmember(f"{name}-linux-amd64/linux/amd64/{name}")
                assert member.isfile() and member.size <= 32 * 1024 * 1024
                with source.extractfile(member) as stream, local.open("xb") as output:
                    shutil.copyfileobj(stream, output)
            lab.upload(local, f"{SCRATCH}/{name}")
            lab.run(f"chmod 0700 {SCRATCH}/{name}")
    remote = f"{SCRATCH}/check_acme_pebble.py"
    lab.upload(Path(__file__).with_name("fixtures") / "check_acme_pebble.py", remote)
    with watch_http80():
        result = lab.run(f"PYTHONPATH={SOURCE} /usr/bin/python3 {remote}", timeout=1800)
        print(result.stdout.decode().strip())


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stdout.decode(errors="replace"), file=sys.stderr)
        print(exc.stderr.decode(errors="replace"), file=sys.stderr)
        raise SystemExit(exc.returncode)
