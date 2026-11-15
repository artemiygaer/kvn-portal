import contextlib
import gzip
import hashlib
import io
import json
import os
import re
import socket
import socketserver
import subprocess
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from v5.core.packages.archive import BLOCK, header, verify_archive
from v5.core.packages.dependencies import dependencies
from v5.core.packages.github import GitHubPackages, _NoRedirect
from v5.core.packages.manifest import MAX_NOTES, PackageError, canonical_json
from v5.core.packages.registry import PackageRegistry
from v5.core.packages.rpc import PackageApplication
from v5.core.packages.signature import Publisher
from v5.core.packages.status import package_status
from v5.packaging.build_module import build
from v5.portal.app import create_app
from v5.portal.rpc import PackageClient

NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)
ISSUED = "2026-11-07T00:00:00Z"
EXPIRES = "2027-02-07T00:00:00Z"
NOTES = "Пакет для проверки\n".encode()


def openssl(*args):
    return subprocess.run(["/usr/bin/openssl", *map(str, args)], check=True, capture_output=True).stdout


def new_key(path):
    openssl("genpkey", "-algorithm", "ED25519", "-out", path)
    der = openssl("pkey", "-in", path, "-pubout", "-outform", "DER")
    return Publisher(der, hashlib.sha256(der).hexdigest())


def member(name, body, custom_header=None):
    return (header(name, len(body)) if custom_header is None else custom_header) + body + bytes(-len(body) % BLOCK)


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "private.pem"
        self.publisher = new_key(self.key)
        self.notes = self.root / "notes.txt"
        self.notes.write_bytes(NOTES)

    def signed(self, doc=None, *, raw=None, notes=NOTES, key=None, signature=None,
               extra=b"", payload_header=None, tail=bytes(2 * BLOCK)):
        if doc is None:
            doc = self.document()
        raw = canonical_json(doc) if raw is None else raw
        if signature is None:
            data, sig = self.root / "data", self.root / "sig"
            data.write_bytes(raw)
            openssl("pkeyutl", "-sign", "-rawin", "-inkey", key or self.key, "-in", data, "-out", sig)
            signature = sig.read_bytes()
        payload = member("payload/notes.txt", notes, payload_header) if notes is not None else b""
        signature_entry = member("manifest.sig", signature) if signature else b""
        return gzip.compress(member("manifest.json", raw) + signature_entry + payload + extra + tail, mtime=0)

    @staticmethod
    def document(**updates):
        return {
            "format": 1, "core_api": 1, "adapter_api": 1, "module_id": "wireguard",
            "version": "1.2.3", "issued_at": ISSUED, "expires_at": EXPIRES,
            "image_digest": None,
            "resources": [{"kind": "notes", "path": "payload/notes.txt", "size": len(NOTES),
                           "sha256": hashlib.sha256(NOTES).hexdigest()}],
            **updates,
        }

    def verify(self, archive, **kwargs):
        with tempfile.TemporaryDirectory(dir=self.root) as staging:
            path = Path(staging)
            result = verify_archive(io.BytesIO(archive), self.publisher, path, now=NOW, **kwargs)
            self.assertEqual((path / "manifest.sig").stat().st_size, 64)
            self.assertEqual((path / "payload/notes.txt").read_bytes(), NOTES)
            return result

    def test_builder_and_pinned_signature(self):
        package = self.root / "fixture.tar.gz"
        args = dict(module_id="wireguard", version="1.2.3", issued_at=ISSUED,
                    expires_at=EXPIRES, notes=self.notes, now=NOW)
        digest = build(package, self.key, **args)
        self.assertEqual(build(package, self.key, **args), digest)
        checked = self.verify(package.read_bytes(), expected_sha256=digest)
        self.assertEqual(checked.manifest.module_id, "wireguard")
        self.assertEqual(checked.archive_sha256, digest)
        self.assertEqual(checked.manifest_sha256, hashlib.sha256(canonical_json(self.document())).hexdigest())
        with self.assertRaisesRegex(PackageError, "^invalid_publisher_pin$"):
            Publisher(self.publisher.public_der, "0" * 64)

    def test_unsigned_foreign_and_corrupt(self):
        other = self.root / "foreign.pem"
        new_key(other)
        original = self.signed()
        cases = [
            (self.signed(signature=b""), "unsupported_archive_header"),
            (self.signed(signature=bytes(64)), "invalid_package_signature"),
            (self.signed(key=other), "invalid_package_signature"),
            (self.signed(notes=b"x" + NOTES[1:]), "resource_hash_mismatch"),
            (original[:-6], "invalid_package_compression"),
            (original + gzip.compress(b""), "extra_gzip_data"),
            (original + b"x", "extra_gzip_data"),
        ]
        for archive, expected in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(PackageError, f"^{expected}$"):
                self.verify(archive)
        with self.assertRaisesRegex(PackageError, "^archive_hash_mismatch$"):
            self.verify(original, expected_sha256="f" * 64)

    def test_builder_checks_release_pin_before_replacing_output(self):
        pin = self.root / "publisher.json"
        pin.write_bytes(canonical_json({"public_der": self.publisher.public_der.hex(),
                                        "sha256": self.publisher.fingerprint}))
        package = self.root / "signed.tar.gz"
        args = dict(module_id="wireguard", version="1.2.3", issued_at=ISSUED,
                    expires_at=EXPIRES, now=NOW, publisher_pin=pin)
        build(package, self.key, **args)
        before = package.read_bytes()
        other = self.root / "foreign.pem"
        new_key(other)
        with self.assertRaisesRegex(PackageError, "^publisher_key_mismatch$"):
            build(package, other, **args)
        self.assertEqual(package.read_bytes(), before)

    def test_expiry_compatibility_and_schema(self):
        cases = [
            (dict(expires_at="2026-11-07T23:59:59Z"), "package_expired"),
            (dict(issued_at="2026-11-09T00:00:00Z"), "package_not_yet_valid"),
            (dict(expires_at="2031-01-01T00:00:00Z"), "invalid_package_lifetime"),
            (dict(core_api=2), "incompatible_package"),
            (dict(adapter_api=True), "incompatible_package"),
            (dict(format=2), "incompatible_package"),
            (dict(module_id="ocserv"), "unsupported_module"),
            (dict(version="1.02.3"), "invalid_module_version"),
            (dict(command=["/bin/sh"]), "unsupported_manifest_fields"),
            (dict(mounts=["/"]), "unsupported_manifest_fields"),
            (dict(image_digest="f" * 64), "unsupported_image"),
        ]
        for update, expected in cases:
            with self.subTest(update=update), self.assertRaisesRegex(PackageError, f"^{expected}$"):
                self.verify(self.signed(self.document(**update)))
        duplicate = canonical_json(self.document()).replace(b'"core_api":1', b'"core_api":1,"core_api":1')
        with self.assertRaisesRegex(PackageError, "^duplicate_json_key$"):
            self.verify(self.signed(raw=duplicate))
        with self.assertRaisesRegex(PackageError, "^noncanonical_manifest$"):
            self.verify(self.signed(raw=canonical_json(self.document()) + b"\n"))

    def test_archive_types_paths_and_bomb(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/etc/passwd", tarfile.REGTYPE),
                           ("payload/notes.txt", tarfile.SYMTYPE), ("payload/notes.txt", tarfile.LNKTYPE),
                           ("payload/notes.txt", tarfile.XHDTYPE), ("payload/notes.txt", tarfile.GNUTYPE_SPARSE)):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.size = kind, 0o600, len(NOTES)
            info.linkname = "/etc/passwd" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            with self.subTest(kind=kind, name=name), self.assertRaisesRegex(PackageError, "^unsupported_archive_header$"):
                self.verify(self.signed(payload_header=info.tobuf(tarfile.USTAR_FORMAT)))
        with self.assertRaisesRegex(PackageError, "^extra_archive_members$"):
            self.verify(self.signed(extra=member("payload/root.sh", b"x")))
        with self.assertRaisesRegex(PackageError, "^invalid_archive_trailer$"):
            self.verify(self.signed(tail=bytes(1024**2)))
        with self.assertRaisesRegex(PackageError, "^expanded_package_limit$"):
            self.verify(self.signed(tail=bytes(1024**2)), expanded_limit=4096)
        with self.assertRaisesRegex(PackageError, "^compressed_package_limit$"):
            self.verify(self.signed(), compressed_limit=32)
        resource = self.document()["resources"][0]
        for update, expected in ((dict(kind="script"), "unsupported_resource"),
                                 (dict(path="../../outside"), "unsupported_resource_path"),
                                 (dict(size=MAX_NOTES + 1), "resource_size")):
            with self.subTest(update=update), self.assertRaisesRegex(PackageError, f"^{expected}$"):
                self.verify(self.signed(self.document(resources=[resource | update])))
        self.assertFalse((self.root / "escape").exists())

    def test_registry_atomic_lifecycle_and_config_preservation(self):
        registry = PackageRegistry(self.root / "registry", self.publisher)
        config = self.root / "module-config.json"
        config.write_bytes(b'{"fixture":true}')
        original_config = hashlib.sha256(config.read_bytes()).hexdigest()
        first = self.signed()
        p1 = registry.prepare(io.BytesIO(first), now=NOW)
        self.assertEqual(registry.installed(), ())
        self.assertEqual(registry.install(p1.ticket, now=NOW).version, "1.2.3")
        self.assertEqual(registry.installed()[0]["enabled"], 0)
        p2 = registry.prepare(io.BytesIO(self.signed(self.document(version="1.2.4"))), now=NOW)
        registry.install(p2.ticket, now=NOW)
        baseline = registry.installed()
        log = registry.journal()
        with self.assertRaisesRegex(PackageError, "^resource_hash_mismatch$"):
            registry.prepare(io.BytesIO(self.signed(notes=b"x" + NOTES[1:])), now=NOW)
        self.assertEqual(registry.installed(), baseline)
        self.assertEqual(registry.journal(), log)
        self.assertEqual(list(registry.work.iterdir()), [])
        old = registry.prepare(io.BytesIO(first), now=NOW)
        with self.assertRaisesRegex(PackageError, "^package_downgrade$"):
            registry.install(old.ticket, now=NOW)
        self.assertEqual(registry.installed(), baseline)
        self.assertEqual(registry.rollback("wireguard", now=NOW).version, "1.2.3")
        self.assertEqual(registry.installed()[0]["highest_version"], "1.2.4")
        registry.remove("wireguard", now=NOW)
        self.assertEqual(registry.installed(), ())
        with self.assertRaisesRegex(PackageError, "^package_downgrade$"):
            registry.install(old.ticket, now=NOW)
        registry.collect(now=NOW + timedelta(days=2))
        self.assertEqual(list(registry.objects.iterdir()), [])
        self.assertEqual(hashlib.sha256(config.read_bytes()).hexdigest(), original_config)
        self.assertEqual([row["action"] for row in registry.journal()],
                         ["prepare", "install", "prepare", "upgrade", "prepare", "rollback", "remove"])

    def test_rechecks_staged_data_and_expiry_at_install(self):
        registry = PackageRegistry(self.root / "registry", self.publisher)
        staged = registry.prepare(io.BytesIO(self.signed()), now=NOW)
        path = registry.objects / staged.package.archive_sha256 / "payload/notes.txt"
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(PackageError, "^resource_hash_mismatch$"):
            registry.install(staged.ticket, now=NOW)
        self.assertEqual(registry.installed(), ())
        short = self.signed(self.document(expires_at="2026-11-08T00:10:00Z"))
        staged = registry.prepare(io.BytesIO(short), now=NOW)
        with self.assertRaisesRegex(PackageError, "^package_expired$"):
            registry.install(staged.ticket, now=NOW + timedelta(minutes=10))
        self.assertEqual(registry.installed(), ())

    def test_interrupted_install_is_retriable_without_partial_state(self):
        registry = PackageRegistry(self.root / "registry", self.publisher)
        staged = registry.prepare(io.BytesIO(self.signed()), now=NOW)
        with patch.object(registry, "_record", side_effect=OSError("Ошибка записи журнала")):
            with self.assertRaises(OSError):
                registry.install(staged.ticket, now=NOW)
        self.assertEqual(registry.installed(), ())
        self.assertEqual([row["action"] for row in registry.journal()], ["prepare"])
        registry.install(staged.ticket, now=NOW)
        self.assertEqual([row["action"] for row in registry.journal()], ["prepare", "install"])

    def test_online_and_offline_dependency_contract(self):
        registry = PackageRegistry(self.root / "registry", self.publisher)
        image = self.root / "image.tar"
        image.write_bytes(b"synthetic runtime blob" * (24 * 1024))
        output = self.root / "xray.tar.gz"
        args = dict(module_id="xray", version="1.0.0", issued_at=ISSUED, expires_at=EXPIRES,
                    image_digest="1" * 64, now=NOW)
        for offline in (False, True):
            digest = build(output, self.key, image=image if offline else None, **args)
            with output.open("rb") as source:
                staged = registry.prepare(source, expected_sha256=digest, now=NOW)
            plan = dependencies(staged.package.manifest)
            self.assertEqual(plan.offline_image, offline)
            self.assertEqual(plan.online_image, None if offline else "ghcr.io/xtls/xray-core@sha256:" + "1" * 64)
            seen = []
            self.assertEqual(plan.missing(lambda _: False, lambda ref: seen.append(ref) or False),
                             ("container_runtime",) if offline else ("container_runtime", "image_unavailable"))
            self.assertEqual(seen, [] if offline else [plan.online_image])
        self.assertEqual(registry.installed(), ())

    def test_rpc_rejects_wrong_uid_extra_fields_and_unframed_upload(self):
        def exchange(uid, method, params, body=b"", registry=None):
            def factory():
                if registry is None:
                    self.fail("Отклонённый RPC не должен открывать хранилище")
                return registry

            app = PackageApplication(uid, factory, clock=lambda: NOW)
            client, server = socket.socketpair()
            with client, server:
                client.sendall(canonical_json({"version": 1, "method": method, "params": params}) + b"\n" + body)
                client.shutdown(socket.SHUT_WR)
                app.handle(server)
                return json.loads(client.recv(8192))

        uid = os.geteuid()
        self.assertEqual(exchange(uid + 1, "package.status", {})["error"], "forbidden")
        self.assertEqual(exchange(uid, "package.enable", {})["error"], "invalid_request")
        self.assertEqual(exchange(uid, "package.github", {"module": "xray", "version": "1.0.0",
                                                           "tag": "v5.0.0", "url": "https://example.org"})["error"],
                         "invalid_request")
        self.assertEqual(exchange(uid, "package.status", {}, b"x")["error"], "invalid_request")
        registry = PackageRegistry(self.root / "registry", self.publisher)
        original = self.signed()
        for body, size in ((original + b"x", len(original)), (original, len(original) + 1)):
            with self.subTest(size=size):
                result = exchange(uid, "package.upload", {"size": size}, body, registry)
                self.assertEqual(result["error"], "package_body_length")
        self.assertEqual(registry.installed(), ())
        self.assertEqual(registry.journal(), ())

    def test_status_does_not_initialize_storage(self):
        state = self.root / "registry"
        with patch("v5.core.packages.status.PACKAGE_STATE", state), patch(
            "v5.core.packages.status.load_publisher", return_value=self.publisher
        ):
            self.assertEqual(package_status(), {"installed": []})
            self.assertFalse(state.exists())
            registry = PackageRegistry(state, self.publisher)
            result = registry.prepare(io.BytesIO(self.signed()), now=NOW)
            self.assertEqual(package_status(), {"installed": []})
            registry.install(result.ticket, now=NOW)
            self.assertEqual(package_status()["installed"][0]["version"], "1.2.3")

    def test_same_archive_github_and_upload_over_tcp_with_local_fallback(self):
        archive = self.signed(self.document(module_id='xray', image_digest='3' * 64))
        digest = hashlib.sha256(archive).hexdigest()
        registry = PackageRegistry(self.root / "registry", self.publisher)
        received = []
        mode = {"asset": archive, "sha": digest, "offline": False, "redirect": "https://release-assets.githubusercontent.com/module"}
        repo = "/repos/artemiygaer/kvn-portal/releases"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, body, **headers):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                received.append((self.path, self.headers["Accept"]))
                if mode["offline"]:
                    self.reply(503, b"")
                elif self.path == f"{repo}/tags/v5.0.0":
                    self.reply(200, json.dumps({
                        "tag_name": "v5.0.0", "draft": False, "prerelease": False,
                        "assets": [{"name": "kvn-module-xray-1.2.3.tar.gz", "id": 12,
                                    "size": len(mode["asset"]), "digest": f"sha256:{mode['sha']}",
                                    "state": "uploaded", "url": "https://untrusted.invalid/never"}],
                    }).encode())
                elif self.path == f"{repo}/assets/12":
                    self.reply(302, b"", Location=mode["redirect"])
                elif self.path == "/module":
                    self.reply(200, mode["asset"])
                else:
                    self.reply(404, b"")

        with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server, contextlib.ExitStack() as cleanup:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            cleanup.callback(worker.join, 2)
            cleanup.callback(server.shutdown)
            base = f"http://127.0.0.1:{server.server_address[1]}"
            transport = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

            class LocalOpener:
                def open(self, request, timeout):
                    host, _, path = request.full_url.removeprefix("https://").partition("/")
                    if host not in {"api.github.com", "release-assets.githubusercontent.com"}:
                        raise AssertionError("Недоверенный сетевой маршрут")
                    return transport.open(urllib.request.Request(f"{base}/{path}", headers=dict(request.header_items())),
                                          timeout=timeout)

            github = GitHubPackages(opener=LocalOpener())
            package_rpc = PackageApplication(os.geteuid(), lambda: registry, github=github, clock=lambda: NOW)

            class UnixHandler(socketserver.BaseRequestHandler):
                def handle(self):
                    package_rpc.handle(self.request)

            rpc_path = self.root / "packages.sock"
            unix = cleanup.enter_context(socketserver.UnixStreamServer(str(rpc_path), UnixHandler))
            unix_worker = threading.Thread(target=unix.serve_forever, daemon=True)
            unix_worker.start()
            cleanup.callback(unix_worker.join, 2)
            cleanup.callback(unix.shutdown)
            origin = "https://localhost"
            app = create_app({"session_key": "fixture-only", "allowed_hosts": ["localhost"]}, client=object(),
                             package_client=PackageClient(rpc_path, timeout=6))
            browser = app.test_client()
            with browser.session_transaction(base_url=origin) as session:
                session.update(admin=True, csrf="fixture-csrf")

            def post(action, data):
                return browser.post("/modules/" + action, base_url=origin, headers={"Origin": origin},
                                    data={"csrf": "fixture-csrf"} | data)

            online = post("github", {"module": "xray", "version": "1.2.3", "tag": "v5.0.0"})
            self.assertEqual(online.status_code, 200)
            self.assertIn(digest.encode(), online.data)
            self.assertEqual(received, [(f"{repo}/tags/v5.0.0", "application/vnd.github+json"),
                                        (f"{repo}/assets/12", "application/octet-stream"),
                                        ("/module", "application/octet-stream")])
            self.assertEqual(registry.installed(), ())
            mode["sha"] = "0" * 64
            with self.assertRaisesRegex(PackageError, "^archive_hash_mismatch$"):
                github.prepare(registry, "xray", "1.2.3", tag="v5.0.0", now=NOW)
            mode["sha"] = digest
            mode["redirect"] = "https://release-assets.githubusercontent.com@127.0.0.1/no"
            with self.assertRaisesRegex(PackageError, "^github_redirect_refused$"):
                github.prepare(registry, "xray", "1.2.3", tag="v5.0.0", now=NOW)
            mode["offline"] = True
            with self.assertRaisesRegex(PackageError, "^github_unavailable$"):
                github.prepare(registry, "xray", "1.2.3", tag="v5.0.0", now=NOW)
            uploaded = post("upload", {"package": (io.BytesIO(archive), "fixture.tar.gz")})
            self.assertEqual(uploaded.status_code, 200)
            self.assertIn(digest.encode(), uploaded.data)
            self.assertEqual(registry.installed(), ())
            self.assertEqual([row["action"] for row in registry.journal()], ["prepare", "prepare"])
            self.assertEqual(len(list(registry.objects.iterdir())), 1)
            for response in (online, uploaded):
                ticket = re.search(rb'name="ticket" value="([0-9a-f]{64})"', response.data).group(1).decode()
                self.assertEqual(post('install', {'ticket': ticket}).status_code, 303)
                row, = registry.installed()
                self.assertEqual((row['module'], row['version'], row['enabled']), ('xray', '1.2.3', 0))
