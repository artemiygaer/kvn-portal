"""Настоящий v4.2 .kvn через Flask и ограниченный Unix RPC, без запуска модулей."""

import json
import os
from pathlib import Path
import re
import socket
from tempfile import TemporaryDirectory
from threading import Event, Thread
from unittest import TestCase
from unittest.mock import Mock

from tests.v5.fixtures.make_v42_fixture import build_fixture
from v5.core.contracts import CORE_API_VERSION
from v5.core.migration.crypto import MAX_ENCRYPTED, decrypt_archive
from v5.core.migration.rpc import MigrationApplication, build_service
from v5.core.migration.target import MigrationTarget
from v5.portal.app import create_app
from v5.portal.migration_client import MigrationClient

PHRASE = "only-a-synthetic-passphrase"
ORIGIN = "https://localhost:8443"
URL = "/users/migration"


class MigrationPortalTests(TestCase):
    def test_real_archive_preview_session_commit_export_and_rollback(self):
        with TemporaryDirectory() as directory, socket.socket(socket.AF_UNIX) as server:
            root = Path(directory)
            target = MigrationTarget(root / "packages", root / "gateway")
            target.packages.mkdir(mode=0o700)
            service = build_service(target)
            rpc = MigrationApplication(os.geteuid(), lambda: service)
            path = root / "migration.sock"
            server.bind(str(path))
            server.listen(2)
            server.settimeout(0.1)
            stop = Event()

            def serve():
                while not stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        rpc.handle(connection)

            worker = Thread(target=serve, daemon=True)
            worker.start()
            try:
                app = create_app({"session_key": "fixture-only", "allowed_hosts": ["localhost:8443"]},
                                 client=object(), migration_client=MigrationClient(path))
                admin, other, guest = (app.test_client() for _ in range(3))
                for browser, csrf in ((admin, "session-one"), (other, "session-two")):
                    with browser.session_transaction(base_url=ORIGIN) as session:
                        session.update(admin=True, csrf=csrf)

                def post(action, *, browser=admin, csrf="session-one", **data):
                    return browser.post(f"{URL}/{action}", data={"csrf": csrf, **data}, base_url=ORIGIN,
                                        headers={"Origin": ORIGIN})

                def preview(archive, phrase, csrf="session-one"):
                    boundary = "kvn-fixture-archive-boundary"
                    parts = [f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
                             for name, value in (("csrf", csrf), ("mode", "restore"), ("phrase", phrase))]
                    parts.extend((f'--{boundary}\r\nContent-Disposition: form-data; name="archive"; '
                                  'filename="fixture.kvn"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode(),
                                  archive, f"\r\n--{boundary}--\r\n".encode()))
                    return admin.post(f"{URL}/preview", data=b"".join(parts), base_url=ORIGIN, headers={"Origin": ORIGIN},
                                      content_type=f"multipart/form-data; boundary={boundary}")

                data = build_fixture()
                self.assertEqual(guest.get(URL, base_url=ORIGIN).status_code, 303)
                self.assertEqual(preview(data, PHRASE, "invalid").status_code, 403)
                self.assertEqual(preview(data, "wrong-archive-phrase").status_code, 303)
                self.assertEqual(preview(b"a" * (MAX_ENCRYPTED + 1), PHRASE).status_code, 303)
                self.assertEqual(service.repository.current().users, ())
                response = preview(data, PHRASE)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["Cache-Control"], "no-store")
                self.assertIn(b"AuditFixture", response.data)
                self.assertNotIn(PHRASE.encode(), response.data)
                self.assertIn(b"OpenConnect", response.data)
                self.assertEqual(service.repository.current().users, ())
                ticket = re.search(rb'name="ticket" value="([0-9a-f]{64})"', response.data)[1].decode()
                self.assertEqual(post("commit", browser=other, csrf="session-two", ticket=ticket, confirm="yes").status_code, 303)
                self.assertEqual(post("commit", ticket=ticket).status_code, 303)
                self.assertEqual(service.repository.current().users, ())
                self.assertEqual(post("commit", ticket=ticket, confirm="yes").status_code, 303)
                (row,) = service.repository.current().users
                self.assertEqual(row.user.name, "AuditFixture")
                self.assertEqual(post("commit", ticket=ticket, confirm="yes").status_code, 303)
                self.assertEqual(service.repository.current().users, (row,))
                response = post("export", phrase=PHRASE, repeat=PHRASE)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["Content-Disposition"], 'attachment; filename="kvn-users-v5.kvn"')
                self.assertEqual(json.loads(decrypt_archive(response.data, PHRASE)), service.repository.current().document())
                self.assertEqual(post("rollback", confirm="yes").status_code, 303)
                self.assertEqual(service.repository.current().users, ())
                self.assertFalse((target.packages / "registry.sqlite3").exists())
                self.assertFalse(target.modules.exists())
            finally:
                stop.set()
                worker.join(timeout=2)

    def test_peer_and_frame_limits_reject_before_service(self):
        for uid, size, payload, expected in (
            (os.geteuid() + 1, 1, b"x", "forbidden"),
            (os.geteuid(), MAX_ENCRYPTED + 1, b"", "migration_archive_size"),
            (os.geteuid(), 2, b"x", "migration_body_length"),
            (os.geteuid(), 1, b"xx", "migration_body_length"),
        ):
            with self.subTest(error=expected):
                client, server = socket.socketpair()
                factory = Mock(side_effect=AssertionError("Запрещённый кадр дошёл до службы"))
                rpc = MigrationApplication(uid, factory)
                with client, server:
                    client.settimeout(2)
                    request = {"version": CORE_API_VERSION, "method": "migration.preview", "params": {
                        "size": size, "phrase": PHRASE, "mode": "restore", "owner": "a" * 64}}
                    client.sendall(json.dumps(request).encode() + b"\n" + payload)
                    client.shutdown(socket.SHUT_WR)
                    rpc.handle(server)
                    self.assertEqual(json.loads(client.recv(4096)), {"ok": False, "error": expected})
                factory.assert_not_called()
