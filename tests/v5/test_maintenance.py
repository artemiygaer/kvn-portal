"""Границы копии, защита файлов и аварийная ротация сеансов."""

import gzip
import io
import json
import os
from pathlib import Path
import stat
import tarfile
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock

from v5.core.credentials import verify_admin_password
from v5.core.maintenance import access, backup
from v5.portal.app import create_app


class BackupTests(TestCase):
    def test_archive_bounded_allowlist_and_digest(self):
        files = {name: b"synthetic" for name in backup.REQUIRED}
        name = "gateway/certs/dns-" + "a" * 60 + "." + "b" * 60 + "." + "c" * 58 + "/" + "f" * 64 + "/privkey.pem"
        files[name] = b"synthetic-key"
        with TemporaryDirectory() as directory:
            root = Path(directory)
            artifact, digest = backup.save(root / "private", files)
            path = root / "private" / artifact
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(backup.load(path.parent, artifact, digest), files)
            for unsafe in ("../" + artifact, str(path)):
                with self.assertRaises(ValueError):
                    backup.load(path.parent, unsafe, digest)
            with self.assertRaises(ValueError):
                backup.load(path.parent, artifact, "0" * 64)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                backup.load(path.parent, artifact, digest)
        for extra in ("users/users.sqlite3", "gateway/../bootstrap.key", "/etc/shadow"):
            with self.assertRaises(ValueError):
                backup.encode({**files, extra: b"x"})
        with self.assertRaises(ValueError):
            backup.decode(gzip.compress(b"0" * (backup.MAX_ARCHIVE + 128 * 1024)))

    def test_refuses_duplicate_links_unknown_entries_and_bad_manifest(self):
        files = {name: b"synthetic" for name in backup.REQUIRED}
        for invalid, kind in (("site/index.html", tarfile.REGTYPE),
                              ("packages/publisher.json", tarfile.SYMTYPE),
                              ("../outside", tarfile.REGTYPE)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name in (*files, invalid):
                    info = tarfile.TarInfo(name)
                    info.type = kind if name == invalid else tarfile.REGTYPE
                    info.size = 0 if info.type != tarfile.REGTYPE else 1
                    archive.addfile(info, io.BytesIO(b"x"))
            with self.subTest(invalid=invalid, kind=kind), self.assertRaises(ValueError):
                backup.decode(buffer.getvalue())
        raw = gzip.decompress(backup.encode(files)).replace(b"synthetic", b"different", 1)
        with self.assertRaises(ValueError):
            backup.decode(gzip.compress(raw))

    def test_runtime_file_does_not_follow_links_or_include_world_readable_secret(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "real"
            file.write_bytes(b"data")
            file.chmod(0o600)
            (root / "symlink").symlink_to(file)
            (root / "dir").mkdir()
            (root / "directory-symlink").symlink_to(root)
            for path in (root / "symlink", root / "directory-symlink" / "real"):
                with self.assertRaises(ValueError):
                    backup.read_owned(path, 0o600)
            os.link(file, root / "another")
            with self.assertRaises(ValueError):
                backup.read_owned(file, 0o600)


class AccessTests(TestCase):
    def test_reset_recovers_corrupt_config_and_rollback_restores_old_file(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "web").mkdir()
            (root / "web").chmod(0o750)
            gid = (root / "web").stat().st_gid
            path = root / "web/config.json"
            path.write_bytes(b"{broken")
            path.chmod(0o640)
            (root / "gateway").mkdir()
            identities = root / "gateway/identities.json"
            identities.write_text('{"ip":"192.0.2.8","names":["portal.example"],"ipv6":false}', encoding="ascii")
            identities.chmod(0o600)
            activate = Mock(side_effect=[RuntimeError("fixture"), None])
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                access.change(root, gid, "admin", "fixture-password-1", activate=activate)
            self.assertEqual(path.read_bytes(), b"{broken")
            self.assertEqual(activate.call_count, 2)
            access.change(root, gid, "other-admin", "fixture-password-1", activate=Mock())
            new = json.loads(path.read_bytes())
            self.assertEqual(new["login"], "other-admin")
            self.assertIn("portal.example:8443", new["allowed_hosts"])
            self.assertTrue(verify_admin_password("fixture-password-1", new["password_hash"]))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            access.change(root, gid, "other-admin", "fixture-password-2", activate=Mock())
            next_config = json.loads(path.read_bytes())
            self.assertNotEqual(next_config["session_key"], new["session_key"])
            self.assertFalse(verify_admin_password("fixture-password-1", next_config["password_hash"]))

    def test_maintenance_is_read_only_and_has_no_backend_request(self):
        backend = Mock()
        app = create_app({"session_key": "fixture", "allowed_hosts": ["localhost:8443"]}, client=backend)
        origin = "https://localhost:8443"
        browser = app.test_client()
        self.assertEqual(browser.get("/maintenance", base_url=origin).status_code, 303)
        with browser.session_transaction(base_url=origin) as session:
            session["admin"] = True
        page = browser.get("/maintenance", base_url=origin)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"reset-admin", page.data)
        self.assertNotIn(b"<script", page.data)
        self.assertEqual(browser.post("/maintenance", base_url=origin, headers={"Origin": origin}).status_code, 405)
        self.assertEqual(backend.mock_calls, [])
