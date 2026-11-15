"""Проверка ограниченного контейнера обновления без запуска обновления."""

import io
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
from unittest import TestCase

from v5.core.maintenance.core_bundle import LIMITS, ORDER, build, unpack
from v5.core.release import ARCHIVE, MANIFEST, SIGNATURE


class CoreBundleTests(TestCase):
    def test_reproducible_bundle_contains_only_three_release_assets(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, result = root / "source", root / "result"
            source.mkdir(mode=0o700)
            result.mkdir(mode=0o700)
            values = {MANIFEST: b"{}", SIGNATURE: b"x" * 64, ARCHIVE: b"fixture-archive"}
            for name, data in values.items():
                (source / name).write_bytes(data)
            first, second = root / "first.tar", root / "second.tar"
            build(source, first)
            build(source, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            unpack(first, result)
            self.assertEqual({path.name: path.read_bytes() for path in result.iterdir()}, values)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in result.iterdir()))

    def test_rejects_traversal_links_duplicates_and_missing_members(self):
        entries = (("../escape", tarfile.REGTYPE, b"x"), (MANIFEST, tarfile.SYMTYPE, b""),
                   (MANIFEST, tarfile.REGTYPE, b"{}"), (SIGNATURE, tarfile.REGTYPE, b"x" * 63))
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, kind, data in entries:
                with self.subTest(name=name, kind=kind, size=len(data)):
                    source, destination = root / "bad.tar", root / "destination"
                    destination.mkdir(mode=0o700)
                    with tarfile.open(source, "w") as archive:
                        member = tarfile.TarInfo(name)
                        member.type, member.size = kind, len(data)
                        if kind == tarfile.SYMTYPE:
                            member.linkname = "/etc/passwd"
                        archive.addfile(member, io.BytesIO(data))
                    with self.assertRaises(ValueError):
                        unpack(source, destination)
                    for path in destination.iterdir():
                        path.unlink()
                    destination.rmdir()
                    source.unlink()
            self.assertFalse((root / "escape").exists())

    def test_duplicate_member_is_rejected(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, destination = root / "bad.tar", root / "destination"
            destination.mkdir(mode=0o700)
            with tarfile.open(source, "w") as archive:
                for name in (MANIFEST, MANIFEST):
                    member = tarfile.TarInfo(name)
                    member.size = 2
                    archive.addfile(member, io.BytesIO(b"{}"))
            with self.assertRaises(ValueError):
                unpack(source, destination)

    def test_rejects_symlink_source_and_nonprivate_destination(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            real, link, directory = root / "real", root / "link", root / "destination"
            real.write_bytes(b"x")
            link.symlink_to(real)
            directory.mkdir(mode=0o700)
            with self.assertRaises(OSError):
                unpack(link, directory)
            directory.chmod(0o755)
            with self.assertRaises(ValueError):
                unpack(real, directory)

    def test_release_files_have_explicit_limits(self):
        self.assertEqual(set(ORDER), set(LIMITS))
        self.assertEqual(LIMITS[SIGNATURE], 64)
