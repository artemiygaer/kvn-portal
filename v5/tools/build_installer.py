"""Собрать воспроизводимый архив установщика без данных сервера."""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
from tempfile import TemporaryDirectory

from v5.core.contracts import CORE_API_VERSION
from v5.core.packages.manifest import canonical_json
from v5.core.packages.signature import parse_publisher
from v5.core.release import ARCHIVE as NAME, MANIFEST, SIGNATURE, VENDOR_METADATA, VERSION_MEMBER, Release, stable_version

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ("core", "portal", "install", "modules")
SOURCE_EXTENSIONS = frozenset({".py", ".html", ".css", ".js", ".sh", ".conf", ".service", ".path", ".timer", ".socket"})
EXTRA_SOURCE = ROOT / "v5/core/tls/requirements-acme.lock"


def build(destination: Path, publisher_pin: Path | None = None, *, version: str | None = None) -> str:
    if version is not None:
        stable_version(version)
    files = []
    for component in COMPONENTS:
        base = ROOT / "v5" / component
        for source in base.rglob("*"):
            if source.is_symlink():
                raise ValueError(f"Симлинк в исходниках установщика: {source.relative_to(ROOT)}")
            extensions = {".py"} if component == "modules" else SOURCE_EXTENSIONS
            if source.is_file() and (source.suffix in extensions or source == EXTRA_SOURCE
                                     or source.relative_to(ROOT).as_posix() in VENDOR_METADATA):
                files.append(source)
    pin = None
    if publisher_pin is not None:
        with publisher_pin.open("rb") as handle:
            pin = handle.read(4097)
        parse_publisher(pin)
    with destination.open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for source in sorted(files):
                    info = tarfile.TarInfo(source.relative_to(ROOT).as_posix())
                    info.mode = 0o755 if source.suffix == ".sh" else 0o644
                    with source.open("rb") as body:
                        info.size = source.stat().st_size
                        archive.addfile(info, body)
                if pin is not None:
                    info = tarfile.TarInfo("v5/install/publisher.json")
                    info.mode, info.size = 0o644, len(pin)
                    archive.addfile(info, io.BytesIO(pin))
                if version is not None:
                    raw = (version + "\n").encode("ascii")
                    info = tarfile.TarInfo(VERSION_MEMBER)
                    info.mode, info.size = 0o644, len(raw)
                    archive.addfile(info, io.BytesIO(raw))
    with destination.open("rb") as artifact:
        return hashlib.file_digest(artifact, "sha256").hexdigest()


def sign_release(archive: Path, key: Path, pin: Path, version: str) -> None:
    from v5.core.maintenance.core_bundle import NAME as BUNDLE, build as build_bundle

    archive = archive.resolve(strict=True)
    for name in (MANIFEST, SIGNATURE, BUNDLE):
        if (archive.parent / name).exists() or (archive.parent / name).is_symlink():
            raise FileExistsError(name)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    with tarfile.open(archive, "r:gz") as compressed, compressed.extractfile(VERSION_MEMBER) as member:
        if member.read(49) != (version + "\n").encode("ascii"):
            raise ValueError("Версия внутри установщика не совпадает")
    raw = canonical_json({"kind": "kvn-v5-core", "format": 1, "core_api": CORE_API_VERSION,
                          "version": version, "sha256": digest, "size": archive.stat().st_size})
    Release.parse(raw)
    with pin.open("rb") as stream:
        publisher = parse_publisher(stream.read(4097))
    with TemporaryDirectory(dir=archive.parent, prefix=".sign-core-") as directory:
        stage = Path(directory)
        manifest, signature = stage / MANIFEST, stage / SIGNATURE
        manifest.write_bytes(raw)
        subprocess.run(["/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key.resolve()),
                        "-in", str(manifest), "-out", str(signature)], check=True, timeout=10,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={"LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
        publisher.verify(raw, signature.read_bytes(), stage)
        os.link(archive, stage / NAME)
        bundle = stage / BUNDLE
        build_bundle(stage, bundle)
        linked = []
        try:
            for item in (manifest, signature, bundle):
                destination = archive.parent / item.name
                os.link(item, destination)
                linked.append(destination)
        except BaseException:
            for item in linked:
                item.unlink()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Существующий выходной каталог")
    parser.add_argument("--publisher-pin", type=Path, help="JSON только с публичным ключом и закреплённым SHA-256")
    parser.add_argument("--version", help="Стабильная версия ядра без v")
    parser.add_argument("--signing-key", type=Path, help="Ed25519-ключ издателя; не включается в архив")
    parser.add_argument("--public-names", action="store_true", help="Выдать файлы с нейтральными именами для публикации")
    args = parser.parse_args()
    if args.signing_key and not (args.version and args.publisher_pin):
        parser.error("Для подписи укажите --version и --publisher-pin")
    if args.public_names:
        with TemporaryDirectory(dir=args.directory, prefix=".publish-core-") as directory:
            _emit(Path(directory), args, args.directory)
    else:
        _emit(args.directory, args, None)


def _emit(directory: Path, args, public_dir: Path | None) -> None:
    from v5.core.maintenance.core_bundle import NAME as BUNDLE

    build(directory / NAME, args.publisher_pin, version=args.version)
    names = (NAME,)
    if args.signing_key:
        sign_release(directory / NAME, args.signing_key, args.publisher_pin, args.version)
        names += (MANIFEST, SIGNATURE, BUNDLE)
    linked = []
    try:
        for name in names:
            output = name.removeprefix("kvn-") if public_dir is not None else name
            path = directory / name
            if public_dir is not None:
                os.link(path, public_dir / output)
                linked.append(public_dir / output)
            with path.open("rb") as artifact:
                print(f"{hashlib.file_digest(artifact, 'sha256').hexdigest()}  {output}")
    except BaseException:
        for path in linked:
            path.unlink()
        raise


if __name__ == "__main__":
    main()
