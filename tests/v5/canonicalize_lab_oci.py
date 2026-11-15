"""Сформировать из OCI-export проверенный архив без тегов для тестового стенда."""

import argparse
from io import BytesIO
import json
from pathlib import Path
import tarfile

from v5.core.packages.manifest import SHA256, canonical_json
from v5.core.packages.oci import verify_oci

PREFIX = "blobs/sha256/"


def canonicalize(source: Path, destination: Path, expected: str) -> None:
    if not SHA256.fullmatch(expected):
        raise ValueError("Некорректный digest")
    if destination.exists() or source == destination:
        raise ValueError("Результат уже существует")
    if source.is_symlink() or not source.is_file() or not 1 <= source.stat().st_size <= 512 * 1024**2:
        raise ValueError("Некорректный исходный архив")
    created = False
    try:
        with tarfile.open(source, "r:") as original:
            names = [item.name for item in original]
            if len(names) > 140 or len(names) != len(set(names)):
                raise ValueError("Повторяющиеся записи")
            def metadata(name):
                info = original.getmember(name)
                if not info.isreg() or not 1 <= info.size <= 128 * 1024:
                    raise ValueError("Некорректные метаданные")
                with original.extractfile(info) as body:
                    return json.load(body)

            index = metadata("index.json")
            rows = index["manifests"]
            if len(rows) != 1 or rows[0]["digest"] != "sha256:" + expected:
                raise ValueError("Неверный манифест")
            descriptor = {key: rows[0][key] for key in ("mediaType", "digest", "size")}
            image = metadata(PREFIX + expected)
            config = PREFIX + image["config"]["digest"][7:]
            layers = [PREFIX + row["digest"][7:] for row in image["layers"]]
            blobs = (PREFIX + expected, config, *layers)
            if any(not name.startswith(PREFIX) or not SHA256.fullmatch(name[len(PREFIX):]) for name in blobs):
                raise ValueError("Некорректные пути blob")
            if len(set(blobs)) != len(blobs):
                raise ValueError("Повторяющиеся blob")
            target = destination.open("xb")
            created = True
            with target, tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as out:
                def emit(name, content):
                    info = tarfile.TarInfo(name)
                    info.mode, info.size = 0o644, len(content)
                    out.addfile(info, BytesIO(content))

                emit("oci-layout", canonical_json({"imageLayoutVersion": "1.0.0"}))
                emit("index.json", canonical_json({"schemaVersion": 2,
                                                   "mediaType": "application/vnd.oci.image.index.v1+json",
                                                   "manifests": [descriptor]}))
                emit("manifest.json", json.dumps([{"Config": config, "Layers": layers, "RepoTags": []}],
                                                  separators=(",", ":")).encode("ascii"))
                for name in blobs:
                    member = original.getmember(name)
                    if not member.isreg() or not 0 < member.size <= 512 * 1024**2:
                        raise ValueError("Некорректный blob")
                    info = tarfile.TarInfo(name)
                    info.mode, info.size = 0o644, member.size
                    with original.extractfile(member) as body:
                        out.addfile(info, body)
        verify_oci(destination, expected, arch="amd64")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("digest")
    args = parser.parse_args()
    canonicalize(args.source, args.destination, args.digest)
    print("OCI: исходный digest и все blob проверены.")


if __name__ == "__main__":
    main()
