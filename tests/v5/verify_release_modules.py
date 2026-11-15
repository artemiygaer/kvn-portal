"""Проверить подписи и содержимое шести кандидатов модулей перед выпуском."""

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from v5.core.packages.archive import verify_archive
from v5.core.packages.signature import parse_publisher


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--publisher", type=Path, default=Path("v5/packaging/publisher.json"))
    args = parser.parse_args()
    publisher = parse_publisher(args.publisher.read_bytes())
    expected = {"xray", "wireguard", "amneziawg", "hysteria", "telemt", "mtg"}
    found = {}
    for archive in sorted(args.directory.glob("kvn-module-*.tar.gz")):
        with TemporaryDirectory(prefix="kvn-release-verify-") as temporary:
            with archive.open("rb") as source:
                checked = verify_archive(source, publisher, Path(temporary))
        module_id = checked.manifest.module_id
        if module_id not in expected or module_id in found:
            raise ValueError(f"Лишний или повторный модуль: {module_id}")
        if archive.name != f"kvn-module-{module_id}-{checked.manifest.version}.tar.gz":
            raise ValueError(f"Имя архива не соответствует манифесту: {archive.name}")
        found[module_id] = {"file": archive.name, "sha256": checked.archive_sha256,
                            "version": checked.manifest.version}
    if set(found) != expected:
        raise ValueError(f"Отсутствуют модули: {sorted(expected - set(found))}")
    print(json.dumps(found, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
