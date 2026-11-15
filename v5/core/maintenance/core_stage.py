"""Проверка содержимого подписанного архива без tar.extract."""

import gzip
import io
from pathlib import Path
import re
import tarfile

from v5.core.release import MAX_UNPACKED, UNIT_FILES, VENDOR_METADATA, VERSION_MEMBER

_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}\Z", re.ASCII)
_RUNTIME_SUFFIXES = {
    "core": {".py", ".conf"},
    "portal": {".py", ".html", ".js", ".css"},
    "modules": {".py"},
}
_INSTALL = {"v5/install/__init__.py", "v5/install/install.sh", "v5/install/preflight.py",
            "v5/install/setup.py", "v5/install/publisher.json", VERSION_MEMBER}
_REQUIRED = {"v5/core/agent.py", "v5/core/release.py", "v5/core/maintenance/__main__.py",
             "v5/portal/app.py", "v5/portal/templates/login.html", "v5/portal/static/portal.css"}


def stage_archive(raw: bytes, version: str, root: Path, uid: int) -> None:
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        data = compressed.read(MAX_UNPACKED + 1)
    if len(data) > MAX_UNPACKED:
        raise ValueError("Превышен лимит распаковки ядра")
    tree, units = root / "tree", root / "new-units"
    tree.mkdir(mode=0o755)
    tree.chmod(0o755)
    units.mkdir(mode=0o700)
    seen, unit_names = set(), set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = member.name
            parts = name.split("/")
            is_unit = len(parts) == 4 and parts[1:3] == ["install", "systemd"] and parts[3] in UNIT_FILES
            checked_parts = parts[:-1] if is_unit else parts
            if (name in seen or len(seen) >= 768 or member.type != tarfile.REGTYPE or member.pax_headers
                    or not 0 <= member.size <= 4 * 1024 * 1024 or not 3 <= len(parts) <= 10
                    or parts[0] != "v5" or any(not _PART.fullmatch(part) for part in checked_parts)):
                raise ValueError("Неизвестная или небезопасная запись архива ядра")
            seen.add(name)
            with archive.extractfile(member) as content:
                body = content.read()
            if name in _INSTALL:
                if name == VERSION_MEMBER and body != (version + "\n").encode("ascii"):
                    raise ValueError("Версия внутри архива не совпадает")
                continue
            if is_unit:
                if len(body) > 16 * 1024 or not body:
                    raise ValueError("Некорректный systemd unit")
                unit_names.add(parts[3])
                output = units / parts[3]
                body = body.replace(b"@WEB_UID@", str(uid).encode("ascii"))
            elif (Path(name).suffix in _RUNTIME_SUFFIXES.get(parts[1], set())
                  or name == "v5/core/tls/requirements-acme.lock" or name in VENDOR_METADATA):
                output = tree / name
                output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                if name.endswith(".py"):
                    compile(body, name, "exec", dont_inherit=True)
            else:
                raise ValueError("Файл не входит в контракт обновления ядра")
            with output.open("xb") as handle:
                handle.write(body)
            output.chmod(0o644)
    if unit_names != set(UNIT_FILES) or not _REQUIRED <= seen or VERSION_MEMBER not in seen:
        raise ValueError("Архив ядра неполный или меняет набор служб")
    (tree / "core-version").write_text(version + "\n", encoding="ascii")
    (tree / "core-version").chmod(0o644)
    # Установщик и SSH могут работать с umask 077; web читает только готовое дерево.
    for directory in tree.rglob("*"):
        if directory.is_dir():
            directory.chmod(0o755)
