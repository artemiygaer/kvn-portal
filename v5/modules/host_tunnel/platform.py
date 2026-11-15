"""Диагностика tools, заголовков и модуля именно загруженного Linux-ядра."""

from dataclasses import dataclass
import base64
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

from v5.modules.amneziawg.profile import Profile

from .config import AWG, WG, Tunnel


_RELEASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+~-]{0,95}", re.ASCII)
_TOOL_VERSION = re.compile(r"\b(v?[0-9]+(?:[.][0-9]+){1,3}(?:[+~-][A-Za-z0-9_.+~-]+)?)\b", re.ASCII)
_AWG31_OPTIONS = (b"header-protection-key", b"content-padding-addition", b"rekey-after-time", b"random-trailers")
_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_IP = "/usr/sbin/ip"


@dataclass(frozen=True, slots=True)
class Capability:
    kernel: str
    headers: bool
    module_available: bool
    module_version: str | None
    tools_version: str | None
    profiles: tuple[str, ...]
    issue: str | None


def trusted_tool(paths: tuple[str, ...]) -> str | None:
    for name in paths:
        path = Path(name)
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and info.st_mode & 0o111):
            return name
    return None


def tools(spec: Tunnel) -> str | None:
    if spec == WG:
        return trusted_tool(("/usr/bin/wg",))
    if spec == AWG:
        return trusted_tool(("/usr/local/bin/awg", "/usr/bin/awg"))
    raise ValueError("Неизвестный модуль туннеля")


def _probe(*argv, allow_error=False) -> bytes:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=10, check=False, env=_ENV)
    except (OSError, subprocess.SubprocessError):
        return b""
    return result.stdout[:8192] if allow_error or result.returncode == 0 else b""


def _version(raw: bytes) -> str | None:
    value = _TOOL_VERSION.search(raw.decode("ascii", "ignore"))
    return value[1] if value else None


def _tool_supports_31(help_text: bytes) -> bool:
    return all(item in help_text for item in _AWG31_OPTIONS)


def _try(*argv, data=None) -> bool:
    try:
        result = subprocess.run(argv, input=data if data is not None else b"", stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=20, check=False, env=_ENV)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _kernel_accepts_31(binary: str) -> bool:
    # Сборка upstream может показывать 1.0.0 даже на свежем теге. Проверять ABI,
    # не поднимать интерфейс, не назначать адрес или порт и не читать ключи пользователей.
    name = "kvnap" + secrets.token_hex(4)
    if not _try(_IP, "link", "add", "name", name, "type", AWG.link_type):
        return False
    try:
        synthetic_key = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        lines = ("[Interface]", *Profile.modern(synthetic_key).lines(), "")
        if not _try(binary, "setconf", name, "/dev/stdin", data="\n".join(lines).encode("ascii")):
            return False
        # Старое ядро может молча пропустить неизвестные netlink-атрибуты.
        observed = set(_probe(binary, "showconf", name).splitlines())
        return {f"HeaderProtectionKey = {synthetic_key}".encode("ascii"), b"ContentPaddingAddition = 16-64",
                b"RekeyAfterTime = 120-150", b"RandomTrailers = on"} <= observed
    finally:
        if not _try(_IP, "link", "delete", "dev", name):
            raise ValueError("Не удалось убрать проверочный интерфейс AWG")


def capability(spec: Tunnel, *, check_modern: bool = True) -> Capability:
    release = os.uname().release
    if not _RELEASE.fullmatch(release):
        raise ValueError("Неизвестная версия Linux-ядра")
    headers = (Path("/lib/modules") / release / "build/Makefile").is_file()
    kernel_name = spec.link_type
    loaded = Path("/sys/module") / kernel_name
    binary = tools(spec)
    module_available = loaded.is_dir() or bool(_probe("/usr/sbin/modinfo", "-k", release, "-F", "filename", kernel_name))
    try:
        installed_version = (loaded / "version").read_bytes()[:256] if loaded.is_dir() else b""
    except OSError:
        installed_version = b""
    # Для уже загруженного AWG не подменять его версию версией файла на диске.
    if not loaded.is_dir():
        installed_version = _probe("/usr/sbin/modinfo", "-k", release, "-F", "version", kernel_name)
    module_version = _version(installed_version)
    tools_version = _version(_probe(binary, "--version")) if binary else None
    if not binary or not tools_version:
        issue = f"{spec.module}_tools_missing"
    elif not module_available:
        issue = "amneziawg_kernel_headers_missing" if spec == AWG and not headers else f"{spec.module}_kernel_missing"
    else:
        issue = None
    profiles = ()
    if issue is None:
        profiles = ("standard",) if spec == WG else ("legacy",)
        if (spec == AWG and check_modern and _tool_supports_31(_probe(binary, "set", allow_error=True))
                and _kernel_accepts_31(binary)):
            profiles += ("3.1",)
    return Capability(release, headers, module_available, module_version, tools_version, profiles, issue)
