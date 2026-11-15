"""Изолированные поколения TOML и запуск только известных MTProto-образов."""

from dataclasses import dataclass
from ipaddress import ip_address
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import stat
import subprocess
from tempfile import mkdtemp
import time

from v5.core.network.plan import Binding, SITE_BACKEND_PORT
from v5.core.packages.docker_image import Docker, IMAGE_ID
from v5.core.packages.manifest import SHA256, canonical_json, json_object, reject
from v5.core.private_files import private_directory, read_private, write_private

from .profiles import CoverTarget, PORTS

MODULES = Path("/var/lib/kvn-v5/modules")
UID = 65532
LABEL = "org.kvn-v5.module"
CONFIG_ROOT = "/etc/kvn-mtproto"
_ENTRY = {
    "telemt": ("/app/telemt", ("run", "--data-path", "/run/kvn-mtproto", "--silent")),
    "mtg": ("/mtg", ("run",)),
}


def _command(*args):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, check=True,
                          timeout=8, env={"PATH": "/usr/sbin:/usr/bin:/bin", "LC_ALL": "C"}).stdout


def cover_target(exposure, gateway) -> CoverTarget:
    if exposure.own_site:
        return CoverTarget("127.0.0.1", SITE_BACKEND_PORT)
    try:
        interfaces = json.loads(_command("/usr/sbin/ip", "-j", "-4", "addr", "show"))
        local = {info["local"] for device in interfaces for info in device["addr_info"]}
        local.update(item.name for item in gateway.identities if item.is_ip)
        rows = _command("/usr/bin/getent", "ahostsv4", exposure.sni).decode("ascii").splitlines()
        addresses = tuple(dict.fromkeys(row.split()[0] for row in rows if row.split()))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        reject("mtproto_cover_resolution_failed")
    if not addresses or len(addresses) > 32:
        reject("mtproto_cover_resolution_failed")
    targets = []
    for address in addresses:
        try:
            address = ip_address(address).compressed
        except ValueError:
            reject("mtproto_cover_not_public")
        if address in local:
            reject("mtproto_cover_loop")
        try:
            targets.append(CoverTarget(address, 443))
        except ValueError:
            reject("mtproto_cover_not_public")
    context = ssl.create_default_context()
    deadline = time.monotonic() + 8
    for target in targets[:3]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            with socket.create_connection((target.ip, target.port), timeout=min(3, remaining)) as transport:
                transport.settimeout(max(0.1, min(3, deadline - time.monotonic())))
                with context.wrap_socket(transport, server_hostname=exposure.sni):
                    return target
        except (OSError, ValueError):
            continue
    reject("mtproto_cover_tls_failed")


def _mount(folder: Path) -> None:
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != UID
            or stat.S_IMODE(info.st_mode) != 0o750 or {item.name for item in folder.iterdir()} != {"config.toml"}):
        reject("unsafe_mtproto_runtime")
    info = (folder / "config.toml").lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != UID
            or stat.S_IMODE(info.st_mode) != 0o640 or not 0 < info.st_size <= 128 * 1024):
        reject("unsafe_mtproto_runtime")


@dataclass(frozen=True, slots=True)
class Runtime:
    module: str
    image: str
    folder: Path
    address: str

    def __post_init__(self):
        if (not isinstance(self.module, str) or self.module not in _ENTRY
                or not isinstance(self.image, str) or not IMAGE_ID.fullmatch(self.image)
                or not isinstance(self.folder, Path) or not self.folder.is_absolute() or "," in str(self.folder)
                or Binding("tcp", self.address, PORTS[self.module]).address.version != 4):
            reject("unsafe_mtproto_runtime")

    @property
    def name(self):
        return f"kvn-v5-{self.module}"

    def arguments(self) -> tuple[str, ...]:
        _mount(self.folder)
        executable, command = _ENTRY[self.module]
        options = (
            "run", "--rm", "--pull=never", "--network", "host", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only", "--user", f"{UID}:{UID}",
            "--pids-limit", "48", "--memory", "128m", "--name", self.name, "--label", f"{LABEL}={self.module}",
            "--log-driver", "local", "--log-opt", "max-size=2m", "--log-opt", "max-file=2",
            "--tmpfs", f"/run/kvn-mtproto:rw,noexec,nosuid,nodev,size=8m,mode=0700,uid={UID},gid={UID}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=8m,mode=1777",
            "--mount", f"type=bind,source={self.folder},target={CONFIG_ROOT},readonly",
        )
        return (*options, "--entrypoint", executable, self.image, *command, f"{CONFIG_ROOT}/config.toml")

    def matches(self, entry) -> bool:
        mounts = entry.get("mounts")
        return (entry["image"] == self.image and entry.get("network") == "host"
                and not entry.get("ports") and isinstance(mounts, list) and len(mounts) == 1
                and isinstance(mounts[0], dict) and mounts[0].get("Type") == "bind"
                and mounts[0].get("Source") == str(self.folder) and mounts[0].get("Destination") == CONFIG_ROOT
                and mounts[0].get("RW") is False)


def read_runtime(module: str, root: Path) -> Runtime:
    raw = json_object(read_private(root / "runtime.json", 2048))
    if (raw.keys() != {"generation", "image", "address"} or not isinstance(raw["generation"], str)
            or not SHA256.fullmatch(raw["generation"])):
        reject("unsafe_mtproto_runtime")
    private_directory(root / "generations")
    folder = root / "generations" / raw["generation"]
    _mount(folder)
    return Runtime(module, raw["image"], folder, raw["address"])


def prepare(module: str, root: Path, settings, render, context, docker: Docker) -> Runtime:
    config = render(settings, cover_target(settings.exposure, context.gateway))
    manifest, archive = context.packages.verified_install(module)
    image = docker.resolve(manifest, archive)
    generations = root / "generations"
    generations.mkdir(mode=0o700, exist_ok=True)
    private_directory(generations)
    name = hashlib.sha256(image.id.encode("ascii") + b"\0" + config).hexdigest()
    folder = generations / name
    if not folder.exists():
        stage = Path(mkdtemp(prefix=".stage-", dir=generations))
        try:
            file = stage / "config.toml"
            write_private(file, config)
            os.chown(file, os.geteuid(), UID)
            file.chmod(0o640)
            os.chown(stage, os.geteuid(), UID)
            stage.chmod(0o750)
            stage.rename(folder)
            fd = os.open(generations, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    _mount(folder)
    runtime = Runtime(module, image.id, folder, settings.exposure.address)
    write_private(root / "runtime.json", canonical_json({"generation": name, "image": image.id,
                                                        "address": runtime.address}))
    return runtime


def inspect_container(docker: Docker, module: str, *, timeout: float = 25) -> dict | None:
    if module not in _ENTRY:
        reject("unsafe_mtproto_runtime")
    pattern = ('{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
               '"pid":{{json .State.Pid}},"owner":{{json (index .Config.Labels "' + LABEL + '")}},'
               '"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
               '"mounts":{{json .Mounts}}}')
    raw = docker.run("container", "inspect", "--format", pattern, f"kvn-v5-{module}", optional=True,
                     timeout=timeout, code="mtproto_inspect_unavailable")
    if raw is None:
        # Код inspect может означать как отсутствие контейнера, так и
        # недоступный daemon. Не считать последнее успешным отключением.
        docker.run("info", "--format", "{{.ServerVersion}}", timeout=timeout,
                   code="mtproto_inspect_unavailable")
        return None
    entry = json_object(raw)
    if (entry.get("owner") != module or not isinstance(entry.get("id"), str) or not SHA256.fullmatch(entry["id"])
            or not isinstance(entry.get("image"), str) or not IMAGE_ID.fullmatch(entry["image"])
            or type(entry.get("running")) is not bool or type(entry.get("pid")) is not int
            or not 0 <= entry["pid"] < 2**31 or (entry["running"] and not entry["pid"])):
        reject("foreign_mtproto_container")
    return entry


def listening(pid: int, address: str, port: int) -> bool:
    if type(pid) is not int or not 0 < pid < 2**31:
        return False
    local = f"{socket.inet_aton(address)[::-1].hex().upper()}:{port:04X}".encode("ascii")
    uid = str(UID).encode("ascii")
    try:
        with Path(f"/proc/{pid}/net/tcp").open("rb") as table:
            rows = [parts for line in table if len(parts := line.split()) >= 8 and parts[3] == b"0A"]
        if any(parts[1] == local and parts[7] == uid for parts in rows):
            return True
        # Go может открыть IPv6 wildcard с поддержкой IPv4 вместо отдельного IPv4-сокета.
        if address != "0.0.0.0":
            return False
        ipv4_endpoints = {f"00000000:{port:04X}".encode(), f"0100007F:{port:04X}".encode()}
        if any(parts[1] in ipv4_endpoints for parts in rows):
            return False
        wildcard = f"{'0' * 32}:{port:04X}".encode("ascii")
        with Path(f"/proc/{pid}/net/tcp6").open("rb") as table:
            if not any(parts[1] == wildcard and parts[3] == b"0A" and parts[7] == uid
                       for line in table if len(parts := line.split()) >= 8):
                return False
        # IPv6-only сокет не подтверждает доступность IPv4.
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def stop_container(docker: Docker, module: str):
    entry = inspect_container(docker, module)
    if entry and entry["running"]:
        docker.run("container", "stop", "-t", "5", entry["id"], code="mtproto_stop_failed")
    elif entry:
        docker.run("container", "rm", entry["id"], code="mtproto_stop_failed")
