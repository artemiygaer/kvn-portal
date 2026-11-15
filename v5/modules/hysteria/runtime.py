"""Запуск проверенного образа с одним UDP-портом и закрытым TLS-ключом."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import stat
from tempfile import NamedTemporaryFile, mkdtemp

from v5.core.network.plan import Binding, Publication
from v5.core.packages.docker_image import Docker, IMAGE_ID
from v5.core.packages.manifest import SHA256, canonical_json, json_object, reject
from v5.core.private_files import private_directory, read_private, write_private
from v5.core.tls.certificates import MAX_CHAIN_BYTES, MAX_KEY_BYTES

from .config import CONFIG_ROOT, INNER_PORT, MODULE, TLS_ROOT, Settings, render_server
from .idle import idle_secret

MODULE_ROOT = Path("/var/lib/kvn-v5/modules/hysteria")
CONTAINER = "kvn-v5-hysteria"
LABEL = "org.kvn-v5.module"
UID = 65532
PORT_KEY = f"{INNER_PORT}/udp"


def certificate(settings, gateway):
    pair = next((item for item in gateway.active() if item.metadata.identity == settings.tls), None)
    if pair is None or pair.metadata.not_after <= datetime.now(timezone.utc) + timedelta(minutes=10):
        reject("hysteria_trusted_tls_required")
    return pair


def _mount_directory(folder: Path) -> None:
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != UID
            or stat.S_IMODE(info.st_mode) != 0o750):
        reject("unsafe_hysteria_runtime")


def _mount_file(file: Path) -> None:
    info = file.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != UID
            or stat.S_IMODE(info.st_mode) != 0o640):
        reject("unsafe_hysteria_runtime")


def validate_mount(folder: Path, filename: str) -> None:
    _mount_directory(folder)
    if {item.name for item in folder.iterdir()} != {filename}:
        reject("unsafe_hysteria_runtime")
    _mount_file(folder / filename)


def publish_certificate(root: Path, pair) -> None:
    """Атомарно заменить пару в выделенном read-only bind mount контейнера."""
    private_directory(root)
    folder = root / "tls"
    if not folder.exists():
        folder.mkdir(mode=0o700)
        os.chown(folder, os.geteuid(), UID)
        folder.chmod(0o750)
    _mount_directory(folder)
    # Hysteria перечитывает пару при handshake; при гонке чтения сохраняет предыдущую.
    # Один PEM атомарно публикует сертификат и закрытый ключ от одной пары.
    raw = (read_private(pair.chain, MAX_CHAIN_BYTES).rstrip() + b"\n"
           + read_private(pair.key, MAX_KEY_BYTES).rstrip() + b"\n")
    target = folder / "server.pem"
    if target.exists() or target.is_symlink():
        _mount_file(target)
        if target.read_bytes() == raw:
            return
    stage = None
    try:
        with NamedTemporaryFile(mode="wb", prefix=".tls-", dir=root, delete=False) as handle:
            stage = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fchown(handle.fileno(), os.geteuid(), UID)
            os.fchmod(handle.fileno(), 0o640)
            os.fsync(handle.fileno())
        stage.replace(target)
        fd = os.open(folder, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if stage is not None:
            stage.unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class Runtime:
    image: str
    folder: Path
    binding: Binding

    @property
    def tls_folder(self) -> Path:
        return self.folder.parent.parent / "tls"

    def __post_init__(self):
        if (not isinstance(self.image, str) or not IMAGE_ID.fullmatch(self.image)
                or not isinstance(self.folder, Path) or not self.folder.is_absolute() or "," in str(self.folder)
                or not isinstance(self.binding, Binding) or self.binding.protocol != "udp"
                or self.binding.address.version != 4):
            reject("unsafe_hysteria_runtime")
        Publication(self.binding)

    def arguments(self) -> tuple[str, ...]:
        validate_mount(self.folder, "server.json")
        validate_mount(self.tls_folder, "server.pem")
        return (
            "run", "--rm", "--pull=never", "--network", "bridge",
            "--publish", f"{self.binding.ip}:{self.binding.port}:{PORT_KEY}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
            "--user", f"{UID}:{UID}", "--pids-limit", "48", "--memory", "128m",
            "--mount", f"type=bind,source={self.folder},target={CONFIG_ROOT},readonly",
            "--mount", f"type=bind,source={self.tls_folder},target={TLS_ROOT},readonly",
            "--name", CONTAINER, "--label", f"{LABEL}={MODULE}", "--log-driver", "local",
            "--log-opt", "max-size=2m", "--log-opt", "max-file=2",
            "--entrypoint", "/usr/local/bin/hysteria", self.image, "server",
            "--disable-update-check", "--log-level", "warn", "--config", f"{CONFIG_ROOT}/server.json",
        )

    def matches(self, current) -> bool:
        expected = {PORT_KEY: [{"HostIp": self.binding.ip, "HostPort": str(self.binding.port)}]}
        mounts = current.get("mounts")
        paths = {CONFIG_ROOT: str(self.folder), TLS_ROOT: str(self.tls_folder)}
        return (current["image"] == self.image and current["network"] == "bridge"
                and current["ports"] == expected and isinstance(mounts, list) and len(mounts) == len(paths)
                and all(isinstance(item, dict) and item.get("Type") == "bind" and item.get("RW") is False
                        and isinstance(item.get("Destination"), str)
                        and paths.get(item["Destination"], "") == item.get("Source") for item in mounts)
                and {item["Destination"] for item in mounts} == set(paths))


def runtime_state(root: Path = MODULE_ROOT) -> Runtime:
    data = json_object(read_private(root / "runtime.json", 2048))
    if (data.keys() != {"generation", "image", "bind", "port"} or not isinstance(data["generation"], str)
            or not SHA256.fullmatch(data["generation"])):
        reject("unsafe_hysteria_runtime")
    private_directory(root / "generations")
    folder = root / "generations" / data["generation"]
    validate_mount(folder, "server.json")
    return Runtime(data["image"], folder, Binding("udp", data["bind"], data["port"]))


def _generation(root: Path, config: bytes, image: str) -> Path:
    digest = hashlib.sha256(image.encode("ascii") + b"\0" + config)
    generations = root / "generations"
    generations.mkdir(mode=0o700, exist_ok=True)
    private_directory(generations)
    folder = generations / digest.hexdigest()
    if not folder.exists():
        stage = Path(mkdtemp(prefix=".stage-", dir=generations))
        try:
            file = stage / "server.json"
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
    validate_mount(folder, "server.json")
    return folder


def prepare(root, packages, gateway, docker: Docker) -> Runtime:
    settings = Settings.load(root / "settings.json")
    config = canonical_json(render_server(settings, idle_secret=idle_secret(root, create=True)))
    pair = certificate(settings, gateway)
    manifest, archive = packages.verified_install(MODULE)
    image = docker.resolve(manifest, archive)
    folder = _generation(root, config, image.id)
    publish_certificate(root, pair)
    result = Runtime(image.id, folder, settings.binding)
    write_private(root / "runtime.json", canonical_json({"generation": folder.name, "image": image.id,
                                                        "bind": settings.bind, "port": settings.port}))
    return result


def inspect_container(docker: Docker, *, timeout: float = 25) -> dict | None:
    pattern = ('{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
               '"pid":{{json .State.Pid}},'
               '"owner":{{json (index .Config.Labels "' + LABEL + '")}},'
               '"network":{{json .HostConfig.NetworkMode}},"ports":{{json .HostConfig.PortBindings}},'
               '"mounts":{{json .Mounts}}}')
    raw = docker.run("container", "inspect", "--format", pattern, CONTAINER, optional=True,
                     timeout=timeout, code="hysteria_inspect_unavailable")
    if raw is None:
        return None
    entry = json_object(raw)
    if (entry.get("owner") != MODULE or not isinstance(entry.get("id"), str) or not SHA256.fullmatch(entry["id"])
            or not isinstance(entry.get("image"), str) or not IMAGE_ID.fullmatch(entry["image"])
            or type(entry.get("running")) is not bool or type(entry.get("pid")) is not int
            or not 0 <= entry["pid"] < 2**31 or (entry["running"] and not entry["pid"])):
        reject("foreign_hysteria_container")
    return entry


def listening(pid: int) -> bool:
    if type(pid) is not int or not 0 < pid < 2**31:
        return False
    # PID взят из inspect нашего контейнера. Таблица относится к его netns,
    # а не к хосту; Docker exec и дополнительные capabilities не нужны.
    local = f"00000000:{INNER_PORT:04X}".encode("ascii")
    uid = str(UID).encode("ascii")
    try:
        with Path(f"/proc/{pid}/net/udp").open("rb") as table:
            return any(parts[1] == local and parts[3] == b"07" and parts[7] == uid
                       for line in table if len(parts := line.split()) >= 8)
    except OSError:
        return False


def stop_container(docker: Docker) -> None:
    current = inspect_container(docker)
    if current and current["running"]:
        docker.run("container", "stop", "-t", "5", current["id"], code="hysteria_stop_failed")
    elif current:
        docker.run("container", "rm", current["id"], code="hysteria_stop_failed")
