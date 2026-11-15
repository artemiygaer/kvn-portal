"""Неизменяемые рабочие поколения Xray и ограниченный контейнер."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import stat
from tempfile import mkdtemp

from v5.core.packages.docker_image import Docker, IMAGE_ID
from v5.core.packages.manifest import SHA256, canonical_json, json_object, reject
from v5.core.private_files import private_directory, read_private, write_private
from v5.core.tls.certificates import MAX_CHAIN_BYTES, MAX_KEY_BYTES

from .config import CONFIG_ROOT, Settings, render_server
from .credentials import profile_reality_keys
from .profiles import Kind

MODULE_ROOT = Path("/var/lib/kvn-v5/modules/xray")
CONTAINER = "kvn-v5-xray"
LABEL = "org.kvn-v5.module"
UID = 65532
_NAMES = frozenset({"config.json", "tls.crt", "tls.key"})


def _hash_parts(*values: bytes) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _validate_mount(folder: Path) -> None:
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != UID
            or stat.S_IMODE(info.st_mode) != 0o750):
        reject("unsafe_xray_runtime")
    files = tuple(folder.iterdir())
    names = {item.name for item in files}
    if names not in ({"config.json"}, _NAMES):
        reject("unsafe_xray_runtime")
    for file in files:
        info = file.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != UID
                or stat.S_IMODE(info.st_mode) != 0o640):
            reject("unsafe_xray_runtime")


@dataclass(frozen=True, slots=True)
class Runtime:
    image: str
    folder: Path

    def matches(self, current: dict) -> bool:
        mounts = current.get("mounts")
        return (current.get("image") == self.image and current.get("network") == "host"
                and isinstance(mounts, list) and len(mounts) == 1 and isinstance(mounts[0], dict)
                and mounts[0].get("Type") == "bind" and mounts[0].get("Source") == str(self.folder)
                and mounts[0].get("Destination") == CONFIG_ROOT and mounts[0].get("RW") is False)

    def arguments(self, *, test: bool) -> tuple[str, ...]:
        _validate_mount(self.folder)
        if not IMAGE_ID.fullmatch(self.image) or "," in str(self.folder):
            reject("unsafe_xray_runtime")
        args = ("run", "--rm", "--pull=never", "--network", "none" if test else "host",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
                "--user", f"{UID}:{UID}", "--pids-limit", "64", "--memory", "192m",
                "--tmpfs", "/usr/local/etc/xray:ro,noexec,nosuid,nodev,size=1m",
                "--tmpfs", "/var/log/xray:rw,noexec,nosuid,nodev,size=2m",
                "--mount", f"type=bind,source={self.folder},target={CONFIG_ROOT},readonly",
                "--entrypoint", "/usr/local/bin/xray")
        if not test:
            args += ("--name", CONTAINER, "--label", f"{LABEL}=xray", "--log-driver", "local",
                     "--log-opt", "max-size=2m", "--log-opt", "max-file=2")
        return (*args, self.image, "run", *(("-test",) if test else ()), "-config", f"{CONFIG_ROOT}/config.json")


def runtime_state(root: Path = MODULE_ROOT) -> Runtime:
    data = json_object(read_private(root / "runtime.json", 2048))
    if (data.keys() != {"generation", "image"} or not isinstance(data["generation"], str)
            or not SHA256.fullmatch(data["generation"]) or not isinstance(data["image"], str)
            or not IMAGE_ID.fullmatch(data["image"])):
        reject("unsafe_xray_runtime")
    private_directory(root / "generations")
    folder = root / "generations" / data["generation"]
    _validate_mount(folder)
    return Runtime(data["image"], folder)


def _certificate(settings, gateway):
    profile = next((item for item in settings.profiles.values if item.kind is Kind.TLS), None)
    if profile is None:
        return b"", b""
    identity = profile.tls_identity()
    pair = next((item for item in gateway.active() if item.metadata.identity == identity), None)
    if pair is None or pair.metadata.not_after <= datetime.now(timezone.utc):
        reject("xray_tls_required")
    return read_private(pair.chain, MAX_CHAIN_BYTES), read_private(pair.key, MAX_KEY_BYTES)


def prepare(root, packages, gateway, docker: Docker, *, imported=None) -> Runtime:
    settings = Settings.load(root / "settings.json")
    if not settings.profiles.values:
        reject("xray_profiles_required")
    key = profile_reality_keys(root / "reality.json", settings.profiles.values, imported=imported, create=True)
    config = canonical_json(render_server(settings, key, site_names=gateway.site_names))
    chain, secret = _certificate(settings, gateway)
    manifest, archive = packages.verified_install("xray")
    image = docker.resolve(manifest, archive)
    generations = root / "generations"
    generations.mkdir(mode=0o700, exist_ok=True)
    private_directory(generations)
    name = _hash_parts(config, chain, secret, image.id.encode("ascii"))
    folder = generations / name
    if not folder.exists():
        stage = Path(mkdtemp(prefix=".stage-", dir=generations))
        try:
            files = {"config.json": config}
            if chain:
                files.update({"tls.crt": chain, "tls.key": secret})
            for filename, raw in files.items():
                write_private(stage / filename, raw)
            for file in stage.iterdir():
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
    candidate = Runtime(image.id, folder)
    docker.run(*candidate.arguments(test=True), timeout=45, code="xray_config_check_failed")
    write_private(root / "runtime.json", canonical_json({"generation": name, "image": image.id}))
    return candidate


def inspect_container(docker: Docker, *, timeout: float = 25) -> dict | None:
    pattern = ('{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
               '"network":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},'
               '"owner":{{json (index .Config.Labels "' + LABEL + '")}}}')
    raw = docker.run("container", "inspect", "--format", pattern, CONTAINER, optional=True, timeout=timeout)
    if raw is None:
        return None
    entry = json_object(raw)
    if (entry.get("owner") != "xray" or not isinstance(entry.get("id"), str) or not SHA256.fullmatch(entry["id"])
            or not isinstance(entry.get("image"), str) or not IMAGE_ID.fullmatch(entry["image"])
            or type(entry.get("running")) is not bool):
        reject("foreign_xray_container")
    return entry


def stop_container(docker: Docker) -> None:
    current = inspect_container(docker)
    if current and current["running"]:
        docker.run("container", "stop", "-t", "5", current["id"], code="xray_stop_failed")
    elif current:
        docker.run("container", "rm", current["id"], code="xray_stop_failed")
