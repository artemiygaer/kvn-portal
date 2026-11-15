"""Разрешение образа из проверенного пакета без использования изменяемых тегов."""

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess

from .manifest import Manifest, reject
from .oci import VerifiedImage, architecture, verify_oci

DOCKER = "/usr/bin/docker"
HOST = "unix:///run/docker.sock"
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"}
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_FORMAT = ('{"id":{{json .Id}},"os":{{json .Os}},"arch":{{json .Architecture}},'
           '"digests":{{json .RepoDigests}}}')


@dataclass(frozen=True, slots=True)
class LocalImage:
    id: str
    os: str
    arch: str
    digests: tuple[str, ...]


class Docker:
    def command(self, *args):
        return DOCKER, "--host", HOST, *args

    def run(self, *args, timeout=25, optional=False, code="docker_operation_failed"):
        try:
            result = subprocess.run(self.command(*args), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=timeout, check=False, env=ENV)
        except (OSError, subprocess.SubprocessError):
            reject(code)
        if result.returncode:
            if optional:
                return None
            reject(code)
        return result.stdout

    def ready(self):
        self.run("info", "--format", "{{.ServerVersion}}", code="docker_unavailable")

    def inspect(self, reference: str) -> LocalImage | None:
        raw = self.run("image", "inspect", "--format", _FORMAT, reference, optional=True)
        if raw is None:
            return None
        try:
            entry = json.loads(raw)
            digests = entry["digests"] or []
            if (not isinstance(entry["id"], str) or not IMAGE_ID.fullmatch(entry["id"])
                    or not isinstance(digests, list) or any(not isinstance(item, str) for item in digests)):
                raise ValueError
            return LocalImage(entry["id"], entry["os"], entry["arch"], tuple(digests))
        except (ValueError, KeyError, TypeError):
            reject("docker_image_identity_invalid")

    def _find_offline(self, verified: VerifiedImage) -> LocalImage | None:
        candidates = {f"sha256:{verified.manifest_digest}", f"sha256:{verified.config_digest}"}
        for ref in sorted(candidates):
            local = self.inspect(ref)
            if local and local.id in candidates and local.os == "linux" and local.arch == verified.architecture:
                return local
        return None

    def resolve(self, manifest: Manifest, directory: Path) -> LocalImage:
        if not manifest.image_ref or not manifest.image_digest:
            reject("module_image_required")
        self.ready()
        arch = architecture()
        if manifest.offline_image:
            archive = directory / "payload/image.tar"
            verified = verify_oci(archive, manifest.image_digest, arch=arch)
            local = self._find_offline(verified)
            if local is None:
                self.run("image", "load", "--input", str(archive), timeout=240, code="docker_load_failed")
                local = self._find_offline(verified)
            if local is None:
                reject("docker_offline_image_mismatch")
            return local
        local = self.inspect(manifest.image_ref)
        if local is None:
            self.run("image", "pull", "--platform", f"linux/{arch}", manifest.image_ref,
                     timeout=240, code="docker_pull_failed")
            local = self.inspect(manifest.image_ref)
        # Engine может вернуть имя Docker Hub без префикса, не меняя digest.
        aliases = {manifest.image_ref}
        if manifest.image_ref.startswith("docker.io/"):
            aliases.add(manifest.image_ref.removeprefix("docker.io/"))
        if local is None or local.os != "linux" or local.arch != arch or aliases.isdisjoint(local.digests):
            reject("docker_online_image_mismatch")
        return local
