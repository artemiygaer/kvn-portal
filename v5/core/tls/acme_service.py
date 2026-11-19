"""Выпуск и обновление TLS без передачи параметров командной строки из UI."""

from dataclasses import dataclass
from datetime import datetime
import os
from pathlib import Path
import stat
import subprocess

from . import imported as generations
from .acme import ACME_ROOT, CERTBOT, AcmeMode, AcmePlan, require_certbot_version, zerossl_ready
from .certificates import CertificateError, MAX_CHAIN_BYTES, MAX_KEY_BYTES, read_certificate_info
from .controller import GatewayController
from .identity import TLSIdentity
from .probe import check_nginx, reload_nginx, verify_bootstrap, verify_pair
from .transaction import GatewayApplyError, _pair_digest


ZEROSSL_GENERATIONS = generations.PATH.with_name("zerossl-generations.json")


class AcmeError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AcmeResult:
    status: str
    expires_at: datetime | None = None


def _classify(output: bytes) -> str:
    output = output.lower()
    if b"nxdomain" in output or b"dns problem" in output or b"no valid a records" in output:
        return "dns_failed"
    if b"ratelimited" in output or b"too many certificates" in output or b"rate limit" in output:
        return "rate_limited"
    if b"unauthorized" in output or b"invalid response" in output or b"challenge" in output:
        return "challenge_failed"
    return "acme_failed"


def _read_lineage(path: Path, directory: Path, maximum: int, *, private: bool = False) -> bytes:
    try:
        base = directory.resolve(strict=True)
        actual = path.resolve(strict=True)
        if base != directory or not actual.is_relative_to(base):
            raise AcmeError("lineage_invalid")
        fd = os.open(actual, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            attrs = os.fstat(stream.fileno())
            if (not stat.S_ISREG(attrs.st_mode) or attrs.st_uid != os.geteuid()
                    or attrs.st_mode & (0o077 if private else 0o022)):
                raise AcmeError("lineage_invalid")
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise AcmeError("lineage_missing") from exc
    if not data or len(data) > maximum:
        raise AcmeError("lineage_invalid")
    return data


class CertbotClient:
    def __init__(self, *, root: Path = ACME_ROOT, executable: Path = CERTBOT):
        self.root = root
        self.executable = executable

    def plan(self, identity: TLSIdentity, mode: AcmeMode) -> AcmePlan:
        return AcmePlan(identity, mode, root=self.root, executable=self.executable)

    def _call(self, argv: tuple[str, ...], timeout: int) -> bytes:
        try:
            result = subprocess.run(argv, check=False, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(self.root)})
        except FileNotFoundError as exc:
            raise AcmeError("certbot_missing") from exc
        except subprocess.TimeoutExpired as exc:
            raise AcmeError("acme_timeout") from exc
        except OSError as exc:
            raise AcmeError("acme_failed") from exc
        if result.returncode != 0:
            raise AcmeError(_classify(result.stdout[-16384:] + result.stderr[-16384:]))
        return result.stdout

    def _require_version(self) -> None:
        output = self._call((str(self.executable), "--version"), 40)
        try:
            require_certbot_version(output.decode("ascii"))
        except ValueError as exc:
            raise AcmeError("certbot_old") from exc

    def material(self, plan: AcmePlan) -> tuple[bytes, bytes]:
        chain, key = plan.candidate
        archive = plan.configuration / "archive" / plan.identity.slot
        return (_read_lineage(chain, archive, MAX_CHAIN_BYTES),
                _read_lineage(key, archive, MAX_KEY_BYTES, private=True))

    def issue(self, plan: AcmePlan, email: str) -> tuple[bytes, bytes]:
        argv = plan.issue(email)
        if plan.mode is AcmeMode.ZEROSSL and not zerossl_ready(self.root):
            raise AcmeError("zerossl_not_configured")
        self._require_version()
        folder = self.root / plan.mode.value
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.is_symlink() or folder.stat().st_uid != os.geteuid() or folder.stat().st_mode & 0o077:
            raise AcmeError("lineage_invalid")
        self._call(argv, 180)
        return self.material(plan)

    def renew(self, plan: AcmePlan) -> tuple[bytes, bytes]:
        if plan.mode is AcmeMode.STAGING:
            raise AcmeError("lineage_invalid")
        if plan.mode is AcmeMode.ZEROSSL and not zerossl_ready(self.root):
            raise AcmeError("zerossl_not_configured")
        self._require_version()
        self._call(plan.renew(), 180)
        return self.material(plan)


class AcmeService:
    def __init__(self, gateway: GatewayController, client: CertbotClient | None = None,
                 *, zerossl_path: Path = ZEROSSL_GENERATIONS):
        self.gateway = gateway
        self.client = CertbotClient() if client is None else client
        self.zerossl_path = zerossl_path
        self.zerossl = generations.load(zerossl_path)

    def renewal_mode(self, identity: TLSIdentity) -> AcmeMode:
        if not identity.is_ip and self.gateway.generation(identity) in self.zerossl.get(identity.slot, ()):
            return AcmeMode.ZEROSSL
        return AcmeMode.PUBLIC

    def _apply_public(self, identity, material, mode):
        if mode is AcmeMode.ZEROSSL:
            current = self.gateway.generation(identity)
            candidate = _pair_digest(*material)
            previous = self.zerossl.get(identity.slot, ())
            keep = [current] if current in previous and current != candidate else []
            # До смены шлюза известны оба допустимых поколения. При сбое старый центр не меняется.
            if self.zerossl.get(identity.slot) != [*keep, candidate]:
                updated = {**self.zerossl, identity.slot: [*keep, candidate]}
                generations.save(updated, self.zerossl_path)
                self.zerossl = updated
        return self._activate(identity, material)

    def _activate(self, identity: TLSIdentity, material: tuple[bytes, bytes]) -> AcmeResult:
        before = self.gateway.generation(identity)
        pair = self.gateway.activate(identity, *material, check=check_nginx, reload=reload_nginx,
                                     verify_live=verify_pair,
                                     verify_restored=lambda: verify_bootstrap(self.gateway.config.parent / "bootstrap.crt"))
        return AcmeResult("unchanged" if before == pair.chain.parent.name else "active", pair.metadata.not_after)

    def issue(self, identity: TLSIdentity, mode: AcmeMode, email: str) -> AcmeResult:
        if identity not in self.gateway.identities:
            raise ValueError("Имя не зарегистрировано на шлюзе")
        plan = self.client.plan(identity, mode)
        material = self.client.issue(plan, email)
        if mode is AcmeMode.STAGING:
            info = read_certificate_info(identity, material[0])
            return AcmeResult("staging_issued", info.not_after)
        return self._apply_public(identity, material, mode)

    def import_pair(self, identity: TLSIdentity, chain: bytes, key: bytes) -> AcmeResult:
        """Проверить и атомарно применить импортированную пару зарегистрированного имени."""
        if identity not in self.gateway.identities:
            raise ValueError("Имя не зарегистрировано на шлюзе")
        return self._activate(identity, (chain, key))

    def renew_due(self, imported: dict[str, list[str]] | None = None) -> dict[TLSIdentity, AcmeResult]:
        results = {}
        for identity in self.gateway.identities:
            # Автоматический ACME не заменяет вручную импортированное поколение.
            if imported and self.gateway.generation(identity) in imported.get(identity.slot, ()):
                continue
            try:
                mode = self.renewal_mode(identity)
                plan = self.client.plan(identity, mode)
            except ValueError:
                continue
            if not plan.candidate[0].exists():
                continue
            try:
                results[identity] = self._apply_public(identity, self.client.renew(plan), mode)
            except (AcmeError, CertificateError, GatewayApplyError) as exc:
                results[identity] = AcmeResult(exc.code)
            except (ValueError, OSError):
                results[identity] = AcmeResult("tls_state_error")
        return results
