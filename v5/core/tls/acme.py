"""Фиксированные команды Certbot и изоляция staging от публичного выпуска."""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
import re
from urllib.parse import urlsplit

from .identity import TLSIdentity


ACME_ROOT = Path("/var/lib/kvn-v5/acme")
CERTBOT = Path("/usr/local/lib/kvn-v5-acme/bin/certbot")
MIN_CERTBOT = (5, 4, 0)
_VERSION = re.compile(r"certbot (\d+)\.(\d+)\.(\d+)\Z", re.ASCII)
_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,63}@[A-Za-z0-9][A-Za-z0-9.\-]{0,251}", re.ASCII)


class AcmeMode(StrEnum):
    PUBLIC = "public"
    STAGING = "staging"
    ZEROSSL = "zerossl"

    @property
    def endpoint(self) -> str:
        if self is AcmeMode.ZEROSSL:
            return "https://acme.zerossl.com/v2/DV90"
        if self is AcmeMode.STAGING:
            return "https://acme-staging-v02.api.letsencrypt.org/directory"
        return "https://acme-v02.api.letsencrypt.org/directory"


def acme_command(mode: AcmeMode, action: str, root: Path, executable: Path) -> list[str]:
    environment = root / mode.value
    return [str(executable), action, "--non-interactive", "--no-directory-hooks",
            "--config-dir", str(environment / "config"), "--work-dir", str(environment / "work"),
            "--logs-dir", str(environment / "logs"), "--server", mode.endpoint]


def acme_contact(email: str) -> list[str]:
    if not isinstance(email, str) or (email and not _EMAIL.fullmatch(email)):
        raise ValueError("Укажите корректный контактный email ACME")
    return ["--email", email] if email else ["--register-unsafely-without-email"]


def zerossl_ready(root: Path = ACME_ROOT) -> bool:
    url = urlsplit(AcmeMode.ZEROSSL.endpoint)
    directory = root / AcmeMode.ZEROSSL.value / "config" / "accounts" / (url.netloc + url.path)
    try:
        # Используем отдельную область Certbot только для одной локальной учётной записи.
        accounts = [p for p in directory.iterdir() if re.fullmatch(r"[0-9a-f]{32}", p.name)]
        return len(accounts) == 1 and all((accounts[0] / name).is_file() and not (accounts[0] / name).is_symlink()
                                           for name in ("private_key.json", "regr.json", "meta.json"))
    except OSError:
        return False


def require_certbot_version(output: str) -> None:
    matched = _VERSION.fullmatch(output.strip())
    if not matched or tuple(map(int, matched.groups())) < MIN_CERTBOT:
        raise ValueError("Для DNS и IP через HTTP-01 нужен Certbot версии 5.4.0 или новее")


@dataclass(frozen=True, slots=True)
class AcmePlan:
    identity: TLSIdentity
    mode: AcmeMode
    root: Path = ACME_ROOT
    executable: Path = CERTBOT

    def __post_init__(self) -> None:
        if not isinstance(self.mode, AcmeMode) or not self.root.is_absolute() or not self.executable.is_absolute():
            raise ValueError("Недопустимое окружение ACME")
        if self.identity.is_ip and not ip_address(self.identity.name).is_global:
            raise ValueError("Для выпуска сертификата требуется публичный IP")
        if self.identity.is_ip and self.mode is AcmeMode.ZEROSSL:
            raise ValueError("Для IP используется только Let’s Encrypt")

    @property
    def webroot(self) -> Path:
        return self.root / "webroot"

    @property
    def configuration(self) -> Path:
        return self.root / self.mode.value / "config"

    @property
    def candidate(self) -> tuple[Path, Path]:
        lineage = self.configuration / "live" / self.identity.slot
        return lineage / "fullchain.pem", lineage / "privkey.pem"

    def _command(self, action: str) -> list[str]:
        argv = acme_command(self.mode, action, self.root, self.executable) + ["--cert-name", self.identity.slot]
        if self.mode is AcmeMode.ZEROSSL:
            argv += ["--config", "/dev/null"]
        return argv

    def issue(self, email: str) -> tuple[str, ...]:
        contact = acme_contact(email)
        if self.mode is AcmeMode.ZEROSSL:
            contact = []  # Аккаунт уже связан через EAB отдельной командой.
        argv = self._command("certonly") + ["--agree-tos", *contact, "--webroot",
                                          "--webroot-path", str(self.webroot), "--keep-until-expiring"]
        if self.identity.is_ip:
            argv.extend(("--preferred-profile", "shortlived", "--ip-address", self.identity.name))
        else:
            argv.extend(("--domains", self.identity.name))
        return tuple(argv)

    def renew(self) -> tuple[str, ...]:
        return tuple(self._command("renew") + ["--no-random-sleep-on-renew"])
