"""Фиксированные команды Certbot и изоляция staging от публичного выпуска."""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
import re

from .identity import TLSIdentity


ACME_ROOT = Path("/var/lib/kvn-v5/acme")
CERTBOT = Path("/usr/local/lib/kvn-v5-acme/bin/certbot")
MIN_CERTBOT = (5, 4, 0)
_VERSION = re.compile(r"certbot (\d+)\.(\d+)\.(\d+)\Z", re.ASCII)
_EMAIL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+\-]{0,63}@[A-Za-z0-9][A-Za-z0-9.\-]{0,251}", re.ASCII)


class AcmeMode(StrEnum):
    PUBLIC = "public"
    STAGING = "staging"

    @property
    def endpoint(self) -> str:
        if self is AcmeMode.STAGING:
            return "https://acme-staging-v02.api.letsencrypt.org/directory"
        return "https://acme-v02.api.letsencrypt.org/directory"


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
        environment = self.root / self.mode.value
        return [str(self.executable), action, "--non-interactive", "--no-directory-hooks",
                "--config-dir", str(self.configuration), "--work-dir", str(environment / "work"),
                "--logs-dir", str(environment / "logs"), "--server", self.mode.endpoint,
                "--cert-name", self.identity.slot]

    def issue(self, email: str) -> tuple[str, ...]:
        if not isinstance(email, str) or (email and not _EMAIL.fullmatch(email)):
            raise ValueError("Укажите корректный контактный email ACME")
        contact = ["--email", email] if email else ["--register-unsafely-without-email"]
        argv = self._command("certonly") + ["--agree-tos", *contact, "--webroot",
                                          "--webroot-path", str(self.webroot), "--keep-until-expiring"]
        if self.identity.is_ip:
            argv.extend(("--preferred-profile", "shortlived", "--ip-address", self.identity.name))
        else:
            argv.extend(("--domains", self.identity.name))
        return tuple(argv)

    def renew(self) -> tuple[str, ...]:
        return tuple(self._command("renew") + ["--no-random-sleep-on-renew"])
