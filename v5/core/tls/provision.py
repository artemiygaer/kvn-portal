"""Отдельная установка Certbot только из закреплённых wheels."""

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import signal
import stat
import subprocess
from tempfile import mkdtemp

from .acme import CERTBOT, require_certbot_version


LOCKFILE = Path(__file__).with_name("requirements-acme.lock")
PYPI = "https://pypi.org/simple"


class ProvisionError(ValueError):
    pass


def _owned_directory(path: Path) -> None:
    attrs = path.lstat()
    if not stat.S_ISDIR(attrs.st_mode) or attrs.st_uid != os.geteuid() or attrs.st_mode & 0o022:
        raise ProvisionError("Каталог Certbot должен принадлежать root и быть закрыт для записи извне")


def _run(command, timeout: float) -> bytes:
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8", "PIP_CONFIG_FILE": os.devnull, "HOME": "/root",
           "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True, env=env) as process:
            try:
                stdout, _ = process.communicate(timeout=timeout)
            except BaseException:
                # venv может запустить ensurepip, который иначе переживёт таймаут родителя.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, command)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError("Не удалось собрать окружение Certbot; проверьте python3-venv, доступ к PyPI или набор wheels") from exc
    return stdout


def _check_version(executable: Path) -> None:
    try:
        require_certbot_version(_run((str(executable), "--version"), 40).decode("ascii"))
    except ValueError as exc:
        raise ProvisionError("Установленный Certbot не прошёл проверку версии") from exc


def _existing(active: Path, generations: Path) -> Path | None:
    if not active.is_symlink():
        if active.exists():
            raise ProvisionError("Существующее окружение Certbot не управляется KVN; оно не изменено")
        return None
    target = active.resolve(strict=False)
    if active.lstat().st_uid != os.geteuid() or target.parent != generations:
        raise ProvisionError("Ссылка Certbot не указывает на управляемое окружение KVN")
    if not target.exists():
        return None
    _owned_directory(target)
    return target


def install_runtime(*, root: Path = CERTBOT.parents[2], lockfile: Path = LOCKFILE,
                    wheels: Path | None = None) -> Path:
    """Проверка хешей и pip check до переключения стабильной ссылки."""
    _owned_directory(root)
    if wheels is not None:
        wheels = wheels.resolve(strict=True)
        if not wheels.is_dir():
            raise ProvisionError("Укажите каталог с wheels Certbot")
    lockfile = lockfile.resolve(strict=True)
    with lockfile.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    active, generations = root / "kvn-v5-acme", root / "kvn-v5-acme-releases"
    generations.mkdir(mode=0o700, exist_ok=True)
    _owned_directory(generations)
    fd = os.open(generations / ".install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProvisionError("Установка Certbot уже выполняется") from exc
        previous = _existing(active, generations)
        if previous is not None and (previous / ".kvn-lock.sha256").is_file():
            if (previous / ".kvn-lock.sha256").read_text(encoding="ascii").strip() == digest:
                _check_version(previous / "bin/certbot")
                return active / "bin/certbot"
        generation = Path(mkdtemp(prefix=digest[:12] + "-", dir=generations))
        link = root / (".kvn-v5-acme-" + secrets.token_hex(8))
        try:
            _run(("/usr/bin/python3", "-m", "venv", str(generation)), 300)
            python = str(generation / "bin/python3")
            pip = (python, "-m", "pip", "--isolated", "--disable-pip-version-check")
            transport = ("--index-url", PYPI) if wheels is None else ("--no-index", "--find-links", str(wheels))
            _run((*pip, "install", "--no-cache-dir", "--no-compile", "--only-binary", ":all:", "--require-hashes", *transport,
                  "--requirement", str(lockfile)), 360)
            _run((*pip, "check"), 60)
            _check_version(generation / "bin/certbot")
            (generation / ".kvn-lock.sha256").write_text(digest + "\n", encoding="ascii")
            link.symlink_to(generation.relative_to(root))
            os.replace(link, active)
        except BaseException as exc:
            # Удаляется только новый каталог из mkdtemp, прежнее окружение и активная ссылка остаются.
            try:
                shutil.rmtree(generation)
            except OSError:
                if isinstance(exc, Exception):
                    raise ProvisionError("Certbot не установлен; не удалось очистить новый неактивный каталог") from exc
            raise
        finally:
            link.unlink(missing_ok=True)
    return active / "bin/certbot"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheels", type=Path, help="Каталог для установки без PyPI")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, "Установка Certbot требует root\n")
    try:
        install_runtime(wheels=args.wheels)
    except ProvisionError as exc:
        parser.exit(1, f"{exc}\n")
    except (OSError, ValueError):
        parser.exit(1, "Не удалось проверить локальные файлы Certbot\n")
    print("Изолированный Certbot готов. Откройте «Сертификаты HTTPS» в панели.")


if __name__ == "__main__":
    main()
