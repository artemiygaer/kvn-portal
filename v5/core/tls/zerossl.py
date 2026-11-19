"""Однократная привязка аккаунта ZeroSSL по SSH без передачи EAB веб-порталу."""

from getpass import GetPassWarning, getpass
import os
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory
import warnings

from v5.core.private_files import private_directory

from .acme import AcmeMode, acme_command, acme_contact, zerossl_ready
from .acme_service import AcmeError, CertbotClient
from .queue import QueueBusy, TLSQueue


def register(client: CertbotClient, kid: str, hmac_key: str, email: str) -> None:
    if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", kid, re.ASCII)
            or not re.fullmatch(r"[A-Za-z0-9_-]{16,256}={0,2}", hmac_key, re.ASCII)):
        raise ValueError("Некорректный формат EAB")
    contact = acme_contact(email)
    client._require_version()
    directory = client.root / AcmeMode.ZEROSSL.value
    directory.mkdir(mode=0o700, exist_ok=True)
    private_directory(directory)
    # EAB не попадает в argv. Диагностические логи регистрации также только временные.
    with TemporaryDirectory(prefix="portal-zerossl-", dir="/run") as private:
        config = Path(private) / "certbot.ini"
        with os.fdopen(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="ascii") as stream:
            stream.write(f"eab-kid = {kid}\neab-hmac-key = {hmac_key}\n")
        argv = acme_command(AcmeMode.ZEROSSL, "register", client.root, client.executable)
        argv[argv.index("--logs-dir") + 1] = private
        client._call(tuple(argv + ["--config", str(config), "--agree-tos", *contact]), 180)
    if not zerossl_ready(client.root):
        raise AcmeError("zerossl_account_missing")


def main() -> int:
    if os.geteuid() != 0 or not sys.stdin.isatty():
        print("Запустите команду от root в интерактивной SSH-сессии.", file=sys.stderr)
        return 1
    if zerossl_ready():
        print("Аккаунт ZeroSSL уже настроен.")
        return 0
    try:
        print("Условия ZeroSSL: https://zerossl.com/legal/terms")
        if input("Вы принимаете условия? [да/нет]: ").strip().lower() not in ("да", "yes"):
            return 1
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            kid = getpass("EAB KID: ").strip()
            key = getpass("EAB HMAC key: ").strip()
        email = input("Email ACME (можно оставить пустым): ").strip()
        queue = TLSQueue()
        with queue.exclusive():
            if queue.pending.exists():
                raise QueueBusy
            if not zerossl_ready():
                register(CertbotClient(), kid, key, email)
    except QueueBusy:
        print("Служба TLS занята. Повторите после завершения текущей задачи.", file=sys.stderr)
    except AcmeError as exc:
        print(f"Не удалось привязать ZeroSSL ({exc.code}). Проверьте EAB и доступ к ZeroSSL.", file=sys.stderr)
    except (OSError, ValueError, GetPassWarning, EOFError, KeyboardInterrupt):
        print("Привязка не выполнена. Проверьте формат данных и наличие SSH-терминала.", file=sys.stderr)
    else:
        print("Аккаунт ZeroSSL привязан. Теперь его можно выбрать для DNS-имени в портале.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
