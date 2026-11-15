"""X25519 и адреса клиентов без вывода ключей и без запуска wg/awg."""

import base64
from ipaddress import IPv4Interface
import os
import subprocess

from .config import Peer, key

_PKCS8 = bytes.fromhex("302e020100300506032b656e04220420")
_SPKI = bytes.fromhex("302a300506032b656e032100")


def public_key(private: str) -> str:
    secret = base64.b64decode(key(private), validate=True)
    try:
        result = subprocess.run(["/usr/bin/openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                                input=_PKCS8 + secret, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=10, check=True, env={"LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
    except (OSError, subprocess.SubprocessError):
        raise ValueError("Не удалось проверить ключ туннеля") from None
    if not result.stdout.startswith(_SPKI) or len(result.stdout) != len(_SPKI) + 32:
        raise ValueError("Неожиданный формат ключа туннеля")
    return key(base64.b64encode(result.stdout[len(_SPKI):]).decode("ascii"))


def peer(credential: dict) -> Peer:
    if public_key(credential["private_key"]) != credential["public_key"]:
        raise ValueError("Ключи клиента туннеля не соответствуют друг другу")
    return Peer(credential["public_key"], str(IPv4Interface(credential["address"]).ip), credential["preshared_key"])


def allocate(settings, occupied: tuple[dict, ...]) -> dict:
    taken = {item.address for item in settings.peers}
    taken.update(str(IPv4Interface(item["address"]).ip) for item in occupied)
    taken.add(str(IPv4Interface(settings.address).ip))
    address = next((str(item) for item in settings.subnet.hosts() if str(item) not in taken), None)
    if address is None:
        raise ValueError("В подсети туннеля не осталось адресов")
    private = base64.b64encode(os.urandom(32)).decode("ascii")
    return {"private_key": private, "public_key": public_key(private), "address": address,
            "preshared_key": base64.b64encode(os.urandom(32)).decode("ascii")}
