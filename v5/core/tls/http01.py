"""Выделенный HTTP-вход: только зарегистрированные Host, ACME и редирект."""

from collections.abc import Iterable
from pathlib import Path
import re

from .acme import ACME_ROOT
from .identity import TLSIdentity


_SAFE_PATH = re.compile(r"(?:/[a-zA-Z0-9_-][a-zA-Z0-9_.-]*)+\Z", re.ASCII)


def safe_path(path: Path) -> str:
    if not _SAFE_PATH.fullmatch(str(path)):
        raise ValueError("Недопустимый путь в конфигурации nginx")
    return str(path)


def render_http01(identities: Iterable[TLSIdentity], *, webroot: Path = ACME_ROOT / "webroot",
                  ipv6: bool = True) -> str:
    """Сгенерировать фрагмент контекста http, без доступа к панели и VPN."""
    names = tuple(identities)
    if not 1 <= len(names) <= 32 or any(not isinstance(item, TLSIdentity) for item in names):
        raise ValueError("Не задан корректный реестр HTTP-имён")
    if len(set(names)) != len(names):
        raise ValueError("Повтор имени HTTP")
    web_path = safe_path(webroot)
    if type(ipv6) is not bool or (not ipv6 and any(item.is_ip and ":" in item.name for item in names)):
        raise ValueError("Для HTTP-01 по IPv6 требуется IPv6-слушатель")
    entries = "\n".join(f'    "{item.authority}{suffix}" "{item.authority}";'
                        for item in names for suffix in ("", ":80"))
    v6 = "    listen [::]:80 default_server ipv6only=on;\n" if ipv6 else ""
    return (
        "map_hash_bucket_size 1024;\n"
        "server_names_hash_bucket_size 512;\n"
        'map $http_host $kvn_public_authority {\n    default "";\n'
        f"{entries}\n}}\n"
        "server {\n"
        "    listen 80 default_server;\n"
        f"{v6}"
        "    server_name _;\n"
        "    access_log off;\n"
        '    if ($kvn_public_authority = "") { return 421; }\n'
        '    location ~ "^/\\.well-known/acme-challenge/[A-Za-z0-9_-]{1,128}$" {\n'
        f"        root {web_path};\n"
        f"        disable_symlinks on from={web_path};\n"
        "        default_type text/plain;\n"
        "        add_header Cache-Control no-store always;\n"
        "        limit_except GET { deny all; }\n"
        "        try_files $uri =404;\n"
        "    }\n"
        "    location /.well-known/acme-challenge/ { return 404; }\n"
        "    location / { return 308 https://$kvn_public_authority$request_uri; }\n"
        "}\n"
    )
