"""Общие имена и пары TLS, изолированные публичный и административный входы."""

from collections.abc import Iterable
import hashlib
from pathlib import Path

from v5.core.network.plan import NetworkPlan, SITE_BACKEND_PORT
from v5.core.network.stream import render_stream
from v5.core.migration import MAX_MIGRATION_FORM
from v5.core.maintenance.core_bundle import MAX_BUNDLE
from v5.core.packages.manifest import MAX_PACKAGE
from v5.core.site.document import MAX_SITE_FORM, SITE_CSP

from .acme import ACME_ROOT
from .access import PortalAccess
from .http01 import render_http01, safe_path
from .identity import TLSIdentity
from .transaction import StoredPair


TEMPLATE = Path(__file__).with_name("nginx.conf")
SITE_ROOT = ACME_ROOT.parent / "site"
_PORTS = (443, 8443)


def admin_hosts(identities: Iterable[TLSIdentity], access: PortalAccess = PortalAccess()) -> list[str]:
    return list(dict.fromkeys(("127.0.0.1:8443", "localhost:8443", *(f"{item.authority}:{access.port}" for item in identities))))


def _listen(port: int, family: int, *, default: bool, loopback: bool = False) -> str:
    if loopback:
        target = f"[::1]:{SITE_BACKEND_PORT}" if family == 6 else f"127.0.0.1:{SITE_BACKEND_PORT}"
    else:
        target = f"[::]:{port}" if family == 6 else str(port)
    options = " default_server" if default else ""
    if family == 6 and default:
        options += " ipv6only=on"
    if family == 4 and port == 8443 and default:
        # Публичный wildcard добавляется reload, не закрывая точный loopback bootstrap.
        options += " reuseport"
    return f"    listen {target} ssl{options};\n"


def _http_routes(pairs: tuple[StoredPair, ...], port: int) -> str:
    entries = []
    for item in pairs:
        identity = item.metadata.identity
        host = identity.authority
        suffixes = ("", ":443") if port == 443 else (f":{port}",)
        sni = "" if identity.is_ip else identity.name
        entries.extend(f'    "{sni}|{host}{suffix}" "{identity.slot}";' for suffix in suffixes)
    return (f'map "$ssl_server_name|$http_host" $kvn_tls_{port} {{\n    default "";\n'
            + "\n".join(entries) + "\n}\n")


def _fallback(port: int, family: int, *, loopback: bool) -> str:
    return ("server {\n" + _listen(port, family, default=True, loopback=loopback)
            + "    ssl_reject_handshake on;\n}\n")


def _portal_proxy(host: str, prefix: str = "") -> str:
    routes = (f"    proxy_set_header Host {host};\n"
            "    proxy_set_header X-KVN-Client-IP $remote_addr;\n"
            "    proxy_set_header X-Forwarded-Proto https;\n"
            '    proxy_set_header X-Forwarded-For "";\n'
            '    proxy_set_header X-Forwarded-Host "";\n'
            "    proxy_connect_timeout 3s;\n"
            "    proxy_read_timeout 10s;\n"
            '    location = /settings/tls/import {\n'
            '        client_max_body_size 176k;\n'
            '        client_body_buffer_size 176k;\n'
            '        proxy_http_version 1.1;\n'
            '        proxy_request_buffering off;\n'
            '        access_log off;\n'
            '        proxy_pass http://portal;\n'
            '    }\n'
            '    location ~ "^/settings/site/(preview|publish)$" {\n'
            f"        client_max_body_size {MAX_SITE_FORM // 1024}k;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /maintenance/console/ws {\n"
            "        access_log off;\n"
            "        error_log /dev/null crit;\n"
            "        proxy_http_version 1.1;\n"
            f"        proxy_set_header Host {host};\n"
            "        proxy_set_header Origin $http_origin;\n"
            "        proxy_set_header Upgrade $http_upgrade;\n"
            '        proxy_set_header Connection "upgrade";\n'
            "        proxy_buffering off;\n"
            "        proxy_read_timeout 30s;\n"
            "        proxy_intercept_errors on;\n"
            "        error_page 502 503 504 =404 @console_unavailable;\n"
            "        proxy_pass http://unix:/run/kvn-v5-console-web.sock;\n"
            "    }\n"
            "    location @console_unavailable { return 404; }\n"
            '    location = /modules/upload {\n'
            f"        client_max_body_size {MAX_PACKAGE // 1024 + 128}k;\n"
            "        proxy_http_version 1.1;\n"
            "        proxy_request_buffering off;\n"
            "        proxy_read_timeout 350s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            '    location = /modules {\n'
            "        proxy_read_timeout 75s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            # Действия модулей могут добавляться при обновлении без замены живого nginx.conf.
            '    location ~ "^/modules/[a-z_]+$" {\n'
            "        proxy_read_timeout 350s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /observability/history {\n"
            "        proxy_read_timeout 45s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /maintenance/update/upload {\n"
            f"        client_max_body_size {(MAX_BUNDLE + 128 * 1024) // 1024}k;\n"
            "        proxy_request_buffering off;\n"
            "        proxy_read_timeout 240s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /maintenance/update {\n"
            "        proxy_read_timeout 25s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /maintenance/update/github {\n"
            "        proxy_read_timeout 240s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /maintenance/update/start {\n"
            "        proxy_read_timeout 45s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location = /maintenance/update/reconcile {\n"
            "        proxy_read_timeout 20s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            '    location ~ "^/users/[A-Za-z0-9_-]+/(grant|retry)$" {\n'
            "        proxy_read_timeout 350s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            '    location ~ "^/users/migration(?:/|$)" {\n'
            f"        client_max_body_size {MAX_MIGRATION_FORM // 1024}k;\n"
            "        access_log off;\n"
            "        proxy_read_timeout 140s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            # Prefix с хвостовым / и proxy_pass автоматически перехватывает /users.
            '    location ~ "^/users/" {\n'
            "        proxy_read_timeout 30s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location ^~ /sub/ {\n"
            "        access_log off;\n"
            "        error_log /dev/null crit;\n"
            "        limit_req zone=kvn_sub_ip burst=5 nodelay;\n"
            "        limit_req zone=kvn_sub_global burst=10 nodelay;\n"
            "        limit_req_status 429;\n"
            "        proxy_read_timeout 30s;\n"
            "        proxy_pass http://portal;\n"
            "    }\n"
            "    location / { proxy_pass http://portal; }\n")
    if not prefix:
        return routes + '    proxy_set_header X-Forwarded-Prefix "";\n'
    # Сохраняем специфические ограничения upload и WebSocket при изменении пути.
    routes = routes.replace('location = /', f'location = {prefix}/')
    routes = routes.replace('location ^~ /', f'location ^~ {prefix}/')
    routes = routes.replace('location ~ "^/', f'location ~ "^{prefix}/')
    routes = routes.replace('location / {', f'location {prefix}/ {{')
    routes = routes.replace('proxy_pass http://', f'rewrite ^{prefix}(/.*)$ $1 break; proxy_pass http://')
    return (routes + f'    proxy_set_header X-Forwarded-Prefix {prefix};\n'
            + f'    location = {prefix} {{ return 308 {prefix}/; }}\n'
            + '    location / { return 404; }\n')


def _vhost(pair: StoredPair, port: int, *, ipv6: bool, site_root: str, loopback: bool, access: PortalAccess) -> str:
    identity = pair.metadata.identity
    if identity.is_ip:
        families = (6,) if ":" in identity.name else (4,)
    else:
        families = (4, 6) if ipv6 else (4,)
    lines = ["server {\n", *(_listen(port, family, default=identity.is_ip, loopback=loopback) for family in families),
             f"    server_name {identity.authority};\n",
             f"    ssl_certificate {safe_path(pair.chain)};\n",
             f"    ssl_certificate_key {safe_path(pair.key)};\n",
             f'    if ($kvn_tls_{port} != "{identity.slot}") {{ return 421; }}\n']
    if port == 443:
        lines.extend((f"    root {site_root};\n", f"    disable_symlinks on from={site_root};\n",
                      "    charset utf-8;\n", "    default_type text/html;\n", "    access_log off;\n",
                      f'    add_header Content-Security-Policy "{SITE_CSP}" always;\n',
                      "    add_header X-Content-Type-Options nosniff always;\n",
                      "    add_header Referrer-Policy no-referrer always;\n",
                      "    location = / { try_files /index.html =404; }\n",
                      "    location = /index.html { try_files /index.html =404; }\n",
                      "    location / { return 404; }\n"))
    else:
        lines.append(_portal_proxy(f"{identity.authority}:{port}", access.prefix))
    return "".join((*lines, "}\n"))


def render_gateway(identities: Iterable[TLSIdentity], *, ipv6: bool, pairs: Iterable[StoredPair] = (),
                   webroot: Path = ACME_ROOT / "webroot", site_root: Path = SITE_ROOT,
                   network: NetworkPlan | None = None, access: PortalAccess = PortalAccess()) -> str:
    names = tuple(identities)
    active = tuple(pairs)
    active_names = [pair.metadata.identity for pair in active]
    if len(set(active_names)) != len(active_names) or not set(active_names).issubset(names):
        raise ValueError("Сертификат не относится к зарегистрированному имени или указан дважды")
    ip_families = [6 if ":" in name.name else 4 for name in active_names if name.is_ip]
    if len(set(ip_families)) != len(ip_families):
        raise ValueError("Для прямого входа поддерживается один IP каждой семьи")
    stream = render_stream(network, ipv6=ipv6 or 6 in ip_families) if network else ""
    if stream and not active:
        raise ValueError("Перед публикацией VPN на TCP/443 настройте сертификат публичного сайта")
    if network and any(item.route.self_steal and TLSIdentity(item.route.sni, False) not in active_names
                       for item in network.routes):
        raise ValueError("Для self-steal нужен действующий сертификат этого имени")
    http01 = render_http01(names, webroot=webroot, site_root=site_root, ipv6=ipv6)
    www = safe_path(site_root)
    tls = []
    if active:
        for port in (443, access.port):
            loopback = bool(stream) and port == 443
            tls.append(_http_routes(active, port))
            for family in (4, 6) if (ipv6 or loopback and 6 in ip_families) else (4,):
                if family not in ip_families:
                    tls.append(_fallback(port, family, loopback=loopback))
            tls.extend(_vhost(pair, port, ipv6=ipv6, site_root=www, loopback=loopback, access=access) for pair in active)
    source = TEMPLATE.read_text(encoding="utf-8")
    if source.count("@STREAM@") != 1:
        raise ValueError("Некорректный шаблон nginx")
    source = source.replace("@STREAM@", stream.rstrip("\n"))
    for marker, fragment in (("@HTTP01@", http01), ("@TLS@", "\n".join(tls)),
                             ("@BOOTSTRAP_PROXY@", _portal_proxy("$http_host"))):
        if source.count(marker) != 1:
            raise ValueError("Некорректный шаблон nginx")
        source = source.replace(marker, "\n".join("    " + line for line in fragment.splitlines()))
    if source.count("@REVISION@") != 1:
        raise ValueError("Некорректный шаблон nginx")
    revision = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return f"# kvn-v5-gateway-revision {revision}\n" + source.replace("@REVISION@", revision)
