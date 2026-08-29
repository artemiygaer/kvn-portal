"""Чистый renderer Hysteria 2."""

import json
from urllib.parse import quote

def render_server(*, portal_secret: str = "", users: list[tuple[str, str]] | None = None) -> str:
    lines = ["listen: :443", "", "tls:", "  cert: /etc/hysteria/certs/server.crt", "  key: /etc/hysteria/certs/server.key", "  sniGuard: disable", ""]
    if portal_secret:
        token = quote(portal_secret, safe="")
        lines.extend(["auth:", "  type: http", "  http:", f"    url: http://portal:8080/internal/hysteria/auth?token={token}", "    insecure: true", "", "trafficStats:", "  listen: 127.0.0.1:9090", f"  secret: {json.dumps(portal_secret)}"])
    else:
        lines.extend(["auth:", "  type: userpass", "  userpass:"])
        lines.extend(f"    {name}: {json.dumps(password)}" for name, password in (users or []))
    lines.extend(["", "masquerade:", "  type: proxy", "  proxy:", "    url: https://www.apple.com/", "    rewriteHost: true", "", "quic:", "  initStreamReceiveWindow: 16777216", "  maxStreamReceiveWindow: 16777216", "  initConnReceiveWindow: 67108864", "  maxConnReceiveWindow: 67108864", "  maxIdleTimeout: 60s", ""])
    return "\n".join(lines)

__all__ = ["render_server"]
