"""Чистые render/export операции ocserv/OpenConnect."""

import ipaddress

def validate_config(config: dict) -> dict:
    network = ipaddress.ip_network(config.get("network", "10.77.77.0/24"), strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Сеть ocserv должна быть IPv4 CIDR.")
    if bool(config.get("dtls_enabled", True)) and int(config.get("udp_port", 4443)) == 443:
        raise ValueError("UDP 443 занят Hysteria2.")
    return config

def render_server(config: dict) -> str:
    validate_config(config)
    network = ipaddress.ip_network(config.get("network", "10.77.77.0/24"), strict=False)
    lines = ["# Конфиг ocserv/OpenConnect. Генерируется из users.json — не править вручную.", 'auth = "plain[passwd=/run/ocserv/ocpasswd]"', "", "tcp-port = 443"]
    if config.get("dtls_enabled", True):
        lines.extend(["# DTLS/UDP data-channel для скорости. 443/udp занят Hysteria2, поэтому используем отдельный порт.", f"udp-port = {config.get('udp_port', 4443)}", ""])
    else:
        lines.extend(["# DTLS/UDP отключён: клиенты используют TCP fallback.", "# udp-port не задаётся.", ""])
    lines.extend([
        "run-as-user = nobody", "run-as-group = nogroup", "device = vpns", "socket-file = /run/ocserv/ocserv.sock", "pid-file = /run/ocserv/ocserv.pid", "",
        "server-cert = /etc/ocserv/certs/server.crt", "server-key = /etc/ocserv/certs/server.key", "",
        f"max-clients = {config.get('max_clients', 64)}", f"max-same-clients = {config.get('max_same_clients', 3)}", "keepalive = 32400", "dpd = 90", "mobile-dpd = 1800", "switch-to-tcp-timeout = 25", "try-mtu-discovery = true", f"mtu = {config.get('mtu', 1400)}", "cisco-client-compat = true", "deny-roaming = false", "isolate-workers = false", 'tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"', "",
        f"ipv4-network = {network.network_address}", f"ipv4-netmask = {network.netmask}", "# Full-tunnel для ocserv: route-строки не задаются.", "tunnel-all-dns = true", "ping-leases = false",
    ])
    lines.extend(f"dns = {dns}" for dns in config.get("dns", ["1.1.1.1", "8.8.8.8"]))
    lines.append("")
    return "\n".join(lines)

def render_users(users: list[tuple[str, str]]) -> str:
    lines = ["# username:password для ocserv entrypoint. Генерируется из users.json — не править вручную."]
    lines.extend(f"{name}:{password}" for name, password in users)
    return "\n".join(lines) + "\n"

def certificate_domains(config: dict) -> list[str]:
    if not config.get("sni_enabled"):
        return []
    domains = []
    for domain in [config.get("sni", ""), *config.get("front_snis", [])]:
        if domain and domain not in domains:
            domains.append(domain)
    return domains

__all__ = ["certificate_domains", "render_server", "render_users", "validate_config"]
