"""Чистые render/export/verify операции стандартного WireGuard."""

def validate_config(config: dict, *, amneziawg: dict | None = None) -> dict:
    port = int(config.get("port", 51821))
    interface = str(config.get("interface", "wg0"))
    awg = amneziawg or {}
    if port == int(awg.get("port", 51820)):
        raise ValueError("WireGuard и AmneziaWG должны использовать разные порты.")
    if interface == str(awg.get("interface", "awg0")):
        raise ValueError("WireGuard и AmneziaWG должны использовать разные интерфейсы.")
    return config

def render_client(config: dict, user_config: dict, endpoint_host: str) -> str:
    dns = config.get("dns", ["1.1.1.1", "8.8.8.8"])
    dns_line = dns if isinstance(dns, str) else ", ".join(str(item) for item in dns)
    return "\n".join([
        "# Стандартный WireGuard-профиль для отдельного сервиса KVN WireGuard.", "[Interface]",
        f"PrivateKey = {user_config.get('private_key', '')}", f"Address = {user_config.get('address', '')}",
        f"DNS = {dns_line}", f"MTU = {int(config.get('mtu', 1420))}", "", "[Peer]",
        f"PublicKey = {config.get('public_key', '')}", f"PresharedKey = {user_config.get('preshared_key', '')}",
        f"Endpoint = {endpoint_host}:{int(config.get('port', 51821))}", "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25", "",
    ])

def render_server(config: dict, users: list[dict]) -> str:
    network, iface, port = config.get("network", "10.88.88.0/24"), config.get("interface", "wg0"), int(config.get("port", 51821))
    lines = [
        "# Конфиг WireGuard. Генерируется из users.json — не править вручную.", "[Interface]",
        f"PrivateKey = {config['private_key']}", f"Address = {config.get('server_address', '10.88.88.1/24')}",
        f"ListenPort = {port}", f"MTU = {int(config.get('mtu', 1420))}",
        f"PostUp = iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT; iptables -I FORWARD 1 -i {iface} -j ACCEPT; iptables -I FORWARD 1 -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -s {network} -o eth0 -j MASQUERADE",
        f"PostDown = iptables -D INPUT -p udp --dport {port} -j ACCEPT; iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -s {network} -o eth0 -j MASQUERADE", "",
    ]
    for user in users:
        peer = user.get("wireguard", {})
        if peer.get("public_key") and peer.get("address"):
            lines.extend(["[Peer]", f"# {user['name']}", f"PublicKey = {peer['public_key']}", f"PresharedKey = {peer.get('preshared_key', '')}", f"AllowedIPs = {peer['address']}", ""])
    return "\n".join(lines)

def expected_peers(users: list[dict]) -> dict[str, str]:
    return {peer["public_key"]: peer["address"] for user in users if (peer := user.get("wireguard", {})).get("public_key") and peer.get("address")}

def parse_runtime_dump(text: str) -> dict[str, str]:
    from ..amneziawg import parse_runtime_dump as parse
    return parse(text)

__all__ = ["expected_peers", "parse_runtime_dump", "render_client", "render_server", "validate_config"]
