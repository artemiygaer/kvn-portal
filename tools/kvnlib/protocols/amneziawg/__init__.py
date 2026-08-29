"""Чистые render/export/verify операции AmneziaWG legacy и 3.1."""

from __future__ import annotations

import hashlib

PROFILES = ("legacy", "3.1")
V3_CONFIG_KEYS = {
    "content_padding_addition": "ContentPaddingAddition",
    "rekey_after_time": "RekeyAfterTime",
    "rekey_timeout": "RekeyTimeout",
    "reject_after_time": "RejectAfterTime",
    "keepalive_timeout": "KeepaliveTimeout",
    "max_handshake_attempts": "MaxHandshakeAttempts",
}

def validate_config(config: dict) -> dict:
    """Проверяет критичные границы профиля без раскрытия HeaderProtectionKey."""
    profile = str(config.get("protocol_version", "legacy"))
    if profile not in PROFILES:
        raise ValueError("Профиль AmneziaWG должен быть legacy или 3.1.")
    port = int(config.get("port", 51820))
    if not 1 <= port <= 65535:
        raise ValueError("Порт AmneziaWG должен быть в диапазоне 1-65535.")
    if profile == "3.1" and not config.get("v3", {}).get("header_protection_key"):
        raise ValueError("Для AWG 3.1 требуется HeaderProtectionKey.")
    return config

def obfuscation_lines(config: dict) -> list[str]:
    obfs = config.get("obfuscation", {})
    padding = ("S1", "S2", "S3", "S4") if config.get("protocol_version") == "3.1" else ("S1", "S2")
    lines = []
    for key in ("Jc", "Jmin", "Jmax", *padding, "H1", "H2", "H3", "H4"):
        if obfs.get(key) is not None:
            lines.append(f"{key} = {obfs[key]}")
    for key in ("I1", "I2", "I3", "I4", "I5"):
        if obfs.get(key):
            lines.append(f"{key} = {obfs[key]}")
    return lines

def v3_lines(config: dict) -> list[str]:
    if config.get("protocol_version") != "3.1":
        return []
    v3 = config["v3"]
    lines = [f"HeaderProtectionKey = {v3['header_protection_key']}"]
    lines.extend(f"{wire_name} = {v3[state_name]}" for state_name, wire_name in V3_CONFIG_KEYS.items())
    return lines

def render_client(
    config: dict,
    user_config: dict,
    endpoint_host: str,
    allowed_ips: list[str],
    *,
    obfuscation: list[str] | None = None,
    v3: list[str] | None = None,
) -> str:
    """Строит импортируемый клиентский профиль без доступа к state или I/O."""
    validate_config(config)
    dns = config.get("dns", ["1.1.1.1", "8.8.8.8"])
    dns_line = dns if isinstance(dns, str) else ", ".join(str(item) for item in dns)
    lines = [
        "[Interface]",
        f"PrivateKey = {user_config.get('private_key', '')}",
        f"Address = {user_config.get('address', '')}",
        f"DNS = {dns_line}",
        f"MTU = {int(config.get('mtu', 1280))}",
        *(obfuscation_lines(config) if obfuscation is None else obfuscation),
        *(v3_lines(config) if v3 is None else v3),
        "",
        "[Peer]",
        f"PublicKey = {config.get('public_key', '')}",
        f"PresharedKey = {user_config.get('preshared_key', '')}",
        f"Endpoint = {endpoint_host}:{int(config.get('port', 51820))}",
        f"AllowedIPs = {', '.join(allowed_ips)}",
        "PersistentKeepalive = 25",
        "",
    ]
    return "\n".join(lines)

def render_server(config: dict, users: list[dict]) -> str:
    """Строит host-конфиг; запись и права остаются runtime-adapter."""
    validate_config(config)
    network = config.get("network", "10.66.66.0/24")
    iface = config.get("interface", "awg0")
    port = int(config.get("port", 51820))
    lines = [
        "# Конфиг AmneziaWG. Генерируется из users.json — не править вручную.", "[Interface]",
        f"PrivateKey = {config['private_key']}", f"Address = {config.get('server_address', '10.66.66.1/24')}",
        f"ListenPort = {port}", f"MTU = {int(config.get('mtu', 1280))}",
        *obfuscation_lines(config), *v3_lines(config),
        f"PostUp = iptables -I INPUT 1 -p udp --dport {port} -j ACCEPT; iptables -I FORWARD 1 -i {iface} -j ACCEPT; iptables -I FORWARD 1 -o {iface} -j ACCEPT; iptables -t nat -A POSTROUTING -s {network} -o eth0 -j MASQUERADE",
        f"PostDown = iptables -D INPUT -p udp --dport {port} -j ACCEPT; iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT; iptables -t nat -D POSTROUTING -s {network} -o eth0 -j MASQUERADE", "",
    ]
    for user in users:
        peer = user.get("amneziawg", {})
        if peer.get("public_key") and peer.get("address"):
            lines.extend(["[Peer]", f"# {user['name']}", f"PublicKey = {peer['public_key']}", f"PresharedKey = {peer.get('preshared_key', '')}", f"AllowedIPs = {peer['address']}", ""])
    return "\n".join(lines)

def expected_peers(users: list[dict]) -> dict[str, str]:
    return {peer["public_key"]: peer["address"] for user in users if (peer := user.get("amneziawg", {})).get("public_key") and peer.get("address")}

def parse_runtime_dump(text: str) -> dict[str, str]:
    peers = {}
    for line in text.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 4 and parts[0]:
            peers[parts[0]] = parts[3]
    return peers

def safe_profile_summary(config: dict) -> dict:
    """DTO для портала: секрет заменён необратимым отпечатком."""
    v3 = config.get("v3", {})
    key = str(v3.get("header_protection_key", ""))
    return {
        "protocol_version": config.get("protocol_version", "legacy"),
        "header_key_sha256": hashlib.sha256(key.encode()).hexdigest() if key else "",
    }

__all__ = ["PROFILES", "V3_CONFIG_KEYS", "expected_peers", "obfuscation_lines", "parse_runtime_dump", "render_client", "render_server", "safe_profile_summary", "v3_lines", "validate_config"]
