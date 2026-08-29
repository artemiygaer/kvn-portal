"""Чистые renderer helpers Telemt и MTG."""

import json

def render_telemt(*, server: str, tls_domain: str, local_site: bool, access_users: dict[str, str]) -> str:
    lines = [
        "# Конфиг Telemt: отдельная реализация MTProto proxy.", "# Внешний порт 443 принимает nginx, поэтому Telemt слушает внутренний порт 3129.", "",
        "[general]", "use_middle_proxy = true", "me2dc_fallback = true", "me2dc_fast = true", "me_keepalive_enabled = true", "me_keepalive_interval_secs = 8", "me_keepalive_jitter_secs = 2", "me_keepalive_payload_random = true", "me_reconnect_backoff_base_ms = 500", "me_reconnect_backoff_cap_ms = 30000", 'log_level = "normal"', 'proxy_secret_path = "/tmp/telemt/proxy-secret"', 'proxy_config_v4_cache_path = "/tmp/telemt/proxy-config-v4.txt"', 'proxy_config_v6_cache_path = "/tmp/telemt/proxy-config-v6.txt"', 'beobachten_file = "/tmp/telemt/beobachten.txt"', "",
        "[general.modes]", "classic = false", "secure = true", "tls = true", "", "[general.links]", "show = []", f"public_host = {json.dumps(server)}", "public_port = 443", "", "[server]", "port = 3129", "", "[server.api]", "enabled = true", 'listen = "0.0.0.0:9091"', "whitelist = [", '  "127.0.0.1/32",', '  "172.16.0.0/12"', "]", "", "[[server.listeners]]", 'ip = "0.0.0.0"', "",
        "[timeouts]", "client_handshake = 30", "client_first_byte_idle_secs = 300", "relay_idle_policy_v2_enabled = true", "relay_client_idle_soft_secs = 120", "relay_client_idle_hard_secs = 360", "relay_idle_grace_after_downstream_activity_secs = 30", "client_keepalive = 15", "client_ack = 90", "",
        "[censorship]", f"tls_domain = {json.dumps(tls_domain)}", 'unknown_sni_action = "mask"', "mask = true",
        *(['mask_host = "nginx"', "mask_port = 8443"] if local_site else []),
        "tls_emulation = true", "alpn_enforce = true", "mask_shape_hardening = true", "mask_shape_hardening_aggressive_mode = false", 'tls_front_dir = "/tmp/telemt/tlsfront"', "", "[access]", "replay_check_len = 65536", "replay_window_secs = 120", "ignore_time_skew = false", "", "[access.users]",
    ]
    lines.extend(f"{json.dumps(name)} = {json.dumps(secret)}" for name, secret in access_users.items())
    lines.append("")
    return "\n".join(lines)

def render_mtg(*, secret: str, local_site: bool) -> str:
    if not secret:
        raise ValueError("MTG secret не задан.")
    lines = [
        "# Конфиг mtg (MTProto FakeTLS). Генерируется из users.json — не править вручную.", "debug = false", f'secret = "{secret}"', 'bind-to = "0.0.0.0:3128"', "concurrency = 8192", 'prefer-ip = "only-ipv4"', 'tolerate-time-skewness = "5s"', "auto-update = false", "allow-fallback-on-unknown-dc = false", "",
        "[domain-fronting]", f"port = {8443 if local_site else 443}", "proxy-protocol = false", "", "[network]", 'dns = ""', "proxies = []", "", "[network.timeout]", 'tcp = "5s"', 'http = "10s"', 'idle = "5m"', 'handshake = "10s"', "", "[network.keep-alive]", "disabled = false", 'idle = "15s"', 'interval = "15s"', "count = 9", "", "[defense.doppelganger]", "urls = []", "repeats-per-raid = 10", 'raid-each = "6h"', "drs = false", "", "[defense.anti-replay]", "enabled = true", 'max-size = "1mib"', "error-rate = 0.001", "",
    ]
    return "\n".join(lines)

__all__ = ["render_mtg", "render_telemt"]
