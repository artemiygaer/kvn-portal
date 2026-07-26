"""Локальный стенд с обезличенными данными для визуальной проверки."""

import base64
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_client import AgentClientError
from app import create_app
from app.security import hash_password


class VisualAgent:
    def __init__(self, users_file: Path, update_dir: Path):
        self.users_file = users_file
        self.update_dir = update_dir
        self.github_state = "normal"
        self.performance_profile = "standard"
        self.performance_features = {"monitoring": True, "background_refresh": True}
        self.client_export = {
            "revision": "visual-revision",
            "address_mode": "server",
            "public_ip": "8.8.4.4",
            "include_alternate": True,
            "server_address": "vpn.example.test",
            "effective_address": "vpn.example.test",
            "ip_bundle_ready": True,
            "subscription": {
                "port": 2096,
                "route_ready": True,
                "certificate_ready": False,
                "ready": False,
                "certificate_target": "site",
            },
        }

    def call(self, method, params, *, timeout=None):
        if method == "project.release.settings":
            if self.github_state == "agent-restart":
                raise AgentClientError("unknown_method: visual")
            return {
                "enabled": self.github_state != "disabled",
                "repository": "artemiygaer/kvn-portal",
                "channel": "stable",
                "tag": "",
                "asset_preference": "deploy",
            }
        if method == "project.release.check":
            errors = {
                "private": "release_not_found: visual",
                "rate": "github_rate_limited: visual",
                "offline": "github_unavailable: visual",
                "no-release": "release_not_found: visual",
            }
            if self.github_state in errors:
                raise AgentClientError(errors[self.github_state])
            tag = "v2026.07.24" if self.github_state == "up-to-date" else "v2026.07.25"
            asset = {
                "id": 72, "name": "kvn-vpn-deploy.tar.gz", "kind": "deploy",
                "size": 4096, "sha256": "d" * 64,
            }
            return {
                "ok": True,
                "repository": "artemiygaer/kvn-portal",
                "channel": "stable",
                "tag": tag,
                "release_id": 71,
                "release_name": "KVN VPN — проверенный Release",
                "published_at": "2026-07-24T10:00:00Z",
                "notes": "<script>visual fixture</script>\nИсправления портала и обновления.",
                "assets": [asset],
                "asset": asset,
                "authenticated": False,
            }
        if method == "project.release.prepare":
            if self.github_state == "digest":
                raise AgentClientError("digest_mismatch: visual")
            self.update_dir.mkdir(parents=True, exist_ok=True)
            path = self.update_dir / "kvn-vpn-deploy-github-dddddddddddd.tar.gz"
            path.write_bytes(b"\x1f\x8b" + b"v" * 4094)
            return {
                "ok": True, "ready": True, "reused": False,
                "repository": "artemiygaer/kvn-portal", "channel": "stable",
                "tag": "v2026.07.25", "release_id": params["release_id"],
                "asset_id": params["asset_id"],
                "archive": f"portal-data/updates/{path.name}",
                "archive_name": "kvn-vpn-deploy.tar.gz",
                "archive_size": path.stat().st_size,
                "archive_sha256": params["asset_sha256"],
                "archive_members": 125,
                "archive_kind": "deploy",
                "validation": {
                    "api_digest": True,
                    "download_sha256": True,
                    "internal_manifest": {
                        "internal": "deploy-inspector",
                        "member_count": 125,
                    },
                },
            }
        if method == "project.update":
            return {
                "ok": True, "archive": params["archive"],
                "archive_name": "kvn-vpn-deploy.tar.gz",
                "archive_size": 4096, "archive_sha256": params["expected_sha256"],
                "archive_members": 125, "unit": "kvn-project-update-visual",
                "journal_command": "journalctl -u kvn-project-update-visual",
                "recovery_command": "sudo ls -ld .update-backups/*",
                "command": {"stderr": ""}, "correlation_id": "visual-update",
            }
        if method == "client.export.settings":
            return json.loads(json.dumps(self.client_export))
        if method == "client.export.update":
            self.client_export.update({
                "revision": "visual-next-revision",
                "address_mode": params["address_mode"],
                "public_ip": params["public_ip"],
                "include_alternate": params["include_alternate"],
                "effective_address": (
                    params["public_ip"]
                    if params["address_mode"] == "public-ip"
                    else "vpn.example.test"
                ),
                "ip_bundle_ready": bool(params["public_ip"]),
            })
            return {
                "changed": True,
                "revision": "visual-next-revision",
                "settings": json.loads(json.dumps(self.client_export)),
                "plan": {"changed": True, "changed_paths": ["clients/"]},
                "apply": {
                    "outcome": "applied", "reconcile_required": False,
                    "warnings": [], "fallbacks": [], "failed": [],
                },
            }
        if method == "portal.performance":
            return {
                "revision": "visual-revision", "profile": self.performance_profile,
                "features": dict(self.performance_features),
                "endpoint": {
                    "host": "46.29.239.64", "host_kind": "ipv4",
                    "public_ready": True, "allow_self_signed_ip": True,
                },
            }
        if method == "portal.performance.update":
            self.performance_profile = params["profile"]
            if self.performance_profile == "standard":
                self.performance_features = {"monitoring": True, "background_refresh": True}
            elif self.performance_profile == "light":
                self.performance_features = {"monitoring": False, "background_refresh": False}
            else:
                self.performance_features = {
                    "monitoring": params["monitoring"],
                    "background_refresh": params["background_refresh"],
                }
            state = json.loads(self.users_file.read_text(encoding="utf-8"))
            state.setdefault("portal", {})["performance_profile"] = self.performance_profile
            state["portal"]["features"] = dict(self.performance_features)
            self.users_file.write_text(
                json.dumps(state, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            return {
                "changed": True, "changed_features": ["monitoring", "background_refresh"],
                "revision": "visual-next-revision", "profile": params["profile"],
                "features": dict(self.performance_features),
                "endpoint": {"host": "46.29.239.64", "host_kind": "ipv4", "public_ready": True, "allow_self_signed_ip": True},
            }
        if method == "dashboard.snapshot":
            methods = {
                "host": "health.host", "metrics": "metrics.current",
                "containers": "stats.containers", "protocols": "protocol.stats",
                "health_summary": "health.summary", "certificates": "certificates.status",
            }
            return {
                "sources": {
                    name: {"data": self.call(source, {}), "collected_at": 1_800_000_000, "age_seconds": 0, "stale": False, "error": ""}
                    for name, source in methods.items()
                },
                "generated_at": 1_800_000_000, "refreshing": False, "stale": False, "status": "ok",
            }
        if method == "network.topology":
            specs = [
                ("tls", "VLESS TLS", "xray", "VLESS / RAW / TLS", "xray:443", "tcp-443-sni", "per_user", "www.microsoft.com"),
                ("reality-xhttp", "Reality xHTTP", "xray", "VLESS / XHTTP / REALITY", "xray:2053", "tcp-2444-direct", "per_user", "github.com"),
                ("reality-tcp", "Reality TCP", "xray", "VLESS / RAW / REALITY", "xray:2054", "tcp-2445-direct", "per_user", "apple.com"),
                ("hysteria", "Hysteria 2", "hysteria", "Hysteria 2 / QUIC / TLS", "hysteria:443", "udp-443-direct", "per_user", "www.apple.com"),
                ("telemt", "Telemt", "telemt", "MTProto / FakeTLS", "telemt:3129", "tcp-2446-direct", "service", "telegram.org"),
                ("mtg", "MTProto FakeTLS", "mtg", "MTProto / FakeTLS", "mtg:3128", "tcp-2447-direct", "service", "cloudflare.com"),
                ("amneziawg", "AmneziaWG", "amneziawg", "AmneziaWG / UDP", "awg0", "udp-51820-direct", "not_applicable", ""),
                ("wireguard", "WireGuard", "wireguard", "WireGuard / UDP", "wg0", "udp-51821-direct", "not_applicable", ""),
                ("ocserv", "OpenConnect", "ocserv", "OpenConnect / TLS + DTLS", "ocserv:443", "udp-4443-direct", "service", "vpn.example.test"),
            ]
            return {
                "revision": "visual-revision",
                "ingress": [
                    {"id": "http-80", "port": 80, "protocol": "tcp", "role": "HTTP-01 / redirect"},
                    {"id": "tcp-443-sni", "port": 443, "protocol": "tcp", "role": "nginx SNI router"},
                    {"id": "udp-443-direct", "port": 443, "protocol": "udp", "role": "Hysteria 2 direct"},
                    {"id": "udp-4443-direct", "port": 4443, "protocol": "udp", "role": "OpenConnect DTLS"},
                    {"id": "udp-51820-direct", "port": 51820, "protocol": "udp", "role": "AmneziaWG"},
                    {"id": "udp-51821-direct", "port": 51821, "protocol": "udp", "role": "WireGuard"},
                ],
                "routes": [
                    {"system": system, "default": sni, "aliases": [sni], "dest": backend, "kind": "direct-udp" if system == "hysteria" else "nginx-sni"}
                    for system, _label, _service, _transport, backend, _ingress, scope, sni in specs if scope != "not_applicable"
                ],
                "protocols": [{
                    "system": system, "label": label, "enabled": system != "mtg", "service": service,
                    "ingress": [ingress], "transport": transport, "backend": backend,
                    "backend_kind": "host" if system in {"amneziawg", "wireguard"} else "docker",
                    "apply_kind": "reload", "users": {"assigned": 2, "enabled": 1},
                    "sni": {"scope": scope, "default": sni, "aliases": [sni] if sni else [], "aliases_count": 1 if sni else 0, "target": "", "server_names": [sni] if sni else []},
                    "sni_scope": scope, "read_only": True,
                    "facts": ({
                        "hysteria": {"public_transport": "443/udp", "certificate_target": "site"},
                        "telemt": {"direct_transport": "2446/tcp", "sni_scope": "service"},
                        "mtg": {"direct_transport": "2447/tcp", "sni_scope": "service"},
                        "amneziawg": {"public_transport": "51820/udp", "interface": "awg0", "apply_path": "awg syncconf или controlled restart"},
                        "wireguard": {"public_transport": "51821/udp", "interface": "wg0", "apply_path": "wg syncconf или controlled restart"},
                        "ocserv": {"tcp_route": "nginx-sni", "dtls_transport": "4443/udp", "certificate_target": "ocserv"},
                    }.get(system, {})),
                    "settings": {"path": "/api/v1/data", "xhttp_mode": "stream-one"} if system == "reality-xhttp" else {},
                } for system, label, service, transport, backend, ingress, scope, sni in specs],
                "infrastructure": [{"id": "nginx", "kind": "docker", "role": "SNI router"}, {"id": "portal", "kind": "docker", "role": "web UI"}, {"id": "agent", "kind": "host", "role": "allowlisted RPC"}],
            }
        if method == "domain.advice":
            zone = params["zone"]
            roles = (
                ("site", zone, "ready"),
                ("portal", f"portal.{zone}", "add-certificate-san"),
                ("subscription", f"sub.{zone}", "add-dns-record"),
                ("tls", f"tls.{zone}", "ready"),
                ("hysteria", f"hy.{zone}", "ready"),
                ("ocserv", f"oc.{zone}", "ready"),
                ("wildcard", f"kvn-wildcard-check.{zone}", "wildcard-absent"),
            )
            return {
                "zone": zone,
                "status": "needs_attention",
                "timeout_seconds": 4.0,
                "hostname_count": len(roles),
                "hostnames": [{
                    "role": role,
                    "hostname": hostname,
                    "dns": "unavailable" if recommendation in {"add-dns-record", "wildcard-absent"} else "ok",
                    "tls": "unavailable" if recommendation == "add-certificate-san" else ("not_checked" if recommendation in {"add-dns-record", "wildcard-absent"} else "ok"),
                    "cert_match": "mismatch" if recommendation == "add-certificate-san" else ("not_checked" if recommendation in {"add-dns-record", "wildcard-absent"} else "match"),
                    "same_server": role == "site",
                    "recommendation": recommendation,
                } for role, hostname, recommendation in roles],
                "protocols": [
                    {"system": "reality-xhttp", "same_server": True, "recommendation": "external-cover-required"},
                    {"system": "reality-tcp", "same_server": True, "recommendation": "external-cover-required"},
                    {"system": "telemt", "same_server": False, "recommendation": "service-level-camouflage"},
                    {"system": "mtg", "same_server": False, "recommendation": "service-level-camouflage"},
                    {"system": "amneziawg", "same_server": False, "recommendation": "no-sni"},
                    {"system": "wireguard", "same_server": False, "recommendation": "no-sni"},
                ],
            }
        if method == "health.host":
            return {"uptime": {"stdout": "up 2 days"}}
        if method == "metrics.current":
            return {"available": True, "sample": {"timestamp": 1_800_000_000, "cpu_percent": 18, "memory_used": 2_500_000_000, "memory_total": 8_000_000_000, "memory_percent": 31, "disk_used": 42_000_000_000, "disk_total": 100_000_000_000, "disk_percent": 42, "load1": 0.18, "rx_bytes_per_second": 1250000, "tx_bytes_per_second": 340000}}
        if method == "metrics.history":
            points = []
            for index in range(48):
                points.append({
                    "timestamp": 1_800_000_000 - (47 - index) * 1800,
                    "cpu_percent": 12 + index % 14,
                    "load1": 0.12 + (index % 8) / 10,
                    "memory_used": 2_300_000_000 + index * 8_000_000,
                    "memory_total": 8_000_000_000,
                    "memory_percent": 29 + index % 4,
                    "disk_used": 42_000_000_000 + index * 40_000_000,
                    "disk_total": 100_000_000_000,
                    "disk_percent": 42,
                    "rx_bytes_per_second": 500000 + index * 18000,
                })
            return {"available": True, "range_hours": params.get("range_hours", 24), "step_minutes": 30, "generated_at": 1_800_000_000, "points": points}
        if method == "stats.containers":
            return {"available": True, "containers": [{"Name": "nginx", "state": "running", "health": "healthy", "restarts": 0}, {"Name": "xray", "state": "running", "health": "none", "restarts": 0}]}
        if method == "protocol.stats":
            return {"collectors": {"hysteria": {"available": True, "values": {"online": 2}}, "xray": {"available": True, "values": {"counters": 7}}}}
        if method == "certificates.status":
            return {"certificates": [{"target": "site", "source": "letsencrypt", "issuer": "Let's Encrypt", "domains": ["portal.example.test"], "sans": ["portal.example.test"], "not_after": "2026-09-18", "expiry": "ok"}]}
        if method == "state.users":
            return {"revision": "visual-revision", "client_export": json.loads(json.dumps(self.client_export)), "systems": ["tls", "reality-xhttp", "reality-tcp", "hysteria", "telemt", "mtg", "amneziawg", "wireguard", "ocserv"], "sni_systems": ["tls", "reality-xhttp", "reality-tcp", "hysteria"], "sni_choices": {"tls": ["www.microsoft.com"], "reality-xhttp": ["github.com"], "reality-tcp": ["apple.com"], "hysteria": ["www.apple.com"]}, "sni_matrix": {"tls": {"scope": "per_user", "default": "www.microsoft.com"}, "reality-xhttp": {"scope": "per_user", "default": "github.com"}, "reality-tcp": {"scope": "per_user", "default": "apple.com"}, "hysteria": {"scope": "per_user", "default": "www.apple.com"}, "telemt": {"scope": "service", "default": "telegram.org"}, "mtg": {"scope": "service", "default": "cloudflare.com"}, "amneziawg": {"scope": "not_applicable", "default": ""}, "wireguard": {"scope": "not_applicable", "default": ""}, "ocserv": {"scope": "service", "default": "vpn.example.test"}}, "devices": ["phone", "desktop"], "users": [{"name": "demo-phone", "description": "Тестовый мобильный профиль", "enabled": True, "systems": ["hysteria", "reality-tcp", "telemt", "amneziawg"], "sni_overrides": {"hysteria": "edge.example.test"}, "effective_sni": {"hysteria": "edge.example.test", "reality-tcp": "apple.com"}}, {"name": "demo-office", "description": "Обезличенный стенд", "enabled": False, "systems": ["ocserv", "mtg", "wireguard"], "sni_overrides": {}, "effective_sni": {}}]}
        if method == "sni.routes":
            return {"revision": "visual-revision", "systems": ["tls", "hysteria"], "routes": {"tls": {"default": "www.microsoft.com", "aliases": ["www.microsoft.com"], "choices": ["www.microsoft.com"], "user_selectable": True}, "hysteria": {"default": "www.apple.com", "aliases": ["www.apple.com"], "choices": ["www.apple.com"], "user_selectable": True}}}
        if method == "mtproto.status":
            return {
                "revision": "visual-revision", "origins": ["external", "local-site"],
                "services": {
                    "telemt": {"label": "Telemt", "origin": "local-site", "sni": "mt.example.test", "target": "nginx:8443", "credential_scope": "per-user", "public_port": 443, "direct_port": 2446},
                    "mtg": {"label": "MTG", "origin": "external", "sni": "cdn.example.test", "target": "cdn.example.test:443", "credential_scope": "shared", "public_port": 443, "direct_port": 2447},
                },
            }
        if method == "state.user":
            return {"revision": "visual-revision", "client_export": json.loads(json.dumps(self.client_export)), "user": {"name": params["name"], "description": "Тестовый профиль", "enabled": True, "systems": ["hysteria", "reality-tcp"], "device": "phone", "sni_overrides": {}, "uuid_mask": "••••••••-••••", "subscription_mask": "••••••••", "files": [{"name": "happ-subscription.txt", "kind": "happ-url", "label": "Ссылка подписки HAPP", "size": 42, "content_type": "text/plain; charset=utf-8", "can_preview": True, "can_download": True}, {"name": "openconnect.txt", "kind": "file", "label": "openconnect.txt", "size": 80, "content_type": "text/plain; charset=utf-8", "can_preview": True, "can_download": True}]}}
        if method == "user.activity":
            return {
                "name": params["name"], "generated_at": 1_800_000_000,
                "privacy": {"client_endpoints": "hidden", "raw_logs": "excluded"},
                "systems": [
                    {"system": "hysteria", "status": "active", "source": "hysteria-api", "reason": "", "rx_bytes": 3_400_000, "tx_bytes": 1_200_000, "online": True, "connections": 2},
                    {"system": "reality-tcp", "status": "observed", "source": "xray-stats", "reason": "", "uplink_bytes": 820_000, "downlink_bytes": 7_600_000},
                ],
            }
        if method == "state.apply":
            fields = params.get("fields", {})
            name = fields.get("new_name") or fields.get("name") or "demo-phone"
            return {"changed": True, "revision": "visual-next-revision", "plan": {"changed": True, "changed_paths": ["clients/fixture"], "services": {}}, "apply": {"outcome": "applied", "warnings": [], "fallbacks": [], "restarted": []}, "user": {"name": name}, "secrets": {"uuid": "00000000-0000-4000-8000-000000000000", "amneziawg_private_key": "DEMO-PRIVATE-KEY-NOT-REAL"}}
        if method == "user.file":
            content = "Обезличенный тестовый профиль\n".encode("utf-8")
            return {"filename": params["filename"], "content_type": "text/plain; charset=utf-8", "kind": "file", "content_base64": base64.b64encode(content).decode("ascii")}
        if method == "user.export":
            mode = params["address_mode"]
            text = (
                "KVN VPN — обезличенный тест\n"
                f"endpoint={'8.8.4.4' if mode == 'public-ip' else 'vpn.example.test'}\n"
                "vless://<скрыто>\n"
            ).encode("utf-8")
            archive = b"PK\x03\x04KVN-VISUAL-REDACTED"
            return {
                "address_mode": mode,
                "archive_filename": f"kvn-{params['name']}-{mode}.zip",
                "archive_content_type": "application/zip",
                "archive_size": len(archive),
                "archive_base64": base64.b64encode(archive).decode("ascii"),
                "text_filename": f"kvn-{params['name']}-{mode}.txt",
                "text_content_type": "text/plain; charset=utf-8",
                "text_size": len(text),
                "text_base64": base64.b64encode(text).decode("ascii"),
                "manifest": {"schema": 1, "address_mode": mode},
            }
        if method == "service.status":
            return {"service": params["service"], "active": params["service"] != "mtg", "enabled": True}
        if method == "service.action":
            return {"ok": True, "service": params["service"], "action": params["action"], "before": {"active": True}, "after": {"active": True}, "health": {"ok": True}, "duration_ms": 8, "correlation_id": "visual-service-action", "warning": ""}
        if method == "logs.tail":
            return {"command": {
                "returncode": 0,
                "duration_ms": 8,
                "stdout": "2026-06-20T12:00:00Z nginx: конфигурация перечитана\n2026-06-20T12:00:01Z portal: запрос обработан\n",
            }}
        if method == "maintenance.commands":
            return {"commands": [
                {"id": "system_failed", "title": "Проблемные systemd units", "group": "Система", "description": "Показывает units в failed-состоянии.", "requires_confirmation": False},
                {"id": "compose_ps", "title": "Docker Compose ps", "group": "Docker", "description": "Состояние контейнеров проекта.", "requires_confirmation": False},
                {"id": "kvn_reconcile", "title": "Согласование состояния", "group": "KVN", "description": "Повторно применяет целевое состояние.", "requires_confirmation": True},
            ]}
        if method == "maintenance.run":
            return {"ok": True, "id": params["command"], "title": "Docker Compose ps", "group": "Docker", "description": "Состояние контейнеров проекта.", "requires_confirmation": False, "correlation_id": "visual-maintenance", "command": {"returncode": 0, "stdout": "NAME          STATE\nnginx-front   running\nxray          running\n", "stderr": "", "duration_ms": 6}}
        if method == "shell.open":
            return {"ok": True, "shell_id": "d" * 32, "alive": True, "exit_code": None, "output": "root@kvn:/srv/kvn# ", "limits": {"idle_seconds": 900, "absolute_seconds": 3600, "max_write_bytes": 4096}}
        if method == "shell.read":
            return {"ok": True, "shell_id": params["shell_id"], "alive": True, "exit_code": None, "output": ""}
        if method == "shell.write":
            return {"ok": True, "shell_id": params["shell_id"], "alive": True, "written": len(params.get("data", ""))}
        if method == "shell.resize":
            return {"ok": True, "shell_id": params["shell_id"], "alive": True, "rows": params.get("rows", 24), "cols": params.get("cols", 100)}
        if method == "shell.close":
            return {"ok": True, "shell_id": params["shell_id"], "alive": False, "exit_code": 0}
        if method == "health.summary":
            return {"services": {"nginx": {"active": True}, "xray": {"active": True}, "mtg": {"active": False}}, "diagnostics": [{"reason": "mtg остановлен по политике", "command": "systemctl status kvn-portal-agent"}]}
        if method == "certificate.action":
            return {"ok": True, "action": params["action"], "target": params["target"], "correlation_id": "visual-certificate-action"}
        raise RuntimeError(f"Метод стенда не реализован: {method}")


class ProxyHeaders:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ["HTTP_X_KVN_PROXY_SECRET"] = "visual-proxy-secret"
        environ["HTTP_X_FORWARDED_PROTO"] = "https"
        environ["HTTP_X_REAL_IP"] = "192.0.2.42"
        return self.app(environ, start_response)


root = Path(tempfile.mkdtemp(prefix="kvn-visual-"))
users_file = root / "users.json"
users_file.write_text(json.dumps({"users": []}), encoding="utf-8")
visual_agent = VisualAgent(users_file, root / "updates")
app = create_app({
    "DATABASE": root / "portal.db",
    "USERS_FILE": users_file,
    "PORTAL_PATH": "/gaer",
    "PORTAL_NAME": "KVN VPN — тестовый узел",
    "ADMIN_LOGIN": "admin",
    "ADMIN_PASSWORD_HASH": hash_password("VisualPassword-2026"),
    "PROXY_SECRET": "visual-proxy-secret",
    "HYSTERIA_SECRET": "visual-hysteria-secret",
    "SESSION_COOKIE_SECURE": False,
    "AGENT_CLIENT": visual_agent,
    "UPDATE_UPLOAD_DIR": root / "updates",
    "UPDATE_UPLOAD_RELATIVE_DIR": "portal-data/updates",
    "BUILD_ID": "2026.07.24",
})


@app.get("/gaer/__visual/github-state")
def set_visual_github_state():
    from flask import jsonify, request

    allowed = {
        "normal", "disabled", "private", "no-release", "up-to-date",
        "rate", "offline", "digest", "agent-restart",
    }
    state = request.args.get("state", "")
    if state not in allowed:
        return jsonify({"ok": False}), 400
    visual_agent.github_state = state
    return jsonify({"ok": True, "state": state})


app.extensions["kvn_storage"].audit(
    "visual-admin", "192.0.2.42", "user.update", "success", now=1_800_000_000,
    target_type="user", target_name="demo-phone",
)
app.extensions["kvn_storage"].audit(
    "visual-admin", "192.0.2.42", "user.link.download", "success", now=1_799_999_700,
    target_type="user", target_name="demo-phone",
)
app.wsgi_app = ProxyHeaders(app.wsgi_app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
