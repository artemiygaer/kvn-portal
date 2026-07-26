"""Адаптер host-agent к единственному источнику правды `users.json`."""

from __future__ import annotations

import base64
import copy
import datetime
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

from tools.kvnlib.export_bundle import (
    ExportBundleError,
    build_user_export_bundle,
)


class ControlError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class KvnControl:
    DOWNLOAD_SUFFIXES = {".txt", ".json", ".yaml", ".toml", ".conf", ".png"}
    TEXT_SUFFIXES = {".txt", ".json", ".yaml", ".toml", ".conf"}
    SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
    MAX_DOWNLOAD_BYTES = 1024 * 1024
    DOMAIN_ADVICE_TIMEOUT = 4.0
    DOMAIN_ADVICE_ROLES = ("site", "portal", "subscription", "tls", "hysteria", "ocserv")
    TOPOLOGY_SPECS = {
        "tls": {
            "service": "xray", "transport": "VLESS / RAW / TLS", "backend": "xray:443",
            "backend_kind": "docker", "apply_kind": "docker-render-reload",
            "ingress": ["tcp-443-sni", "tcp-2443-direct"],
        },
        "reality-xhttp": {
            "service": "xray", "transport": "VLESS / XHTTP / REALITY", "backend": "xray:2053",
            "backend_kind": "docker", "apply_kind": "docker-render-reload",
            "ingress": ["tcp-443-sni", "tcp-2444-direct"],
        },
        "reality-tcp": {
            "service": "xray", "transport": "VLESS / RAW / REALITY", "backend": "xray:2054",
            "backend_kind": "docker", "apply_kind": "docker-render-reload",
            "ingress": ["tcp-443-sni", "tcp-2445-direct"],
        },
        "hysteria": {
            "service": "hysteria", "transport": "Hysteria 2 / QUIC / TLS", "backend": "hysteria:443",
            "backend_kind": "docker", "apply_kind": "docker-render-restart",
            "ingress": ["udp-443-direct"],
        },
        "telemt": {
            "service": "telemt", "transport": "MTProto / FakeTLS", "backend": "telemt:3129",
            "backend_kind": "docker", "apply_kind": "docker-file-watcher",
            "ingress": ["tcp-443-sni", "tcp-2446-direct"],
        },
        "mtg": {
            "service": "mtg", "transport": "MTProto / FakeTLS", "backend": "mtg:3128",
            "backend_kind": "docker", "apply_kind": "docker-render-restart",
            "ingress": ["tcp-443-sni", "tcp-2447-direct"],
        },
        "amneziawg": {
            "service": "amneziawg", "transport": "AmneziaWG / UDP", "backend": "awg0",
            "backend_kind": "host", "apply_kind": "host-syncconf-or-restart",
            "ingress": ["udp-51820-direct"],
        },
        "wireguard": {
            "service": "wireguard", "transport": "WireGuard / UDP", "backend": "wg0",
            "backend_kind": "host", "apply_kind": "host-syncconf-or-restart",
            "ingress": ["udp-51821-direct"],
        },
        "ocserv": {
            "service": "ocserv", "transport": "OpenConnect / TLS + DTLS", "backend": "ocserv:443",
            "backend_kind": "docker", "apply_kind": "docker-hup-or-restart",
            "ingress": ["tcp-443-sni", "tcp-2448-direct", "udp-4443-direct"],
        },
    }
    INGRESS_SPECS = (
        ("http-80", 80, "tcp", "domain-check / redirect / HTTP-01"),
        ("tcp-443-sni", 443, "tcp", "nginx SNI router"),
        ("udp-443-direct", 443, "udp", "Hysteria 2 direct"),
        ("udp-4443-direct", 4443, "udp", "OpenConnect DTLS direct"),
        ("udp-51820-direct", 51820, "udp", "AmneziaWG direct"),
        ("udp-51821-direct", 51821, "udp", "WireGuard direct"),
        ("tcp-2096-subscription", 2096, "tcp", "HTTPS subscription fallback"),
        ("tcp-2443-direct", 2443, "tcp", "VLESS TLS direct"),
        ("tcp-2444-direct", 2444, "tcp", "Reality xHTTP direct"),
        ("tcp-2445-direct", 2445, "tcp", "Reality TCP direct"),
        ("tcp-2446-direct", 2446, "tcp", "Telemt direct"),
        ("tcp-2447-direct", 2447, "tcp", "mtg direct"),
        ("tcp-2448-direct", 2448, "tcp", "OpenConnect TCP direct"),
    )

    def __init__(self, project_root: Path):
        self.root = Path(project_root).resolve()
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
        from tools import kvnctl
        from tools.kvnlib.state import StateRevisionConflict, state_revision

        if kvnctl.ROOT.resolve() != self.root:
            raise RuntimeError("Host-agent загружен не из настроенного каталога проекта.")
        self.kvnctl = kvnctl
        self.StateRevisionConflict = StateRevisionConflict
        self.state_revision = state_revision

    def _safe_user(self, user: dict | None) -> dict | None:
        if user is None:
            return None
        return {
            "name": user["name"],
            "description": user.get("description", ""),
            "enabled": user.get("enabled", True),
            "systems": self.kvnctl.user_systems(user),
            "device": user.get("device", ""),
            "sni_overrides": copy.deepcopy(user.get("sni_overrides", {})),
            "uuid_mask": self.kvnctl.mask_secret(user.get("uuid", ""), 8),
            "subscription_mask": self.kvnctl.mask_secret(user.get("sub_token", ""), 6),
            "files": self.user_files(user["name"]),
        }

    def list_users(self) -> dict:
        stored_state = self.kvnctl.STATE_STORE.load()
        revision = self.state_revision(stored_state)
        state = copy.deepcopy(stored_state)
        safe_users = []
        for user in state.get("users", []):
            safe = self._safe_user(user)
            safe["effective_sni"] = {
                system: user.get("sni_overrides", {}).get(system) or self.kvnctl.ensure_sni_route(state, system).get("default", "")
                for system in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS
                if system in self.kvnctl.user_systems(user)
            }
            safe_users.append(safe)
        sni_matrix = {}
        for system in self.kvnctl.ALL_SYSTEMS:
            if system in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS:
                route = self.kvnctl.ensure_sni_route(state, system)
                sni_matrix[system] = {"scope": "per_user", "default": route.get("default", "")}
            elif system in self.kvnctl.SNI_ROUTE_SYSTEMS:
                route = self.kvnctl.ensure_sni_route(state, system)
                sni_matrix[system] = {"scope": "service", "default": route.get("default", "")}
            elif system == "ocserv":
                ocserv = state.get("ocserv", {}) if isinstance(state.get("ocserv"), dict) else {}
                sni_matrix[system] = {"scope": "service", "default": str(ocserv.get("sni", "")) if ocserv.get("sni_enabled") else ""}
            else:
                sni_matrix[system] = {"scope": "not_applicable", "default": ""}
        return {
            "revision": revision,
            "users": safe_users,
            "systems": list(self.kvnctl.ALL_SYSTEMS),
            "sni_systems": list(self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS),
            "sni_choices": self.kvnctl.user_selectable_sni_choices(state),
            "sni_matrix": sni_matrix,
            "devices": list(self.kvnctl.ALL_DEVICES),
            "client_export": self.client_export_settings(state),
        }

    def network_topology(self) -> dict:
        """Возвращает безопасную модель сети без ключей и generated-конфигов."""
        stored_state = self.kvnctl.STATE_STORE.load()
        revision = self.state_revision(stored_state)
        state = copy.deepcopy(stored_state)
        users = state.get("users", []) if isinstance(state.get("users"), list) else []
        service_preferences = state.get("services", {})
        if not isinstance(service_preferences, dict):
            service_preferences = {}

        protocols = []
        for system in self.kvnctl.ALL_SYSTEMS:
            spec = self.TOPOLOGY_SPECS[system]
            assigned = [user for user in users if system in self.kvnctl.user_systems(user)]
            service_cfg = service_preferences.get(spec["service"], {})
            service_enabled = not isinstance(service_cfg, dict) or bool(service_cfg.get("enabled", True))
            if system == "ocserv":
                ocserv_cfg = state.get("ocserv", {})
                if isinstance(ocserv_cfg, dict) and "enabled" in ocserv_cfg:
                    service_enabled = service_enabled and bool(ocserv_cfg.get("enabled"))

            if system in self.kvnctl.SNI_ROUTE_SYSTEMS:
                route = self.kvnctl.ensure_sni_route(state, system)
                aliases = list(route.get("aliases", []))
                server_names = (
                    self.kvnctl.reality_xhttp_server_names(state)
                    if system == "reality-xhttp"
                    else self.kvnctl.route_server_names(state, system)
                )
                sni = {
                    "scope": "per_user" if system in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS else "service",
                    "default": route.get("default", ""),
                    "aliases": aliases,
                    "aliases_count": len(aliases),
                    "target": f"{route.get('default', '')}:443" if system in self.kvnctl.REALITY_SYSTEMS else "",
                    "server_names": server_names,
                }
            elif system == "ocserv":
                ocserv_cfg = state.get("ocserv", {}) if isinstance(state.get("ocserv"), dict) else {}
                ocserv_sni = str(ocserv_cfg.get("sni", "")) if ocserv_cfg.get("sni_enabled") else ""
                front_snis = [item for item in ocserv_cfg.get("front_snis", []) if isinstance(item, str)]
                sni = {
                    "scope": "service", "default": ocserv_sni,
                    "aliases": front_snis, "aliases_count": len(front_snis),
                    "target": "", "server_names": [item for item in [ocserv_sni, *front_snis] if item],
                }
            else:
                sni = {
                    "scope": "not_applicable", "default": "", "aliases": [],
                    "aliases_count": 0, "target": "", "server_names": [],
                }

            protocol = {
                "system": system,
                "label": self.kvnctl.SYSTEM_LABELS.get(system, system),
                "enabled": service_enabled,
                "service": spec["service"],
                "ingress": list(spec["ingress"]),
                "transport": spec["transport"],
                "backend": spec["backend"],
                "backend_kind": spec["backend_kind"],
                "apply_kind": spec["apply_kind"],
                "sni_scope": sni["scope"],
                "read_only": True,
                "users": {
                    "assigned": len(assigned),
                    "enabled": sum(1 for user in assigned if user.get("enabled", True)),
                },
                "sni": sni,
            }
            specialized = {
                "hysteria": {"public_transport": "443/udp", "certificate_target": "site", "metrics": ["users", "online", "tx", "rx"]},
                "telemt": {"direct_transport": "2446/tcp", "sni_scope": "service"},
                "mtg": {"direct_transport": "2447/tcp", "sni_scope": "service"},
                "amneziawg": {"public_transport": "51820/udp", "interface": "awg0", "apply_path": "awg syncconf или controlled restart"},
                "wireguard": {"public_transport": "51821/udp", "interface": "wg0", "apply_path": "wg syncconf или controlled restart"},
                "ocserv": {"tcp_route": "nginx-sni", "direct_transport": "2448/tcp", "dtls_transport": "4443/udp", "certificate_target": "ocserv"},
            }
            protocol["facts"] = specialized.get(system, {})
            if system == "reality-xhttp":
                protocol["settings"] = {
                    "path": "/api/v1/data",
                    "xhttp_mode": self.kvnctl.xhttp_mode(state),
                }
            protocols.append(protocol)

        routes = []
        for system in self.kvnctl.SNI_ROUTE_SYSTEMS:
            route = self.kvnctl.ensure_sni_route(state, system)
            routes.append({
                "system": system,
                "default": route.get("default", ""),
                "aliases": list(route.get("aliases", [])),
                "dest": route.get("dest", ""),
                "kind": "direct-udp" if system == "hysteria" else "nginx-sni",
            })

        return {
            "revision": revision,
            "ingress": [
                {"id": identifier, "port": port, "protocol": protocol, "role": role}
                for identifier, port, protocol, role in self.INGRESS_SPECS
            ],
            "routes": routes,
            "protocols": protocols,
            "infrastructure": [
                {"id": "nginx", "kind": "docker", "role": "SNI router и web ingress"},
                {"id": "portal", "kind": "docker", "role": "непривилегированный web UI"},
                {"id": "agent", "kind": "host", "role": "allowlisted RPC по Unix socket"},
            ],
        }

    @staticmethod
    def _resolve_addresses(host: str, timeout: float) -> set[str]:
        """Резолвит адреса только для внутреннего сравнения, не для ответа RPC."""
        addresses: set[str] = set()
        finished = threading.Event()

        def resolve() -> None:
            try:
                for _family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
                    if sockaddr:
                        addresses.add(str(sockaddr[0]))
            except OSError:
                pass
            finally:
                finished.set()

        threading.Thread(target=resolve, name="kvn-domain-advice-resolve", daemon=True).start()
        finished.wait(max(0.05, min(timeout, 1.0)))
        return addresses if finished.is_set() else set()

    def domain_advice(self, params: dict) -> dict:
        """Оценивает DNS/TLS без сохранения state и раскрытия сетевой идентичности."""
        if set(params) != {"zone"}:
            raise ControlError("invalid_params", "Советник принимает только базовую DNS-зону.")
        zone = params.get("zone")
        if not isinstance(zone, str):
            raise ControlError("validation_error", "DNS-зона не задана.")
        try:
            zone = self.kvnctl.validate_sni_domain(zone.strip().lower())
            ipaddress.ip_address(zone)
        except ValueError:
            pass
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc
        else:
            raise ControlError("validation_error", "IP-адрес нельзя использовать как базовую DNS-зону.")
        if zone.count(".") < 1 or len(zone) > 180:
            raise ControlError("validation_error", "Некорректная базовая DNS-зона.")

        state = self.kvnctl.STATE_STORE.load()
        server = str(state.get("server", "")).strip()
        try:
            server_addresses = {str(ipaddress.ip_address(server))}
        except ValueError:
            server_addresses = self._resolve_addresses(server, 0.5) if server else set()
        hostnames = {
            "site": zone,
            "portal": f"portal.{zone}",
            "subscription": f"sub.{zone}",
            "tls": f"tls.{zone}",
            "hysteria": f"hy.{zone}",
            "ocserv": f"oc.{zone}",
        }
        wildcard_host = f"kvn-wildcard-check.{zone}"
        started = time.monotonic()
        results = []
        for role, hostname in [*hostnames.items(), ("wildcard", wildcard_host)]:
            remaining = self.DOMAIN_ADVICE_TIMEOUT - (time.monotonic() - started)
            if remaining <= 0:
                probe = {"dns": "timeout", "tls": "not_checked", "reason": "total_timeout"}
            else:
                try:
                    probe = self.kvnctl.probe_sni_target(hostname, timeout=min(0.6, remaining))
                except (OSError, ValueError, SystemExit):
                    probe = {"dns": "unavailable", "tls": "not_checked", "reason": "probe_error"}
            dns = str(probe.get("dns", "unavailable"))
            tls = str(probe.get("tls", "not_checked"))
            cert_match = "match" if tls == "ok" else ("mismatch" if probe.get("reason") == "tls_invalid" else "not_checked")
            candidate_addresses = self._resolve_addresses(hostname, min(0.3, max(0.05, remaining))) if dns == "ok" else set()
            same_server = bool(server_addresses and candidate_addresses & server_addresses)
            if role == "wildcard":
                recommendation = "wildcard-present" if dns == "ok" else "wildcard-absent"
            elif dns != "ok":
                recommendation = "add-dns-record"
            elif tls != "ok" or cert_match != "match":
                recommendation = "add-certificate-san"
            else:
                recommendation = "ready"
            results.append({
                "role": role, "hostname": hostname, "dns": dns, "tls": tls,
                "cert_match": cert_match, "same_server": same_server,
                "recommendation": recommendation,
            })

        site_same_server = next(item["same_server"] for item in results if item["role"] == "site")
        local_route_names = {
            alias
            for system in self.kvnctl.SNI_ROUTE_SYSTEMS
            for alias in self.kvnctl.ensure_sni_route(state, system).get("aliases", [])
            if isinstance(alias, str)
        }
        reality_warning = bool(site_same_server or zone in local_route_names)
        policies = [
            {"system": system, "same_server": reality_warning, "recommendation": "external-cover-required" if reality_warning else "external-cover-preferred"}
            for system in ("reality-xhttp", "reality-tcp")
        ]
        policies.extend([
            {"system": "telemt", "same_server": False, "recommendation": "service-level-camouflage"},
            {"system": "mtg", "same_server": False, "recommendation": "service-level-camouflage"},
            {"system": "amneziawg", "same_server": False, "recommendation": "no-sni"},
            {"system": "wireguard", "same_server": False, "recommendation": "no-sni"},
        ])
        ready = all(item["recommendation"] == "ready" for item in results if item["role"] != "wildcard") and any(
            item["role"] == "wildcard" and item["dns"] == "ok" and item["cert_match"] == "match"
            for item in results
        )
        return {
            "zone": zone,
            "status": "ready" if ready else "needs_attention",
            "timeout_seconds": self.DOMAIN_ADVICE_TIMEOUT,
            "hostname_count": len(results),
            "hostnames": results,
            "protocols": policies,
        }

    def sni_routes(self) -> dict:
        stored_state = self.kvnctl.STATE_STORE.load()
        revision = self.state_revision(stored_state)
        state = copy.deepcopy(stored_state)
        return {
            "revision": revision,
            "systems": list(self.kvnctl.SNI_ROUTE_SYSTEMS),
            "user_systems": list(self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS),
            "routes": {
                system: self._sni_route_summary(state, system)
                for system in self.kvnctl.SNI_ROUTE_SYSTEMS
            },
        }

    def sni_diagnose(self, params: dict) -> dict:
        if set(params) != {"sni"}:
            raise ControlError("invalid_params", "Диагностика SNI принимает только домен.")
        sni = params.get("sni")
        if not isinstance(sni, str) or not sni.strip():
            raise ControlError("validation_error", "SNI не задан.")
        return self.kvnctl.probe_sni_target(sni)

    def mtproto_status(self) -> dict:
        """Безопасный статус маскировки без shared/per-user secrets."""
        stored_state = self.kvnctl.STATE_STORE.load()
        revision = self.state_revision(stored_state)
        state = copy.deepcopy(stored_state)
        services = {}
        for system in self.kvnctl.MTPROTO_SYSTEMS:
            assigned = [
                user for user in state.get("users", [])
                if system in self.kvnctl.user_systems(user) and user.get("enabled", True)
            ]
            origin = self.kvnctl.mtproto_camouflage_origin(state, system)
            sni = self.kvnctl.system_sni(state, system)
            services[system] = {
                "system": system,
                "label": self.kvnctl.SYSTEM_LABELS[system],
                "origin": origin,
                "sni": sni,
                "target": "nginx:8443" if origin == "local-site" else f"{sni}:443",
                "public_port": 443,
                "direct_port": self.kvnctl.DIRECT_PORTS[system],
                "credential_scope": "per-user" if system == "telemt" else "shared",
                "user_attribution": system == "telemt",
                "assigned_users": len(assigned),
            }
        return {
            "revision": revision,
            "origins": list(self.kvnctl.CAMOUFLAGE_ORIGINS),
            "services": services,
            "limitations": "Полную блокировку IP/TCP/TLS гарантированно обойти невозможно.",
        }

    def mtproto_diagnose(self, params: dict) -> dict:
        if set(params) != {"system"} or params.get("system") not in self.kvnctl.MTPROTO_SYSTEMS:
            raise ControlError("invalid_params", "Диагностика MTProto принимает telemt или mtg.")
        state = self.kvnctl.STATE_STORE.load()
        try:
            return self.kvnctl.mtproto_diagnose(
                state, params["system"], timeout=3.0, runtime_checks=True
            )
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc

    def apply_mtproto(self, params: dict) -> dict:
        if set(params) != {"system", "origin", "revision"}:
            raise ControlError("invalid_params", "Некорректная схема настройки MTProto.")
        system = params.get("system")
        origin = params.get("origin")
        revision = params.get("revision")
        if system not in self.kvnctl.MTPROTO_SYSTEMS:
            raise ControlError("validation_error", "Неизвестный MTProto-сервис.")
        if origin not in self.kvnctl.CAMOUFLAGE_ORIGINS:
            raise ControlError("validation_error", "Неизвестный источник маскировки.")
        if not isinstance(revision, str) or len(revision) != 64:
            raise ControlError("invalid_revision", "Некорректная ревизия состояния.")

        diagnosis: dict = {}

        def mutate(state: dict) -> None:
            nonlocal diagnosis
            self.kvnctl.mtproto_config(state, system)["camouflage_origin"] = origin
            self.kvnctl.prepare_state(state)
            diagnosis = self.kvnctl.mtproto_diagnose(
                state, system, timeout=1.0, runtime_checks=False
            )
            if not diagnosis.get("can_apply"):
                errors = ", ".join(diagnosis.get("errors", []))
                raise ControlError(
                    "validation_error",
                    f"Режим не применён: исправьте обязательные проверки ({errors}).",
                )

        try:
            transaction = self.kvnctl.STATE_STORE.update(mutate, expected_revision=revision)
        except self.StateRevisionConflict as exc:
            raise ControlError("revision_conflict", str(exc)) from exc
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc
        if not transaction.changed:
            return {
                "changed": False,
                "revision": transaction.after_revision,
                "diagnosis": diagnosis,
                "status": self.mtproto_status(),
            }
        try:
            render_result = self.kvnctl.render_all(transaction.state)
            apply_report = self.kvnctl.restart_services(
                render_result,
                before_state=transaction.before_state,
                after_state=transaction.state,
            )
        except Exception as exc:
            raise ControlError(
                "apply_degraded",
                "Источник правды сохранён, но MTProto применён не полностью. Выполните reconcile.",
            ) from exc
        return {
            "changed": True,
            "revision": self.state_revision(transaction.state),
            "diagnosis": diagnosis,
            "plan": render_result.to_dict(),
            "apply": apply_report,
            "status": self.mtproto_status(),
        }

    def _sni_route_summary(self, state: dict, system: str) -> dict:
        route = self.kvnctl.ensure_sni_route(state, system)
        return {
            "system": system,
            "label": self.kvnctl.SYSTEM_LABELS.get(system, system),
            "default": route.get("default", ""),
            "dest": route.get("dest", ""),
            "aliases": list(route.get("aliases", [])),
            "choices": self.kvnctl.route_sni_choices(state, system),
            "user_selectable": system in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS,
        }

    def apply_sni_route(self, params: dict) -> dict:
        action = params.get("action")
        revision = params.get("revision")
        system = params.get("system")
        sni = params.get("sni")
        if action not in {"set-default", "add-alias", "remove-alias"}:
            raise ControlError("invalid_action", "Операция SNI не разрешена.")
        if not isinstance(revision, str) or len(revision) != 64:
            raise ControlError("invalid_revision", "Некорректная ревизия состояния.")
        if system not in self.kvnctl.SNI_ROUTE_SYSTEMS:
            raise ControlError("validation_error", "Неизвестный сервис SNI.")
        if not isinstance(sni, str) or not sni.strip():
            raise ControlError("validation_error", "SNI не задан.")
        sni = self.kvnctl.validate_sni_domain(sni)

        def mutate(state: dict) -> None:
            route = self.kvnctl.ensure_sni_route(state, system)
            aliases = route.setdefault("aliases", [])
            if action == "set-default":
                route["default"] = sni
                if sni not in aliases:
                    aliases.insert(0, sni)
            elif action == "add-alias":
                if sni not in aliases:
                    aliases.append(sni)
            elif action == "remove-alias":
                if sni == route.get("default"):
                    raise ControlError("validation_error", "Default SNI нельзя удалить из aliases.")
                for user in state.get("users", []):
                    if user.get("sni_overrides", {}).get(system) == sni:
                        raise ControlError("validation_error", "SNI используется пользователем; сначала выберите другой SNI.")
                route["aliases"] = [alias for alias in aliases if alias != sni]
            self.kvnctl.prepare_state(state)

        try:
            transaction = self.kvnctl.STATE_STORE.update(mutate, expected_revision=revision)
        except self.StateRevisionConflict as exc:
            raise ControlError("revision_conflict", str(exc)) from exc
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc
        if not transaction.changed:
            return {
                "changed": False,
                "revision": transaction.after_revision,
                "plan": {"changed": False, "changed_paths": [], "services": {}},
                "routes": self.sni_routes()["routes"],
            }
        try:
            render_result = self.kvnctl.render_all(transaction.state)
            apply_report = self.kvnctl.restart_services(
                render_result,
                before_state=transaction.before_state,
                after_state=transaction.state,
            )
        except Exception as exc:
            raise ControlError(
                "apply_degraded",
                "Источник правды сохранён, но применение SNI не завершено. Выполните reconcile.",
            ) from exc
        return {
            "changed": True,
            "revision": self.state_revision(transaction.state),
            "plan": render_result.to_dict(),
            "apply": apply_report,
            "routes": {
                route_system: self._sni_route_summary(transaction.state, route_system)
                for route_system in self.kvnctl.SNI_ROUTE_SYSTEMS
            },
        }

    def apply_protocol(self, params: dict) -> dict:
        """Применяет одну строго типизированную настройку протокола."""
        if set(params) != {"action", "system", "mode", "revision"}:
            raise ControlError("invalid_params", "Редактор протокола принимает только mode и revision.")
        if params.get("action") != "set-xhttp-mode" or params.get("system") != "reality-xhttp":
            raise ControlError("invalid_action", "Операция протокола не разрешена.")
        mode = params.get("mode")
        if mode not in {"stream-one", "stream-up", "packet-up"}:
            raise ControlError("validation_error", "Режим XHTTP не разрешён.")
        revision = params.get("revision")
        if not isinstance(revision, str) or len(revision) != 64:
            raise ControlError("invalid_revision", "Некорректная ревизия состояния.")

        def mutate(state: dict) -> None:
            xray = state.setdefault("xray", {})
            if not isinstance(xray, dict):
                raise ControlError("validation_error", "Секция Xray повреждена.")
            xray["xhttp_mode"] = mode
            self.kvnctl.prepare_state(state)

        try:
            transaction = self.kvnctl.STATE_STORE.update(mutate, expected_revision=revision)
        except self.StateRevisionConflict as exc:
            raise ControlError("revision_conflict", str(exc)) from exc
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc
        if not transaction.changed:
            return {
                "changed": False, "revision": transaction.after_revision,
                "plan": {"changed": False, "changed_paths": [], "services": {}},
                "apply": {"outcome": "no-op", "reconcile_required": False, "warnings": [], "fallbacks": []},
                "protocol": {"system": "reality-xhttp", "xhttp_mode": mode},
            }

        try:
            render_result = self.kvnctl.render_all(transaction.state)
            apply_report = self.kvnctl.restart_services(
                render_result,
                before_state=transaction.before_state,
                after_state=transaction.state,
            )
            plan = render_result.to_dict()
        except Exception:
            plan = {"changed": True, "changed_paths": [], "services": {}}
            apply_report = {
                "outcome": "failed", "reconcile_required": True,
                "warnings": ["Desired state сохранён, но runtime не применён. Выполните reconcile."],
                "fallbacks": [], "failed": ["xray"],
            }
        return {
            "changed": True,
            "revision": transaction.after_revision,
            "plan": plan,
            "apply": apply_report,
            "protocol": {"system": "reality-xhttp", "xhttp_mode": mode},
        }

    def service_preferences(self) -> dict[str, bool]:
        state = self.kvnctl.STATE_STORE.load()
        return self.kvnctl.configured_service_preferences(state)

    def effective_service_preferences(self) -> dict[str, bool]:
        """Единый effective lifecycle-план для host-agent и портала."""
        state = self.kvnctl.STATE_STORE.load()
        return dict(self.kvnctl.effective_service_plan(state).effective_preferences)

    def observability_config(self) -> dict:
        state = self.kvnctl.STATE_STORE.load()
        portal = state.get("portal", {})
        return {"hysteria_secret": str(portal.get("hysteria_secret", ""))}

    def portal_performance(self) -> dict:
        """Возвращает безопасные настройки нагрузки портала и ревизию state."""
        state = self.kvnctl.STATE_STORE.load()
        revision = self.state_revision(state)
        portal = copy.deepcopy(state.get("portal", {}))
        try:
            performance = self.kvnctl.portal_performance_config(portal)
        except SystemExit as exc:
            raise ControlError("invalid_state", str(exc)) from exc
        endpoint = {"host": "", "host_kind": "domain", "public_ready": False, "allow_self_signed_ip": False}
        if isinstance(portal, dict) and portal.get("enabled") and portal.get("domain"):
            try:
                host = self.kvnctl.validate_portal_host(str(portal["domain"]))
                endpoint = {
                    "host": host,
                    "host_kind": self.kvnctl.portal_host_kind(host),
                    "public_ready": self.kvnctl.portal_public_ready(copy.deepcopy(state)),
                    "allow_self_signed_ip": bool(portal.get("allow_self_signed_ip", False)),
                }
            except SystemExit:
                pass
        return {
            "revision": revision,
            "profile": performance["profile"],
            "endpoint": endpoint,
            "features": {
                "monitoring": performance["monitoring"],
                "background_refresh": performance["background_refresh"],
            },
        }

    def update_portal_performance(self, params: dict) -> dict:
        """Меняет профиль нагрузки без render/restart VPN-сервисов."""
        expected = {"revision", "profile", "monitoring", "background_refresh"}
        if set(params) != expected:
            raise ControlError("invalid_params", "Некорректная схема настроек нагрузки портала.")
        revision = params.get("revision")
        profile = params.get("profile")
        if not isinstance(revision, str) or len(revision) != 64:
            raise ControlError("invalid_revision", "Некорректная ревизия состояния.")
        if profile not in {"standard", "light", "custom"}:
            raise ControlError("validation_error", "Профиль портала не разрешён.")
        for name in ("monitoring", "background_refresh"):
            if not isinstance(params.get(name), bool):
                raise ControlError("validation_error", f"{name} должен быть true или false.")

        def mutate(state: dict) -> None:
            portal = state.setdefault("portal", {})
            if not isinstance(portal, dict):
                raise ControlError("invalid_state", "Секция portal повреждена.")
            if profile in self.kvnctl.PORTAL_PERFORMANCE_PROFILES:
                features = dict(self.kvnctl.PORTAL_PERFORMANCE_PROFILES[profile])
            else:
                features = {
                    "monitoring": params["monitoring"],
                    "background_refresh": params["background_refresh"],
                }
            portal["performance_profile"] = profile
            portal["features"] = features
            self.kvnctl.portal_performance_config(portal)

        try:
            transaction = self.kvnctl.STATE_STORE.update(mutate, expected_revision=revision)
        except self.StateRevisionConflict as exc:
            raise ControlError("revision_conflict", str(exc)) from exc
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc
        self.kvnctl.sync_portal_runtime_state(transaction.state)
        portal = copy.deepcopy(transaction.state.get("portal", {}))
        performance = self.kvnctl.portal_performance_config(portal)
        before_portal = copy.deepcopy(transaction.before_state.get("portal", {}))
        before = self.kvnctl.portal_performance_config(before_portal)
        return {
            "changed": transaction.changed,
            "revision": transaction.after_revision,
            "profile": performance["profile"],
            "endpoint": self.portal_performance()["endpoint"],
            "changed_features": [
                name for name in ("monitoring", "background_refresh")
                if before[name] != performance[name]
            ],
            "features": {
                "monitoring": performance["monitoring"],
                "background_refresh": performance["background_refresh"],
            },
        }

    def client_export_settings(self, source_state: dict | None = None) -> dict:
        """Возвращает только безопасную политику endpoint и IP readiness."""
        state = (
            copy.deepcopy(source_state)
            if source_state is not None
            else self.kvnctl.STATE_STORE.load()
        )
        revision = self.state_revision(state)
        try:
            policy = self.kvnctl.ClientExportPolicy.from_state(state)
            subscription = self.kvnctl.sub_config(state)
        except (self.kvnctl.ClientExportValidationError, SystemExit) as exc:
            raise ControlError("invalid_state", str(exc)) from exc
        public_ip = policy.public_ip
        route_ready = bool(
            public_ip
            and subscription.get("enabled", True)
            and int(subscription.get("port", self.kvnctl.DEFAULT_SUB_PORT)) > 0
        )
        certificate_sans = self.kvnctl.certificate_sans(
            self.kvnctl.SITE_CERTS_DIR / "server.crt",
        )
        certificate_ready = bool(public_ip and public_ip in certificate_sans)
        return {
            "revision": revision,
            "address_mode": policy.address_mode,
            "public_ip": public_ip,
            "include_alternate": policy.include_alternate,
            "server_address": str(state.get("server", "") or ""),
            "effective_address": self.kvnctl.client_connection_host(state, policy),
            "ip_bundle_ready": bool(public_ip),
            "subscription": {
                "port": int(
                    subscription.get("port", self.kvnctl.DEFAULT_SUB_PORT),
                ),
                "route_ready": route_ready,
                "certificate_ready": certificate_ready,
                "ready": route_ready and certificate_ready,
                "certificate_target": "site",
            },
        }

    def update_client_export(self, params: dict) -> dict:
        """Сохраняет default endpoint и обновляет generated client artifacts."""
        expected = {
            "revision", "address_mode", "public_ip", "include_alternate",
        }
        if set(params) != expected:
            raise ControlError(
                "invalid_params",
                "Некорректная схема настроек клиентского экспорта.",
            )
        revision = params.get("revision")
        address_mode = params.get("address_mode")
        public_ip = params.get("public_ip")
        include_alternate = params.get("include_alternate")
        if not isinstance(revision, str) or len(revision) != 64:
            raise ControlError("invalid_revision", "Некорректная ревизия состояния.")
        if address_mode not in {"server", "public-ip"}:
            raise ControlError("validation_error", "Режим адреса не разрешён.")
        if not isinstance(public_ip, str) or not isinstance(include_alternate, bool):
            raise ControlError("validation_error", "Некорректные типы настроек экспорта.")
        try:
            policy = self.kvnctl.ClientExportPolicy.from_state({
                "client_export": {
                    "address_mode": address_mode,
                    "public_ip": public_ip,
                    "include_alternate": include_alternate,
                },
            })
        except self.kvnctl.ClientExportValidationError as exc:
            raise ControlError("validation_error", str(exc)) from exc

        def mutate(state: dict) -> None:
            state["client_export"] = policy.as_state()

        try:
            transaction = self.kvnctl.STATE_STORE.update(
                mutate,
                expected_revision=revision,
            )
        except self.StateRevisionConflict as exc:
            raise ControlError("revision_conflict", str(exc)) from exc

        if transaction.changed:
            try:
                render_result = self.kvnctl.render_all(transaction.state)
                apply_report = self.kvnctl.restart_services(
                    render_result,
                    before_state=transaction.before_state,
                    after_state=transaction.state,
                )
                plan = render_result.to_dict()
            except Exception:
                plan = {
                    "changed": True, "changed_paths": [],
                    "services": {},
                }
                apply_report = {
                    "outcome": "failed",
                    "reconcile_required": True,
                    "warnings": [
                        "Настройки сохранены, но клиентские файлы применены "
                        "не полностью. Выполните reconcile.",
                    ],
                    "fallbacks": [],
                    "failed": ["client-export"],
                }
        else:
            plan = {"changed": False, "changed_paths": [], "services": {}}
            apply_report = {
                "outcome": "no-op", "reconcile_required": False,
                "warnings": [], "fallbacks": [], "failed": [],
            }
        return {
            "changed": transaction.changed,
            "revision": transaction.after_revision,
            "settings": self.client_export_settings(transaction.state),
            "plan": plan,
            "apply": apply_report,
        }

    def update_portal_credentials(self, params: dict) -> dict:
        password_hash = params.get("password_hash", "")
        if not isinstance(password_hash, str) or not re.fullmatch(
            r"scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+",
            password_hash,
        ):
            raise ControlError("validation_error", "Некорректный хэш пароля портала.")

        def mutate(state: dict) -> None:
            portal = state.setdefault("portal", {})
            if not isinstance(portal, dict):
                raise ControlError("invalid_state", "Секция portal повреждена.")
            portal["password_hash"] = password_hash

        transaction = self.kvnctl.STATE_STORE.update(mutate)
        self.kvnctl.sync_portal_runtime_state(transaction.state)
        return {
            "changed": transaction.changed,
            "revision": transaction.after_revision,
        }

    def portal_custom_gateway(self) -> bool:
        state = self.kvnctl.STATE_STORE.load()
        cfg = self.kvnctl.portal_config(state)
        return bool(cfg.get("enabled") and cfg.get("port") != 443)

    def certificate_status(self) -> dict:
        state = self.kvnctl.STATE_STORE.load()
        items = []
        for target in ["site", "ocserv"]:
            domains = self.kvnctl.letsencrypt_target_domains(state, target)
            path = self.kvnctl.cert_target_dir(target) / "server.crt"
            not_before, not_after = self.kvnctl.certificate_dates(path)
            sans = self.kvnctl.certificate_sans(path)
            expires_days = None
            if not_after:
                try:
                    expires = datetime.datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    expires_days = (expires - datetime.datetime.now(datetime.timezone.utc)).days
                    not_after_display = expires.strftime("%d.%m.%Y %H:%M UTC")
                except ValueError:
                    expires_days = None
                    not_after_display = not_after
            else:
                not_after_display = ""
            items.append({
                "target": target,
                "domains": domains,
                "source": self.kvnctl.certificate_source(path),
                "issuer": self.kvnctl.certificate_issuer(path),
                "not_before": not_before,
                "not_after": not_after,
                "not_after_display": not_after_display,
                "sans": sans,
                "san_mismatch": bool(domains and not set(domains).issubset(set(sans))),
                "expires_days": expires_days,
                "expiry": "unknown" if expires_days is None else (
                    "expired" if expires_days < 0 else "critical" if expires_days < 7
                    else "warning" if expires_days < 30 else "ok"
                ),
            })
        return {"certificates": items}

    def set_service_enabled(self, service: str, enabled: bool) -> dict:
        def mutate(state: dict) -> None:
            services = state.setdefault("services", {})
            if not isinstance(services, dict):
                raise ControlError("invalid_state", "Секция services повреждена.")
            settings = services.setdefault(service, {})
            if not isinstance(settings, dict):
                settings = {}
                services[service] = settings
            settings["enabled"] = bool(enabled)

        result = self.kvnctl.STATE_STORE.update(mutate)
        return {"changed": result.changed, "revision": result.after_revision, "enabled": bool(enabled)}

    def get_user(self, name: str) -> dict:
        state = self.kvnctl.STATE_STORE.load()
        user = self.kvnctl.find_user(state, name)
        if user is None:
            raise ControlError("not_found", "Пользователь не найден.")
        return {
            "revision": self.state_revision(state),
            "user": self._safe_user(user),
            "client_export": self.client_export_settings(state),
        }

    def user_activity_subject(self, name: str) -> dict:
        """Внутренняя привязка runtime-метрик без выдачи пользовательских секретов."""
        if not isinstance(name, str):
            raise ControlError("invalid_user", "Некорректное имя пользователя.")
        try:
            self.kvnctl.validate_name(name)
        except SystemExit as exc:
            raise ControlError("invalid_user", str(exc)) from exc
        state = self.kvnctl.STATE_STORE.load()
        user = self.kvnctl.find_user(state, name)
        if user is None:
            raise ControlError("not_found", "Пользователь не найден.")
        services = dict(self.kvnctl.effective_service_plan(state).effective_preferences)
        return {
            "name": user["name"],
            "enabled": bool(user.get("enabled", True)),
            "systems": self.kvnctl.user_systems(user),
            "services": services,
            "amneziawg_public_key": str(user.get("amneziawg", {}).get("public_key", "")),
            "wireguard_public_key": str(user.get("wireguard", {}).get("public_key", "")),
        }

    @classmethod
    def _file_metadata(cls, path: Path) -> dict:
        labels = {
            "amneziawg.png": ("amneziawg-qr", "QR для AmneziaWG app"),
            "amneziawg.conf": ("amneziawg-config", "Конфигурация для AmneziaWG app"),
            "wireguard.png": ("wireguard-qr", "QR стандартного WireGuard"),
            "wireguard.conf": ("wireguard-config", "Конфигурация стандартного WireGuard"),
            "happ-subscription.png": ("happ-qr", "QR подписки HAPP"),
            "happ-subscription.txt": ("happ-url", "Ссылка подписки HAPP"),
            "karing-subscription.png": ("karing-qr", "QR подписки Karing"),
            "karing-subscription.txt": ("karing-url", "Ссылка подписки Karing"),
            "karing-wireguard.png": ("karing-wireguard-qr", "QR Karing: стандартный WireGuard"),
            "karing-wireguard.txt": ("karing-wireguard-url", "Ссылка Karing: стандартный WireGuard"),
            "karing-wireguard.yaml": ("karing-wireguard-config", "Clash-профиль WireGuard для Karing"),
            "telemt.png": ("telemt-qr", "QR Telemt"),
            "telemt.txt": ("telemt-config", "Параметры Telemt"),
            "mtg.png": ("mtg-qr", "QR mtg"),
            "mtg.txt": ("mtg-config", "Параметры mtg"),
            "telegram-proxy.txt": ("telegram-proxy", "Telegram proxy"),
            "openconnect.txt": ("openconnect-config", "Параметры OpenConnect"),
        }
        kind, label = labels.get(path.name, ("file", path.name))
        return {
            "name": path.name,
            "kind": kind,
            "label": label,
            "size": path.stat().st_size,
            "content_type": cls._content_type(path.suffix.lower()),
            "can_preview": path.suffix.lower() in cls.TEXT_SUFFIXES or path.suffix.lower() == ".png",
            "can_download": True,
        }

    @staticmethod
    def _content_type(suffix: str) -> str:
        return {
            ".png": "image/png",
            ".json": "application/json; charset=utf-8",
            ".yaml": "application/yaml; charset=utf-8",
            ".toml": "application/toml; charset=utf-8",
        }.get(suffix, "text/plain; charset=utf-8")

    def user_files(self, name: str) -> list[dict]:
        try:
            self.kvnctl.validate_name(name)
        except SystemExit as exc:
            raise ControlError("invalid_user", str(exc)) from exc
        user_dir = (self.root / "clients" / name).resolve()
        clients_root = (self.root / "clients").resolve()
        if user_dir.parent != clients_root or not user_dir.is_dir():
            return []
        paths = sorted(
            (path for path in user_dir.iterdir()), key=lambda item: item.name
        )
        return [
            self._file_metadata(path) for path in paths
            if path.is_file()
            and not path.is_symlink()
            and path.suffix.lower() in self.DOWNLOAD_SUFFIXES
            and path.stat().st_size <= self.MAX_DOWNLOAD_BYTES
        ]

    def read_user_file(self, name: str, filename: str) -> dict:
        if not isinstance(filename, str) or not self.SAFE_FILENAME_RE.fullmatch(filename):
            raise ControlError("invalid_file", "Недопустимое имя файла.")
        if Path(filename).suffix.lower() not in self.DOWNLOAD_SUFFIXES:
            raise ControlError("invalid_file", "Тип файла не разрешён.")
        try:
            self.kvnctl.validate_name(name)
        except SystemExit as exc:
            raise ControlError("invalid_user", str(exc)) from exc
        state = self.kvnctl.STATE_STORE.load()
        if self.kvnctl.find_user(state, name) is None:
            raise ControlError("not_found", "Пользователь не найден.")
        user_dir = (self.root / "clients" / name).resolve()
        path = (user_dir / filename).resolve()
        if path.parent != user_dir or path.is_symlink() or not path.is_file():
            raise ControlError("not_found", "Файл не найден.")
        content = path.read_bytes()
        if len(content) > self.MAX_DOWNLOAD_BYTES:
            raise ControlError("file_too_large", "Файл превышает допустимый размер.")
        return {
            "filename": filename,
            "content_type": self._content_type(path.suffix.lower()),
            "kind": self._file_metadata(path)["kind"],
            "content_base64": base64.b64encode(content).decode("ascii"),
        }

    @staticmethod
    def _json_artifact(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")

    def _user_export_artifacts(
        self,
        state: dict,
        user: dict,
        public_key: str,
    ) -> dict[str, bytes]:
        """Строит только известные client artifacts, не читая generated dirs."""
        systems = self.kvnctl.user_systems(user)
        artifacts: dict[str, bytes] = {}

        def text(name: str, value: str) -> None:
            artifacts[name] = value.encode("utf-8")

        def json_file(name: str, value: object) -> None:
            artifacts[name] = self._json_artifact(value)

        if "tls" in systems:
            json_file(
                "xray-vless-tls.json",
                self.kvnctl.client_json_tls(state, user),
            )
            json_file(
                "xray-vless-tls-direct.json",
                self.kvnctl.client_json_tls(
                    state,
                    user,
                    port=self.kvnctl.DIRECT_PORTS["tls"],
                    remarks_suffix="VLESS TLS Vision direct",
                ),
            )
        if "reality-xhttp" in systems:
            json_file(
                "xray-reality.json",
                self.kvnctl.client_json_reality(state, user, public_key),
            )
            json_file(
                "xray-reality-direct.json",
                self.kvnctl.client_json_reality(
                    state,
                    user,
                    public_key,
                    port=self.kvnctl.DIRECT_PORTS["reality-xhttp"],
                    remarks_suffix="Reality xHTTP direct",
                ),
            )
        if "reality-tcp" in systems:
            json_file(
                "xray-reality-tcp.json",
                self.kvnctl.client_json_reality_tcp(state, user, public_key),
            )
            json_file(
                "xray-reality-tcp-direct.json",
                self.kvnctl.client_json_reality_tcp(
                    state,
                    user,
                    public_key,
                    port=self.kvnctl.DIRECT_PORTS["reality-tcp"],
                    remarks_suffix="Reality TCP Vision direct",
                ),
            )
        if "hysteria" in systems:
            text("hysteria2.yaml", self.kvnctl.hysteria_client_yaml(state, user))
            json_file(
                "xray-hysteria2.json",
                self.kvnctl.xray_hysteria2_json(state, user),
            )
        if "amneziawg" in systems:
            text("amneziawg.conf", self.kvnctl.amneziawg_client_conf(state, user))
        if "wireguard" in systems:
            text("wireguard.conf", self.kvnctl.wireguard_client_conf(state, user))
            text(
                "karing-wireguard.yaml",
                self.kvnctl.karing_wireguard_yaml(state, user),
            )
            text(
                "karing-wireguard.txt",
                self.kvnctl.karing_wireguard_sub_url(state, user) + "\n",
            )
        if "telemt" in systems:
            text("telemt.txt", self.kvnctl.telemt_client_text(state, user))
        if "mtg" in systems:
            text("mtg.txt", self.kvnctl.mtg_client_text(state))
        if "telemt" in systems or "mtg" in systems:
            text(
                "telegram-proxy.txt",
                self.kvnctl.telegram_proxy_text(state, user),
            )
        if "ocserv" in systems:
            text(
                "openconnect.txt",
                self.kvnctl.openconnect_client_text(state, user) + "\n",
            )

        json_file(
            "subscription.json",
            self.kvnctl.singbox_subscription(state, user, public_key),
        )
        text(
            "subscription.txt",
            self.kvnctl.subscription_txt(state, user, public_key),
        )
        text(
            "subscription-raw.txt",
            self.kvnctl.subscription_raw_txt(state, user, public_key),
        )
        text(
            "subscription-raw-all.txt",
            self.kvnctl.subscription_raw_all_txt(state, user, public_key),
        )
        text(
            "happ-subscription.txt",
            self.kvnctl.happ_sub_url(state, user) + "\n",
        )
        text(
            "karing-subscription.txt",
            self.kvnctl.karing_sub_url(state, user) + "\n",
        )
        text(
            "links.txt",
            self.kvnctl.user_links_text(state, user, public_key),
        )
        return artifacts

    def user_export(self, name: str, address_mode: str) -> dict:
        """Формирует ZIP/text только в памяти и возвращает их host-agent."""
        if not isinstance(address_mode, str) or address_mode not in {
            "server",
            "public-ip",
        }:
            raise ControlError("invalid_mode", "Режим адреса экспорта не разрешён.")
        try:
            self.kvnctl.validate_name(name)
        except SystemExit as exc:
            raise ControlError("invalid_user", str(exc)) from exc

        source_state = self.kvnctl.STATE_STORE.load()
        source_user = self.kvnctl.find_user(source_state, name)
        if source_user is None:
            raise ControlError("not_found", "Пользователь не найден.")
        try:
            current_policy = self.kvnctl.ClientExportPolicy.from_state(source_state)
            public_ip = (
                current_policy.public_ip
                if address_mode == "public-ip"
                else ""
            )
            state = self.kvnctl.with_client_export_policy(
                source_state,
                address_mode=address_mode,
                public_ip=public_ip,
            )
        except self.kvnctl.ClientExportValidationError as exc:
            raise ControlError("invalid_mode", str(exc)) from exc

        user = self.kvnctl.find_user(state, name)
        public_key, _changed = self.kvnctl.ensure_reality_public_key(
            state,
            "reality",
        )
        artifacts = self._user_export_artifacts(state, user, public_key)
        send_text = self.kvnctl.user_send_text(state, user, public_key)
        try:
            bundle = build_user_export_bundle(
                username=user["name"],
                address_mode=address_mode,
                build_id=os.environ.get("KVN_BUILD_ID", "source"),
                send_text=send_text,
                artifacts=artifacts,
            )
        except ExportBundleError as exc:
            raise ControlError(exc.code, str(exc)) from exc

        basename = f"kvn-{user['name']}-{address_mode}"
        return {
            "address_mode": address_mode,
            "archive_filename": basename + ".zip",
            "archive_content_type": "application/zip",
            "archive_size": len(bundle.archive),
            "archive_base64": base64.b64encode(bundle.archive).decode("ascii"),
            "text_filename": basename + ".txt",
            "text_content_type": "text/plain; charset=utf-8",
            "text_size": len(bundle.text),
            "text_base64": base64.b64encode(bundle.text).decode("ascii"),
            "manifest": bundle.manifest,
        }

    def apply_user(self, params: dict) -> dict:
        action = params.get("action")
        revision = params.get("revision")
        fields = params.get("fields", {})
        allowed = {"create", "update", "set-enabled", "delete", "rotate", "rotate-subscription", "reset-ocserv"}
        if action not in allowed:
            raise ControlError("invalid_action", "Операция пользователя не разрешена.")
        if not isinstance(revision, str) or len(revision) != 64:
            raise ControlError("invalid_revision", "Некорректная ревизия состояния.")
        if not isinstance(fields, dict):
            raise ControlError("invalid_fields", "Поля операции должны быть объектом.")
        target_name = fields.get("name", "")

        def mutate(state: dict) -> None:
            nonlocal target_name
            if action == "create":
                target_name = self._create_user(state, fields)
            else:
                user = self.kvnctl.find_user(state, target_name) if isinstance(target_name, str) else None
                if user is None:
                    raise ControlError("not_found", "Пользователь не найден.")
                if action == "update":
                    target_name = self._update_user(state, user, fields)
                elif action == "set-enabled":
                    user["enabled"] = bool(fields.get("enabled"))
                elif action == "delete":
                    state["users"] = [item for item in state["users"] if item is not user]
                elif action == "rotate":
                    self._rotate_user(user)
                elif action == "rotate-subscription":
                    user["sub_token"] = self.kvnctl.random_hex32()
                elif action == "reset-ocserv":
                    user["ocserv_password"] = self.kvnctl.random_password()
            # Все автоматически создаваемые ключи/defaults входят в ту же atomic revision.
            self.kvnctl.prepare_state(state)

        try:
            transaction = self.kvnctl.STATE_STORE.update(mutate, expected_revision=revision)
        except self.StateRevisionConflict as exc:
            raise ControlError("revision_conflict", str(exc)) from exc
        except SystemExit as exc:
            raise ControlError("validation_error", str(exc)) from exc
        if not transaction.changed:
            return {
                "changed": False,
                "revision": transaction.after_revision,
                "plan": {"changed": False, "changed_paths": [], "services": {}},
                "user": self._safe_user(self.kvnctl.find_user(transaction.state, target_name)),
                "secrets": {},
            }
        try:
            render_result = self.kvnctl.render_all(transaction.state)
            force_host_sync = self._user_apply_host_sync_services(
                action,
                fields,
                target_name,
                transaction.before_state,
                transaction.state,
            )
            apply_report = self.kvnctl.restart_services(
                render_result,
                before_state=transaction.before_state,
                after_state=transaction.state,
                force_host_sync_services=force_host_sync,
            )
        except Exception as exc:
            raise ControlError(
                "apply_degraded",
                "Источник правды сохранён, но применение не завершено. Выполните reconcile.",
            ) from exc
        current_user = self.kvnctl.find_user(transaction.state, target_name)
        secrets_result = self._returned_secrets(current_user, action)
        return {
            "changed": True,
            "revision": self.state_revision(transaction.state),
            "plan": render_result.to_dict(),
            "apply": apply_report,
            "user": self._safe_user(current_user),
            "secrets": secrets_result,
        }

    def _user_apply_host_sync_services(
        self,
        action: str,
        fields: dict,
        target_name: str,
        before_state: dict,
        after_state: dict,
    ) -> set[str]:
        """Возвращает host VPN-сервисы, которые надо синхронизировать после операции пользователя."""
        if action in {"rotate-subscription", "reset-ocserv"}:
            return set()
        if action == "update":
            relevant_fields = {"systems", "enabled", "new_name"}
            if not any(key in fields for key in relevant_fields):
                return set()

        names = {
            name
            for name in (fields.get("name"), fields.get("new_name"), target_name)
            if isinstance(name, str) and name
        }
        services: set[str] = set()
        for state in (before_state, after_state):
            for user in state.get("users", []):
                if user.get("name") not in names:
                    continue
                systems = self.kvnctl.user_systems(user)
                for service in ("amneziawg", "wireguard"):
                    if service in systems:
                        services.add(service)
        return services

    def _state_host_sync_services(self, state: dict) -> set[str]:
        services: set[str] = set()
        for user in state.get("users", []):
            systems = self.kvnctl.user_systems(user)
            for service in ("amneziawg", "wireguard"):
                if service in systems:
                    services.add(service)
        return services

    def reconcile_state(self) -> dict:
        """Повторно применяет текущий desired state без пользовательской мутации."""
        def prepare(state: dict) -> None:
            self.kvnctl.prepare_state(state)

        transaction = self.kvnctl.STATE_STORE.update(prepare)
        render_result = self.kvnctl.render_all(transaction.state)
        apply_report = self.kvnctl.restart_services(
            render_result,
            before_state=transaction.before_state,
            after_state=transaction.state,
            force_host_sync_services=self._state_host_sync_services(transaction.state),
        )
        return {
            "changed": bool(transaction.changed or render_result),
            "revision": transaction.after_revision,
            "plan": render_result.to_dict(),
            "apply": apply_report,
            "user": None,
            "secrets": {},
        }

    def apply_host_service(self, service: str) -> dict:
        """Принудительно применяет host VPN-конфиг из текущего desired state."""
        if service not in {"amneziawg", "wireguard"}:
            raise ControlError("invalid_service", "Принудительное применение доступно только для host VPN-сервисов.")

        def prepare(state: dict) -> None:
            self.kvnctl.prepare_state(state)

        transaction = self.kvnctl.STATE_STORE.update(prepare)
        try:
            render_result = self.kvnctl.render_all(transaction.state)
            apply_report = self.kvnctl.restart_services(
                render_result,
                before_state=transaction.before_state,
                after_state=transaction.state,
                force_host_sync_services={service},
            )
        except Exception as exc:
            raise ControlError(
                "apply_degraded",
                f"Конфигурация {service} сохранена, но не применена. Проверьте host-службу и логи.",
            ) from exc
        return {
            "changed": bool(transaction.changed or render_result),
            "revision": transaction.after_revision,
            "plan": render_result.to_dict(),
            "apply": apply_report,
            "service": service,
        }

    def _systems(self, value) -> list[str]:
        if not isinstance(value, list) or not value:
            raise ControlError("validation_error", "Выберите хотя бы одну систему.")
        return self.kvnctl.parse_systems(",".join(str(item) for item in value))

    def _create_user(self, state: dict, fields: dict) -> str:
        name = fields.get("name", "")
        if not isinstance(name, str):
            raise ControlError("validation_error", "Некорректное имя пользователя.")
        self.kvnctl.validate_name(name)
        self.kvnctl.unique_name(state, name)
        systems = self._systems(fields.get("systems"))
        user = {
            "name": name,
            "uuid": self.kvnctl.validate_uuid(fields["uuid"]) if fields.get("uuid") else str(uuid.uuid4()),
            "hysteria_password": self.kvnctl.validate_hysteria_password(fields["hysteria_password"])
            if fields.get("hysteria_password") else self.kvnctl.random_password(),
            "telemt_secret": self.kvnctl.validate_telemt_secret(fields["telemt_secret"])
            if fields.get("telemt_secret") else self.kvnctl.random_hex32(),
            "ocserv_password": self.kvnctl.validate_ocserv_password(fields["ocserv_password"])
            if fields.get("ocserv_password") else self.kvnctl.random_password(),
            "sub_token": self.kvnctl.random_hex32(),
            "enabled": bool(fields.get("enabled", True)),
            "description": self.kvnctl.validate_description(str(fields.get("description", ""))),
            "device": "",
            "systems": systems,
            "sni_overrides": {},
        }
        device = fields.get("device", "")
        if device:
            if device not in self.kvnctl.ALL_DEVICES:
                raise ControlError("validation_error", "Неизвестный профиль устройства.")
            self.kvnctl.apply_device_profile(user, device, overwrite=True)
        overrides = fields.get("sni_overrides", {})
        if not isinstance(overrides, dict):
            raise ControlError("validation_error", "Некорректные SNI overrides.")
        user["sni_overrides"] = {
            system: self.kvnctl.validate_sni_domain(domain)
            for system, domain in overrides.items()
            if system in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS and system in systems and domain
        }
        state.setdefault("users", []).append(user)
        return name

    def _update_user(self, state: dict, user: dict, fields: dict) -> str:
        name = user["name"]
        new_name = fields.get("new_name", name)
        if not isinstance(new_name, str):
            raise ControlError("validation_error", "Некорректное новое имя.")
        if new_name != name:
            self.kvnctl.validate_name(new_name)
            self.kvnctl.unique_name(state, new_name, exclude=name)
            user["name"] = new_name
            name = new_name
        if "description" in fields:
            user["description"] = self.kvnctl.validate_description(str(fields["description"]))
        if "systems" in fields:
            user["systems"] = self._systems(fields["systems"])
            user["sni_overrides"] = {
                key: value
                for key, value in user.get("sni_overrides", {}).items()
                if key in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS and key in user["systems"]
            }
        if "enabled" in fields:
            user["enabled"] = bool(fields["enabled"])
        if "device" in fields:
            device = fields["device"]
            if device not in [*self.kvnctl.ALL_DEVICES, ""]:
                raise ControlError("validation_error", "Неизвестный профиль устройства.")
            self.kvnctl.apply_device_profile(user, device or "none", overwrite=True)
        if "sni_overrides" in fields:
            overrides = fields["sni_overrides"]
            if not isinstance(overrides, dict):
                raise ControlError("validation_error", "Некорректные SNI overrides.")
            user["sni_overrides"] = {
                system: self.kvnctl.validate_sni_domain(domain)
                for system, domain in overrides.items()
                if system in self.kvnctl.USER_SNI_OVERRIDE_SYSTEMS
                and system in self.kvnctl.user_systems(user)
                and domain
            }
        if fields.get("ocserv_password"):
            user["ocserv_password"] = self.kvnctl.validate_ocserv_password(
                str(fields["ocserv_password"])
            )
        return name

    def _rotate_user(self, user: dict) -> None:
        user["uuid"] = str(uuid.uuid4())
        user["hysteria_password"] = self.kvnctl.random_password()
        user["telemt_secret"] = self.kvnctl.random_hex32()
        user["ocserv_password"] = self.kvnctl.random_password()
        user["sub_token"] = self.kvnctl.random_hex32()
        if "amneziawg" in self.kvnctl.user_systems(user):
            address = user.get("amneziawg", {}).get("address", "")
            user["amneziawg"] = {
                "private_key": self.kvnctl.random_wg_private_key(),
                "preshared_key": base64.b64encode(self.kvnctl.secrets.token_bytes(32)).decode("ascii"),
            }
            if address:
                user["amneziawg"]["address"] = address
        if "wireguard" in self.kvnctl.user_systems(user):
            address = user.get("wireguard", {}).get("address", "")
            user["wireguard"] = {
                "private_key": self.kvnctl.random_wg_private_key(),
                "preshared_key": base64.b64encode(self.kvnctl.secrets.token_bytes(32)).decode("ascii"),
            }
            if address:
                user["wireguard"]["address"] = address

    def _returned_secrets(self, user: dict | None, action: str) -> dict:
        if user is None or action not in {"create", "rotate", "rotate-subscription", "reset-ocserv"}:
            return {}
        key_map = {
            "create": ["uuid", "hysteria_password", "telemt_secret", "ocserv_password", "sub_token"],
            "rotate": ["uuid", "hysteria_password", "telemt_secret", "ocserv_password", "sub_token"],
            "rotate-subscription": ["sub_token"],
            "reset-ocserv": ["ocserv_password"],
        }
        result = {key: user.get(key, "") for key in key_map[action]}
        if action in {"create", "rotate"} and "amneziawg" in self.kvnctl.user_systems(user):
            result["amneziawg_private_key"] = user.get("amneziawg", {}).get("private_key", "")
        if action in {"create", "rotate"} and "wireguard" in self.kvnctl.user_systems(user):
            result["wireguard_private_key"] = user.get("wireguard", {}).get("private_key", "")
        return result
