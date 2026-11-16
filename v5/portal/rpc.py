"""Клиент разрешённых операций по локальному Unix-сокету."""

import json
from pathlib import Path
import re
import socket

from v5.core.contracts import CORE_API_VERSION


class AgentUnavailable(Exception):
    pass


class AgentRejected(AgentUnavailable):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class HostClient:
    def __init__(self, socket_path: Path, timeout: float = 2):
        self.socket_path = socket_path
        self.timeout = timeout

    def status(self) -> dict:
        return self._request("host.status", {})

    def tls_status(self) -> dict:
        return self._request("tls.status", {})

    def tls_issue(self, name: str, mode: str, email: str) -> dict:
        return self._request("tls.issue", {"name": name, "mode": mode, "email": email})

    def tls_import(self, name: str, chain: bytes, key: bytes) -> dict:
        return self._request("tls.import", {"name": name, "chain_size": len(chain), "key_size": len(key)},
                             body=chain + key, timeout=8)

    def tls_diagnose(self, name: str) -> dict:
        return self._request("tls.diagnose", {"name": name})

    def tls_prepare(self) -> dict:
        return self._request("tls.prepare", {})

    def site_status(self) -> dict:
        return self._request("site.status", {})

    def site_publish(self, html: bytes) -> dict:
        return self._request("site.publish", {"size": len(html)}, body=html)

    def site_reset(self) -> dict:
        return self._request("site.reset", {})

    def package_status(self) -> dict:
        return self._request("package.status", {}, timeout=6)

    def journal_recent(self, source: str) -> dict:
        return self._request("journal.recent", {"source": source})

    def observe_live(self, session_id: str | None = None) -> dict:
        return self._request("observe.live", {"session": session_id} if session_id else {}, timeout=9)

    def observe_history(self, hours: int) -> dict:
        return self._request("observe.history", {"hours": hours}, timeout=8)

    def _request(self, method: str, params: dict, *, body: bytes | None = None,
                 source=None, timeout: float | None = None) -> dict:
        request = {"version": CORE_API_VERSION, "method": method, "params": params}
        maximum = (512 * 1024 if method in {"users.profiles", "users.subscription"}
                   else 2 * 1024 * 1024 if method == "observe.history"
                   else 256 * 1024 if method == "observe.live"
                   else 32768 if method in {"tls.status", "users.list", "users.config", "lifecycle.plan"} else 8192)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout if timeout is None else timeout)
                connection.connect(str(self.socket_path))
                connection.sendall(json.dumps(request).encode() + b"\n")
                send_failed = False
                if source is not None:
                    try:
                        while chunk := source.read(128 * 1024):
                            connection.sendall(chunk)
                    except BrokenPipeError:
                        # При раннем отказе служба могла уже отправить код ошибки.
                        send_failed = True
                elif body is not None:
                    connection.sendall(body)
                if body is not None or method.startswith(("package.", "lifecycle.", "users.", "core.")):
                    try:
                        connection.shutdown(socket.SHUT_WR)
                    except OSError:
                        if not send_failed:
                            raise
                with connection.makefile("rb") as stream:
                    line = stream.readline(maximum + 1)
                if len(line) > maximum or not line.endswith(b"\n"):
                    raise AgentUnavailable
                response = json.loads(line)
            if not isinstance(response, dict):
                raise AgentUnavailable
            if response.get("ok") is False:
                error = response.get("error")
                if error in ("tls_busy", "tls_unavailable", "site_invalid", "site_unavailable", "invalid_request") or (
                    method.startswith(("package.", "lifecycle.", "users.", "core.")) and isinstance(error, str)
                    and re.fullmatch("[a-z0-9_]{1,64}", error)
                ):
                    raise AgentRejected(error)
            if response.get("ok") is not True or not isinstance(response.get("result"), dict):
                raise AgentUnavailable
            return response["result"]
        except (OSError, ValueError, RecursionError) as exc:
            raise AgentUnavailable from exc


class PackageClient(HostClient):
    def status(self) -> dict:
        return self._request("package.status", {}, timeout=6)

    def upload(self, stream, size: int) -> dict:
        return self._request("package.upload", {"size": size}, source=stream)

    def github(self, module: str, version: str, tag: str | None) -> dict:
        return self._request("package.github", {"module": module, "version": version, "tag": tag})

    def install(self, ticket: str) -> dict:
        return self._request("package.install", {"ticket": ticket})

    def rollback(self, module: str) -> dict:
        return self._request("package.rollback", {"module": module})

    def remove(self, module: str) -> dict:
        return self._request("package.remove", {"module": module})


class CoreUpdateClient(HostClient):
    def forwarding_status(self) -> dict:
        return self._request("core.forwarding_status", {}, timeout=12)

    def forwarding_enable(self, module: str) -> dict:
        return self._request("core.forwarding_enable", {"module": module}, timeout=65)

    def provision_status(self) -> dict:
        return self._request("core.provision_status", {}, timeout=8)

    def provision_start(self, module: str) -> dict:
        return self._request("core.provision_start", {"module": module}, timeout=35)

    def status(self) -> dict:
        return self._request("core.status", {}, timeout=20)

    def upload(self, stream, size: int) -> dict:
        return self._request("core.upload", {"size": size}, source=stream, timeout=235)

    def github(self, tag: str | None) -> dict:
        return self._request("core.github", {"tag": tag}, timeout=235)

    def start(self, ticket: str) -> dict:
        return self._request("core.start", {"ticket": ticket}, timeout=35)

    def discard(self, ticket: str) -> dict:
        return self._request("core.discard", {"ticket": ticket}, timeout=8)

    def reconcile(self, ticket: str) -> dict:
        return self._request("core.reconcile", {"ticket": ticket}, timeout=10)


class LifecycleClient(HostClient):
    def settings_snapshot(self, modules: list[str]) -> dict:
        return self._request("lifecycle.settings_snapshot", {"modules": modules}, timeout=35)

    def history_status(self) -> dict:
        return self._request("lifecycle.history.status", {}, timeout=10)

    def history_configure(self, enabled: bool) -> dict:
        return self._request("lifecycle.history.configure", {"enabled": enabled}, timeout=40)

    def set_enabled(self, module: str, enabled: bool) -> dict:
        return self._request("lifecycle.enable" if enabled else "lifecycle.disable", {"module": module})

    def upgrade(self, module: str, ticket: str) -> dict:
        return self._request("lifecycle.upgrade", {"module": module, "ticket": ticket})

    def diagnostics(self, module: str) -> dict:
        return self._request("lifecycle.diagnostics", {"module": module}, timeout=35)

    def initialize_tunnel(self, module: str, egress: str | None) -> dict:
        return self._request("lifecycle.initialize", {"module": module, "egress": egress}, timeout=35)

    def tunnel_settings(self, module: str) -> dict:
        return self._request("lifecycle.tunnel_settings", {"module": module}, timeout=20)

    def change_tunnel(self, module: str, egress: str | None, revision: str) -> dict:
        return self._request("lifecycle.change_tunnel", {"module": module, "egress": egress,
                             "revision": revision}, timeout=35)

    def initialize_xray(self, *, kind, exposure, sni, reality, external_host, path, add=False, revision=None) -> dict:
        method = "lifecycle.replace_xray" if revision is not None else ("lifecycle.add_xray" if add else "lifecycle.initialize_xray")
        params = {"module": "xray", "kind": kind, "exposure": exposure, "sni": sni,
                  "reality": reality, "external_host": external_host, "path": path}
        if revision is not None:
            params["revision"] = revision
        return self._request(method, params, timeout=35)

    def xray_profiles(self) -> dict:
        return self._request("lifecycle.xray_profiles", {"module": "xray"}, timeout=20)

    def remove_xray(self, kind, revision) -> dict:
        return self._request("lifecycle.remove_xray", {"module": "xray", "kind": kind, "revision": revision}, timeout=35)

    def initialize_hysteria(self, identity, port, salamander) -> dict:
        return self._request("lifecycle.initialize_hysteria", {"module": "hysteria", "identity": identity,
                             "port": port, "salamander": salamander}, timeout=35)

    def change_hysteria(self, identity, port, salamander, revision) -> dict:
        return self._request("lifecycle.change_hysteria", {"module": "hysteria", "identity": identity,
                             "port": port, "salamander": salamander, "revision": revision}, timeout=35)

    def initialize_mtproto(self, module, sni, mode, exposure) -> dict:
        return self._request("lifecycle.initialize_mtproto", {"module": module, "sni": sni,
                             "mode": mode, "exposure": exposure}, timeout=35)

    def mtproto_exposure(self, module) -> dict:
        return self._request("lifecycle.mtproto_exposure", {"module": module}, timeout=20)

    def change_mtproto(self, module, sni, mode, exposure, revision) -> dict:
        return self._request("lifecycle.change_mtproto", {"module": module, "sni": sni,
                             "mode": mode, "exposure": exposure, "revision": revision}, timeout=35)

    def plan(self, module: str) -> dict:
        return self._request("lifecycle.plan", {"module": module}, timeout=9)


class UsersClient(HostClient):
    def users(self, method: str, **params) -> dict:
        timeout = (346 if method in {"grant", "retry"}
                   else 25 if method in {"detail", "profiles", "subscription", "config"} else 9)
        return self._request("users." + method, params, timeout=timeout)
