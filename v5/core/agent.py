"""Локальный агент v5: ограниченный Unix RPC и сводка журнала."""

import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import struct
import time
from subprocess import SubprocessError

from . import audit
from .contracts import CORE_API_VERSION
from .host_status import HostStatus
from .observability.live import Observer
from .observability.collector import DIRECTORY as OBSERVATION_DIRECTORY
from .observability.history import History, WINDOWS, summarize
from .observability.ssh import session_id
from .packages.manifest import PackageError
from .packages.status import package_status
from .site.document import MAX_HTML_BYTES, SiteStore, UnsafeDocument
from .tls.gateway import SITE_ROOT
from .tls.certificates import MAX_CHAIN_BYTES, MAX_KEY_BYTES
from .tls.acme import AcmeMode, zerossl_ready
from .tls.queue import QueueBusy, TLSDNSJob, TLSImportJob, TLSJob, TLSQueue, registry
from .tls.transaction import read_gateway_config

MAX_REQUEST = 4096
PEER = struct.Struct("3i")


def site_body_size(request) -> int | None:
    if (not isinstance(request, dict) or set(request) != {"version", "method", "params"}
            or type(request["version"]) is not int or request["version"] != CORE_API_VERSION
            or request["method"] != "site.publish"):
        return None
    params = request["params"]
    if not isinstance(params, dict) or set(params) != {"size"}:
        return None
    size = params["size"]
    return size if type(size) is int and 1 <= size <= MAX_HTML_BYTES else None


def tls_import_body_size(request) -> int | None:
    if (not isinstance(request, dict) or set(request) != {"version", "method", "params"}
            or type(request["version"]) is not int or request["version"] != CORE_API_VERSION
            or request["method"] != "tls.import" or not isinstance(request["params"], dict)
            or set(request["params"]) != {"name", "chain_size", "key_size"}
            or not isinstance(request["params"]["name"], str)):
        return None
    chain, key = request["params"]["chain_size"], request["params"]["key_size"]
    if type(chain) is not int or type(key) is not int or not (1 <= chain <= MAX_CHAIN_BYTES and 1 <= key <= MAX_KEY_BYTES):
        return None
    return chain + key


class AgentApplication:
    def __init__(self, web_uid: int, status=None, tls: TLSQueue | None = None, tls_registry=registry,
                 site: SiteStore | None = None, packages=None, journal=None, observer=None, history=None):
        self.web_uid = web_uid
        self.status = status if status is not None else HostStatus()
        self.tls = tls
        self.tls_registry = tls_registry
        self.site = site
        self.packages = packages
        self.journal = journal
        self.observer = observer
        self.history = history

    def _tls_dispatch(self, method, params, body):
        try:
            identities, _ = self.tls_registry()
        except (OSError, ValueError, RecursionError):
            return {"ok": False, "error": "tls_unavailable"}
        try:
            if method == "tls.status" and params == {} and body is None:
                state = self.tls.snapshot()
                try:
                    config = read_gateway_config(Path('/etc/kvn-v5/gateway/nginx.conf'))
                    state['import_ready'] = (b'location = /settings/tls/import {' in config
                                             and b'client_body_buffer_size 176k;' in config)
                except (OSError, ValueError):
                    state['import_ready'] = False
                state["names"] = [{"name": item.name, "authority": item.authority, "slot": item.slot,
                                   "is_ip": item.is_ip} for item in identities]
                state["zerossl_ready"] = any(not item.is_ip for item in identities) and zerossl_ready()
                return {"ok": True, "result": state}
            if method == "tls.issue" and body is None:
                job = TLSJob.parse(params, identities)
                if job.mode is AcmeMode.ZEROSSL and not zerossl_ready():
                    return {"ok": False, "error": "zerossl_not_configured"}
                self.tls.submit(job)
                return {"ok": True, "result": {"queued": True}}
            if method == "tls.diagnose" and body is None and set(params) == {"name"}:
                self.tls.submit_dns(TLSDNSJob.parse({"kind": "dns", "name": params["name"]}, identities))
                return {"ok": True, "result": {"queued": True}}
            if method == "tls.prepare" and body is None and params == {}:
                pending = Path('/usr/local/lib/.kvn-v5-core/pending')
                if pending.exists() or pending.is_symlink():
                    return {"ok": False, "error": "core_update_busy"}
                self.tls.submit_prepare()
                return {"ok": True, "result": {"queued": True}}
            if method == "tls.import":
                request = {"version": CORE_API_VERSION, "method": method, "params": params}
                size = tls_import_body_size(request)
                if size is None or not isinstance(body, bytes) or len(body) != size:
                    return {"ok": False, "error": "invalid_request"}
                identity = next((item for item in identities if item.name == params["name"]), None)
                if identity is None:
                    raise ValueError("Имя не зарегистрировано")
                split = params["chain_size"]
                self.tls.submit_import(TLSImportJob(identity, body[:split], body[split:]))
                return {"ok": True, "result": {"queued": True}}
        except QueueBusy:
            return {"ok": False, "error": "tls_busy"}
        except (ValueError, RecursionError):
            return {"ok": False, "error": "invalid_request"}
        except OSError:
            return {"ok": False, "error": "tls_unavailable"}
        return {"ok": False, "error": "invalid_request"}

    def _site_dispatch(self, request, body):
        method, params = request["method"], request["params"]
        try:
            if method == "site.publish":
                if not isinstance(body, bytes) or len(body) != site_body_size(request):
                    return {"ok": False, "error": "invalid_request"}
                self.site.publish(body)
                return {"ok": True, "result": {"published": True}}
            if params or body is not None:
                return {"ok": False, "error": "invalid_request"}
            if method == "site.status":
                return {"ok": True, "result": self.site.status()}
            if method == "site.reset":
                self.site.reset()
                return {"ok": True, "result": {"reset": True}}
        except UnsafeDocument:
            return {"ok": False, "error": "site_invalid"}
        except OSError:
            return {"ok": False, "error": "site_unavailable"}
        return {"ok": False, "error": "invalid_request"}

    def dispatch(self, peer_uid: int, request, *, body: bytes | None = None):
        if peer_uid != self.web_uid:
            return {"ok": False, "error": "forbidden"}
        if not isinstance(request, dict) or set(request) != {"version", "method", "params"}:
            return {"ok": False, "error": "invalid_request"}
        if (type(request["version"]) is not int or request["version"] != CORE_API_VERSION
                or not isinstance(request["method"], str) or not isinstance(request["params"], dict)):
            return {"ok": False, "error": "invalid_request"}
        if self.tls is not None and request["method"] in ("tls.status", "tls.issue", "tls.import", "tls.diagnose", "tls.prepare"):
            result = self._tls_dispatch(request["method"], request["params"], body)
            audit.outcome(request, result)
            return result
        if self.site is not None and request["method"] in ("site.status", "site.publish", "site.reset"):
            result = self._site_dispatch(request, body)
            audit.outcome(request, result)
            return result
        if self.journal is not None and request["method"] == "journal.recent":
            params = request["params"]
            if set(params) != {"source"} or params["source"] not in audit.SOURCES or body is not None:
                return {"ok": False, "error": "invalid_request"}
            try:
                return {"ok": True, "result": {"entries": self.journal(params["source"])}}
            except (OSError, ValueError, SubprocessError):
                return {"ok": False, "error": "journal_unavailable"}
        if self.observer is not None and request["method"] == "observe.ssh":
            if request["params"] or body is not None:
                return {"ok": False, "error": "invalid_request"}
            try:
                return {"ok": True, "result": self.observer.ssh_snapshot()}
            except (OSError, ValueError, IndexError):
                return {"ok": False, "error": "observe_unavailable"}
        if self.observer is not None and request["method"] == "observe.live":
            params = request["params"]
            if (set(params) - {"session"} or ("session" in params and not session_id(params["session"]))
                    or body is not None):
                return {"ok": False, "error": "invalid_request"}
            try:
                result = self.observer.snapshot(params.get("session"))
                from v5.core.observability.listeners import listeners
                try:
                    result["listeners"], result["listeners_partial"] = listeners()
                except (OSError, ValueError, SubprocessError):
                    result["listeners"], result["listeners_partial"] = [], True
                return {"ok": True, "result": {key: value for key, value in result.items() if key != "boot_id"}}
            except (OSError, ValueError, IndexError):
                return {"ok": False, "error": "observe_unavailable"}
        if self.history is not None and request["method"] == "observe.history":
            params = request["params"]
            if (set(params) != {"hours"} or type(params["hours"]) is not int
                    or params["hours"] not in WINDOWS or body is not None):
                return {"ok": False, "error": "invalid_request"}
            try:
                now = int(time.time())
                return {"ok": True, "result": self.history.summary(params["hours"], now)}
            except FileNotFoundError:
                return {"ok": True, "result": summarize([], params["hours"], int(time.time()))}
            except (OSError, ValueError, sqlite3.Error):
                return {"ok": False, "error": "observe_unavailable"}
        if request["params"] != {} or body is not None:
            return {"ok": False, "error": "invalid_request"}
        if request["method"] == "health":
            return {"ok": True, "result": {"version": CORE_API_VERSION, "status": "ready"}}
        if self.packages is not None and request["method"] == "package.status":
            try:
                return {"ok": True, "result": self.packages()}
            except PackageError as exc:
                return {"ok": False, "error": str(exc)}
            except OSError:
                return {"ok": False, "error": "package_store_unavailable"}
        if request["method"] == "host.status":
            try:
                return {"ok": True, "result": self.status.snapshot()}
            except (OSError, KeyError, IndexError, ValueError):
                return {"ok": False, "error": "status_unavailable"}
        return {"ok": False, "error": "unknown_method"}


class RequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            _, uid, _ = PEER.unpack(self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEER.size))
            if uid != self.server.application.web_uid:
                response = {"ok": False, "error": "forbidden"}
            else:
                line = self.rfile.readline(MAX_REQUEST + 1)
                if len(line) > MAX_REQUEST or not line.endswith(b"\n"):
                    response = {"ok": False, "error": "invalid_request"}
                else:
                    request = json.loads(line)
                    size = site_body_size(request) if self.server.application.site is not None else None
                    if size is None and self.server.application.tls is not None:
                        size = tls_import_body_size(request)
                    # Читаем отдельное тело только для двух явно ограниченных операций.
                    body = self.rfile.read(size + 1) if size is not None else None
                    response = self.server.application.dispatch(uid, request, body=body)
        except (OSError, ValueError, RecursionError):
            response = {"ok": False, "error": "invalid_request"}
        try:
            self.wfile.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        except OSError:
            pass


class AgentServer(socketserver.UnixStreamServer):
    def __init__(self, path: Path, application: AgentApplication):
        self.application = application
        super().__init__(str(path), RequestHandler)
        os.chmod(path, 0o660)


def _refresh_public_site(site, tls, gateway_file):
    try:
        site.refresh_default()
    except OSError:
        pass
    try:
        if b"return 308 https://$kvn_public_authority$request_uri;" in read_gateway_config(gateway_file):
            tls.submit_prepare()
    except (OSError, ValueError, QueueBusy):
        # Очередь уже обрабатывается либо шлюз ещё не настроен.
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--web-uid", type=int, required=True)
    options = parser.parse_args()
    tls, site = TLSQueue(), SiteStore(SITE_ROOT)
    _refresh_public_site(site, tls, Path("/etc/kvn-v5/gateway/nginx.conf"))
    with AgentServer(options.socket, AgentApplication(options.web_uid, tls=tls, site=site,
                                                     packages=package_status, journal=audit.recent,
                                                     observer=Observer(), history=History(OBSERVATION_DIRECTORY))) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
