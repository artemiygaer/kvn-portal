"""Ограниченный RPC подготовки и отдельного запуска обновления ядра."""

import argparse
import json
import re
import socket
import struct
import subprocess
import tarfile

from v5.core.contracts import CORE_API_VERSION
from v5.core import audit
from v5.core.lifecycle.controller import LifecycleError
from v5.core.packages.manifest import PackageError, json_object
from v5.core.packages.debian_provision import ProvisionError
from v5.core.packages.provision_state import ProvisionJournal
from v5.core.release import installed_version, stable_version

from .core_github import GitHubCore
from .portal_store import LIFETIME, PortalUpdateStore, TICKET, UpdateStoreError

SOCKET = "/run/kvn-v5-core-update.sock"
_PEER = struct.Struct("3i")
_METHODS = {"core.status": frozenset(), "core.upload": frozenset({"size"}),
            "core.github": frozenset({"tag"}), "core.start": frozenset({"ticket"}),
            "core.discard": frozenset({"ticket"}), "core.reconcile": frozenset({"ticket"}),
            "core.provision_status": frozenset(), "core.provision_start": frozenset({"module"}),
            "core.forwarding_status": frozenset(), "core.forwarding_enable": frozenset({"module"})}


def _forwarding_status():
    from pathlib import Path
    value = Path('/proc/sys/net/ipv4/ip_forward').read_bytes().strip()
    if value not in (b'0', b'1'):
        raise UpdateStoreError('forwarding_state_unavailable')
    result = subprocess.run(['/usr/bin/systemctl', 'is-enabled', '--quiet', 'kvn-v5-forwarding.service'],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=8, check=False)
    if result.returncode not in (0, 1):
        raise UpdateStoreError('forwarding_state_unavailable')
    return {'active': value == b'1', 'persistent': result.returncode == 0}


def _enable_forwarding(module):
    from v5.core.packages.registry import PackageRegistry
    from v5.core.packages.signature import load_publisher
    from v5.core.packages.status import PACKAGE_STATE
    from v5.modules.host_tunnel.state import MODULES_ROOT, State, TUNNELS
    if module not in ('wireguard', 'amneziawg'):
        raise UpdateStoreError('invalid_request')
    packages = PackageRegistry(PACKAGE_STATE, load_publisher())
    with packages.runtime_guard():
        packages.require_network_idle()
        if not any(row['module'] == module for row in packages.installed()):
            raise UpdateStoreError('module_not_installed')
        packages.verified_install(module)
        try:
            state = State.load(TUNNELS[module], MODULES_ROOT / module / 'settings.json')
        except FileNotFoundError:
            raise UpdateStoreError('forwarding_egress_required') from None
        if not state.settings.egress:
            raise UpdateStoreError('forwarding_egress_required')
        for action in ('start', 'enable'):
            result = subprocess.run(['/usr/bin/systemctl', action, 'kvn-v5-forwarding.service'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=25, check=False)
            if result.returncode:
                raise UpdateStoreError('forwarding_enable_unconfirmed')
    status = _forwarding_status()
    if not status['active'] or not status['persistent']:
        raise UpdateStoreError('forwarding_enable_unconfirmed')
    return status


def _start(ticket):
    if not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None:
        raise UpdateStoreError("core_ticket_invalid")
    try:
        result = subprocess.run(["/usr/bin/systemctl", "start", "--no-block", f"kvn-v5-core-apply@{ticket}.service"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise UpdateStoreError("core_start_unavailable") from exc
    if result.returncode:
        raise UpdateStoreError("core_start_unavailable")


def _unit_active(ticket, template):
    if not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None:
        raise UpdateStoreError("core_ticket_invalid")
    try:
        result = subprocess.run(["/usr/bin/systemctl", "show", f"{template}@{ticket}.service",
                                 "--property=LoadState", "--property=ActiveState", "--property=Job"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
        if result.returncode:
            return None
        fields = dict(line.split("=", 1) for line in result.stdout.decode("ascii").splitlines() if "=" in line)
        if fields.get("Job"):
            return True
        if fields.get("ActiveState") in ("active", "activating", "reloading", "deactivating"):
            return True
        if fields.get("ActiveState") in ("inactive", "failed") and fields.get("LoadState") in ("loaded", "not-found"):
            return False
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _job_active(ticket):
    return _unit_active(ticket, "kvn-v5-core-apply")


def _provision_active(ticket):
    return _unit_active(ticket, "kvn-v5-provision")


def _start_provision(ticket):
    if not isinstance(ticket, str) or TICKET.fullmatch(ticket) is None:
        raise ProvisionError("invalid_provision_request")
    try:
        busy = subprocess.run(["/usr/bin/systemctl", "list-units", "--no-legend", "--plain",
                               "--state=active,activating,deactivating", "kvn-v5-core-apply@*.service"],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=5, check=False)
        if busy.returncode or busy.stdout.strip():
            raise ProvisionError("provision_busy")
        result = subprocess.run(["/usr/bin/systemctl", "start", "--no-block", f"kvn-v5-provision@{ticket}.service"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=30, check=False)
        if result.returncode:
            raise ProvisionError("provision_unconfirmed")
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError("provision_unconfirmed") from exc


class PortalUpdateApplication:
    def __init__(self, uid, store, *, github=None, launch=_start, probe=_job_active,
                 provision=None, provision_launch=_start_provision, provision_probe=_provision_active,
                 forwarding_status=_forwarding_status, forwarding_enable=_enable_forwarding):
        self.uid, self.store = uid, store
        self.github = github if github is not None else GitHubCore()
        self.launch = launch
        self.probe = probe
        self.provision = provision if provision is not None else ProvisionJournal()
        self.provision_launch, self.provision_probe = provision_launch, provision_probe
        self.forwarding_status, self.forwarding_enable = forwarding_status, forwarding_enable

    def dispatch(self, request, stream):
        if (not isinstance(request, dict) or set(request) != {"version", "method", "params"}
                or type(request["version"]) is not int or request["version"] != CORE_API_VERSION
                or not isinstance(request["method"], str) or request["method"] not in _METHODS
                or not isinstance(request["params"], dict)
                or request["params"].keys() != _METHODS[request["method"]]):
            raise UpdateStoreError("invalid_request")
        method, params = request["method"], request["params"]
        if method != "core.upload" and stream.read(1):
            raise UpdateStoreError("invalid_request")
        if method == "core.status":
            records = self.store.records()
            current = installed_version(self.store.live)
            for record in records:
                if record["status"] == "ready" and self.store.clock() - record["created"] >= LIFETIME:
                    record["status"] = "expired"
                elif (record["status"] == "ready" and current is not None
                      and stable_version(record["version"]) <= stable_version(current)):
                    record["status"] = "obsolete"
                elif record["status"] in ("queued", "running"):
                    record["job_active"] = self.probe(record["ticket"])
            return {"current": current, "records": records}
        if method == "core.upload":
            return self.store.prepare(stream, params["size"])
        if method == "core.forwarding_status":
            return self.forwarding_status()
        if method == "core.forwarding_enable":
            if params['module'] not in ('wireguard', 'amneziawg'):
                raise UpdateStoreError('invalid_request')
            try:
                status = self.forwarding_enable(params['module'])
            except (PackageError, UpdateStoreError, LifecycleError, OSError, ValueError, subprocess.SubprocessError):
                audit.record('core.forwarding_enable', False, params['module'])
                raise
            audit.record('core.forwarding_enable', True, params['module'])
            return status
        if method == "core.provision_status":
            record = self.provision.get()
            if record and record["status"] in ("queued", "running"):
                active = self.provision_probe(record["ticket"])
                if active is False and self.provision.clock() - record["updated"] >= 10:
                    try:
                        record = self.provision.transition(record["ticket"], record["status"], "failed",
                                                           "provision_unconfirmed")
                    except ProvisionError:
                        record = self.provision.get()
            if record:
                record = {key: record[key] for key in ("module", "status", "code", "updated")}
            return {"job": record}
        if method == "core.provision_start":
            record = self.provision.queue(params["module"])
            try:
                self.provision_launch(record["ticket"])
            except (ProvisionError, OSError, subprocess.SubprocessError) as exc:
                code = 'provision_busy' if isinstance(exc, ProvisionError) and str(exc) == 'provision_busy' else 'provision_unconfirmed'
                self.provision.transition(record["ticket"], "queued", "failed", code)
                raise ProvisionError(code) from None
            return {"module": record["module"], "status": "queued"}
        if method == "core.github":
            return self.github.prepare(self.store, params["tag"])
        if method == "core.discard":
            self.store.discard(params["ticket"])
            return {"discarded": True}
        if method == "core.reconcile":
            ticket = params["ticket"]
            with self.store.locked():
                record = self.store.record(ticket)
                if (record["status"] not in ("queued", "running") or self.store.clock() - record["updated"] < 10
                        or self.probe(ticket) is not False):
                    raise UpdateStoreError("core_update_busy")
                self.store.set_status(ticket, "failed")
            return {"status": "failed"}
        ticket = params["ticket"]
        with self.store.locked():
            record = self.store.record(ticket)
            if record["status"] != "ready" or self.store.clock() - record["created"] >= LIFETIME:
                raise UpdateStoreError("core_not_ready")
            current = installed_version(self.store.live)
            if current is not None and stable_version(record["version"]) <= stable_version(current):
                raise UpdateStoreError("core_version_not_newer")
            self.store.set_status(ticket, "queued")
        try:
            self.launch(ticket)
        except (OSError, ValueError, subprocess.SubprocessError):
            with self.store.locked():
                if self.store.record(ticket)["status"] == "queued":
                    self.store.set_status(ticket, "ready")
            raise UpdateStoreError("core_start_unavailable") from None
        return {"ticket": ticket, "status": "queued"}

    def handle(self, connection):
        connection.settimeout(12)
        try:
            _, uid, _ = _PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _PEER.size))
            if uid != self.uid:
                raise UpdateStoreError("forbidden")
            with connection.makefile("rb") as stream:
                line = stream.readline(4097)
                if len(line) > 4096 or not line.endswith(b"\n"):
                    raise UpdateStoreError("invalid_request")
                result = self.dispatch(json_object(line), stream)
            response = {"ok": True, "result": result}
        except (PackageError, UpdateStoreError, ProvisionError, LifecycleError) as exc:
            code = str(exc)
            response = {"ok": False, "error": code if re.fullmatch(r"[a-z0-9_]{1,64}", code) else "core_update_unavailable"}
        except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError, RecursionError):
            response = {"ok": False, "error": "core_update_unavailable"}
        try:
            connection.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web-uid", type=int, required=True)
    options = parser.parse_args()
    with socket.socket(fileno=0) as connection:
        PortalUpdateApplication(options.web_uid, PortalUpdateStore(options.web_uid)).handle(connection)


if __name__ == "__main__":
    main()
