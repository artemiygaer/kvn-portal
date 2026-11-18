"""Ограниченный live-снимок, без фоновой записи и с раздельными статусами."""

from pathlib import Path
import re
from subprocess import SubprocessError
import time

from . import processes, ssh
from v5.core.host_status import HostStatus


class Observer:
    def __init__(self, *, process_source=processes.sample, session_source=ssh.sessions,
                 socket_source=ssh.connections, network_source=None, clock=time.monotonic, wall=time.time, uptime=None):
        self.sources = process_source, session_source, socket_source
        self.network_source = network_source if network_source is not None else HostStatus()._network
        self.clock, self.wall = clock, wall
        self.uptime = uptime if uptime is not None else self._uptime
        self._cache = None
        self._previous_processes, self._previous_tcp = {}, {}
        self._previous_network = None
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
            self.boot_id = boot_id if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id) else None
        except (OSError, UnicodeError):
            self.boot_id = None

    @staticmethod
    def _uptime():
        return float(Path("/proc/uptime").read_text(encoding="ascii").split()[0])

    @staticmethod
    def _source(source, fallback):
        try:
            return source(), False
        except (OSError, ValueError, SubprocessError):
            return fallback, True

    def ssh_snapshot(self):
        summary = self.snapshot(include_processes=False)
        return {key: summary[key] for key in ("captured_at", "ssh", "ssh_partial")}

    def snapshot(self, session_id=None, *, include_processes=True):
        current = self.clock()
        if self._cache is None or current - self._cache[0] >= 2:
            proc_source, session_source, socket_source = self.sources
            (proc, proc_partial), proc_failed = self._source(proc_source, ({}, False))
            (sessions, ssh_partial), ssh_failed = self._source(session_source, ([], False))
            sockets, tcp_failed = self._source(socket_source, []) if sessions or ssh_failed else ([], False)
            if ssh_failed and not tcp_failed:
                sessions, _ = self._source(lambda: ssh.fallback_sessions(proc, sockets), [])
            network, network_failed = self._source(self.network_source, None)
            uptime, stamp = self.uptime(), int(self.wall())
            elapsed = current - self._cache[0] if self._cache is not None else 0
            if network is not None:
                network = dict(network)
                for counter, rate in (("received_bytes", "rx_per_second"), ("sent_bytes", "tx_per_second")):
                    old = self._previous_network.get(counter) if self._previous_network is not None else None
                    value = network[counter]
                    network[rate] = round((value - old) / elapsed) if old is not None and value >= old and elapsed > 0 else None
            self._previous_network = network
            previous_processes = self._previous_processes
            rows, tcp = ssh.project(sessions, proc, sockets, self._previous_tcp, elapsed, uptime)
            for row in rows:
                row["started_at"] = max(0, stamp - row["age_seconds"])
            self._cache = current, proc, sessions, previous_processes, elapsed, uptime, {
                "captured_at": stamp, "boot_id": self.boot_id, "ssh": rows,
                "ssh_partial": ssh_failed or ssh_partial, "processes_partial": proc_failed or proc_partial,
                "tcp_partial": tcp_failed,
                "network": network, "network_partial": network_failed,
            }
            self._previous_processes, self._previous_tcp = proc, tcp
        _, proc, sessions, previous_processes, elapsed, uptime, summary = self._cache
        if not include_processes:
            return dict(summary)
        visible, confirmed = None, None
        if session_id is not None:
            row = next((item for item in sessions if item.id == session_id), None)
            key = ssh.leader_key(row, proc) if row is not None else None
            confirmed = key is not None and sum(ssh.leader_key(item, proc) == key for item in sessions) == 1
            visible = processes.descendants(proc, key) if confirmed else frozenset()
        candidates = len(proc) if visible is None else len(visible)
        return {**summary, "processes_partial": summary["processes_partial"] or candidates > processes.MAX_ROWS,
                "session_filter_confirmed": confirmed,
                "processes": processes.project(proc, previous_processes, elapsed, uptime, visible=visible)}
