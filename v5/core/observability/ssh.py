"""SSH-сессии logind и строгое сопоставление с установленными TCP-сокетами."""

from collections import Counter
from dataclasses import dataclass
from ipaddress import ip_address
import os
from pathlib import Path
import pwd
import re
import select
import socket
import stat
import subprocess
import time

MAX_SESSIONS = 32
MAX_OUTPUT = 256 * 1024
_SID = re.compile(r"[a-zA-Z0-9]{1,32}\Z", re.ASCII)
_USER = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,63}[$]?\Z", re.ASCII)
_TTY = re.compile(r"(?:pts/)?[0-9]{1,8}\Z", re.ASCII)
_NUMBER = re.compile(r"[0-9]{1,20}\Z", re.ASCII)
_SSHD = frozenset(("sshd", "sshd-session", "sshd-auth"))
_SERVICE = frozenset(("sshd", "sshd-session"))
_PROP = ("Id", "Name", "Leader", "Remote", "RemoteHost", "Service", "State", "TTY", "TimestampMonotonic")
_OWNERS = re.compile(r'"(sshd(?:-session|-auth)?)",pid=([0-9]{1,10}),fd=[0-9]{1,10}')
_TOKEN = re.compile(r"(?:^|\s)(ino|sk|bytes_acked|bytes_received):([^\s]+)")
_WHO = re.compile(r"^([a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,63}\$?)\s+(pts/[0-9]{1,8})\s+"
                  r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[A-Z][a-z]{2}\s+[0-9]{1,2})\s+"
                  r"[0-9]{2}:[0-9]{2}\s+\(([^()\s]+)\)\s*$", re.ASCII)
SOCKET = "/run/kvn-v5-observer.sock"
SS_COMMAND = ("/usr/bin/ss", "-HntOeip", "state", "established")


def session_id(value):
    return isinstance(value, str) and _SID.fullmatch(value) is not None


def _uint(value):
    if not isinstance(value, str) or not _NUMBER.fullmatch(value) or int(value) >= 2**64:
        raise ValueError("Недопустимый счётчик")
    return int(value)


def _address(value):
    addr = ip_address(value)
    if addr.is_unspecified or addr.is_multicast:
        raise ValueError("Недопустимый адрес SSH")
    return (addr.ipv4_mapped or addr).compressed if addr.version == 6 else addr.compressed


@dataclass(frozen=True, slots=True)
class Session:
    id: str
    user: str
    address: str | None
    leader: int
    started_us: int
    tty: str | None


@dataclass(frozen=True, slots=True)
class Connection:
    local: tuple[str, int]
    peer: tuple[str, int]
    inode: int
    cookie: str
    owners: frozenset[int]
    rx: int | None
    tx: int | None

    @property
    def key(self):
        return self.local, self.peer, self.inode, self.cookie


def _query(argv):
    deadline = time.monotonic() + 1.0
    data = bytearray()
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          env={"PATH": "/usr/bin:/bin", "LANG": "C", "SYSTEMD_COLORS": "0"}) as process:
        try:
            while True:
                wait = deadline - time.monotonic()
                if wait <= 0 or not select.select([process.stdout], [], [], wait)[0]:
                    raise subprocess.TimeoutExpired(argv[0], 1.0)
                chunk = os.read(process.stdout.fileno(), min(16384, MAX_OUTPUT + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_OUTPUT:
                    raise ValueError("Ответ источника превысил лимит")
            if process.wait(timeout=max(0, deadline - time.monotonic())):
                raise subprocess.CalledProcessError(process.returncode, argv[0])
        finally:
            if process.poll() is None:
                process.kill()
    return data.decode("utf-8", "replace")


def sessions(*, query=_query):
    args = ["/usr/bin/loginctl", "--no-pager"]
    listing = query([*args, "--no-legend", "list-sessions"])
    ids = list(dict.fromkeys(line.split()[0] for line in listing.splitlines() if line.strip()))
    partial = len(ids) > MAX_SESSIONS or any(not _SID.fullmatch(item) for item in ids)
    ids = [item for item in ids if _SID.fullmatch(item)][:MAX_SESSIONS]
    if not ids:
        return [], partial
    output = query([*args, *[f"--property={key}" for key in _PROP], "show-session", *ids])
    return parse_sessions(output, set(ids)), partial


def parse_sessions(output, expected):
    rows = {}
    for block in re.split(r"\n\s*\n", output.strip()):
        fields = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
        sid, user = fields.get("Id", ""), fields.get("Name", "")
        if (sid not in expected or not _SID.fullmatch(sid) or not _USER.fullmatch(user)
                or fields.get("Remote") != "yes" or fields.get("Service") not in _SERVICE
                or fields.get("State") not in ("active", "online")):
            continue
        try:
            leader = _uint(fields.get("Leader"))
            started = _uint(fields.get("TimestampMonotonic"))
        except ValueError:
            continue
        if not leader or not started:
            continue
        try:
            address = _address(fields.get("RemoteHost", ""))
        except ValueError:
            # Не резолвить hostnames: нельзя доказать соответствие конкретному TCP.
            address = None
        tty = fields.get("TTY", "")
        rows[sid] = Session(sid, user, address, leader, started, tty if _TTY.fullmatch(tty) else None)
    return list(rows.values())


def _tty_owner(uid, device, process_rows, sockets, address=None):
    candidates = {}
    for process in process_rows.values():
        if process.uid != uid or process.tty != device:
            continue
        seen, current = set(), process
        while current is not None and current.pid not in seen and len(seen) < 64:
            seen.add(current.pid)
            if current.uid == 0 and current.name in _SSHD:
                owned = [sock for sock in sockets if current.pid in sock.owners
                         and (address is None or sock.peer[0] == address)]
                if len(owned) == 1:
                    candidates[current.pid] = current, owned[0]
            parent = process_rows.get(current.parent)
            current = parent if parent is not None and parent.started <= current.started else None
    if len({item.key for _, item in candidates.values()}) != 1:
        return None
    return min(candidates.values(), key=lambda pair: pair[0].started)


def _ttys(devices):
    with os.scandir(devices / "pts") as items:
        for count, item in enumerate(items):
            if count >= 256:
                break
            if not 1 <= len(item.name) <= 8 or not item.name.isascii() or not item.name.isdecimal():
                continue
            try:
                info = item.stat(follow_symlinks=False)
                if stat.S_ISCHR(info.st_mode):
                    yield "pts/" + item.name, info
            except OSError:
                continue


def fallback_sessions(process_rows, sockets, *, query=_query, devices=Path("/dev"), user_lookup=pwd.getpwnam,
                      uid_lookup=pwd.getpwuid, ttys=_ttys):
    """Подтвердить TTY, владельца, ancestry sshd и TCP; не угадывать по одному IP."""
    try:
        raw = query(["/usr/bin/who"])
    except (OSError, ValueError, subprocess.SubprocessError):
        raw = ""
    result, used = [], set()
    frequency = os.sysconf("SC_CLK_TCK")

    def add(name, tty, info, address=None):
        sid = "w" + tty.removeprefix("pts/")
        if sid in used or len(result) >= MAX_SESSIONS:
            return
        owner = _tty_owner(info.st_uid, info.st_rdev, process_rows, sockets, address)
        if owner is None:
            return
        leader, connection = owner
        used.add(sid)
        result.append(Session(sid, name, connection.peer[0], leader.pid,
                              int(leader.started * 1_000_000 / frequency), tty))

    for line in raw.splitlines()[:MAX_SESSIONS]:
        match_line = _WHO.fullmatch(line)
        if match_line is None:
            continue
        name, tty, host = match_line.groups()
        try:
            address = _address(host)
            uid = user_lookup(name).pw_uid
            info = (devices / tty).stat()
            if stat.S_ISCHR(info.st_mode) and info.st_uid == uid:
                add(name, tty, info, address)
        except (OSError, ValueError, KeyError):
            continue
    try:
        for tty, info in ttys(devices):
            try:
                name = uid_lookup(info.st_uid).pw_name
                if _USER.fullmatch(name):
                    add(name, tty, info)
            except (KeyError, ValueError):
                continue
    except OSError:
        pass
    return result


def _endpoint(value):
    addr, port = value.rsplit(":", 1)
    number = _uint(port)
    if not 1 <= number <= 65535:
        raise ValueError("Некорректный TCP-порт")
    return _address(addr.removeprefix("[").removesuffix("]")), number


def _socket_query(argv):
    if tuple(argv) != SS_COMMAND:
        raise ValueError("Недопустимый источник соединений")
    data = bytearray()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(SOCKET)
        while True:
            chunk = connection.recv(min(16384, MAX_OUTPUT + 4 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_OUTPUT + 3:
                raise ValueError("Ответ источника превысил лимит")
    if not data.startswith(b"OK\n"):
        raise OSError("Источник TCP недоступен")
    return data[3:].decode("utf-8", "replace")


def connections(*, query=_socket_query):
    raw = query(SS_COMMAND)
    result = []
    for line in raw.splitlines()[:4096]:
        owners = frozenset(int(pid) for _, pid in _OWNERS.findall(line))
        if not owners:
            continue
        try:
            fields = line.split(None, 4)
            tokens = dict(_TOKEN.findall(line))
            cookie = tokens["sk"]
            inode = _uint(tokens["ino"])
            if not inode or not re.fullmatch(r"[0-9a-f]{1,16}", cookie) or int(cookie, 16) == 0:
                continue
            values = [(_uint(tokens[name]) if name in tokens else None) for name in ("bytes_received", "bytes_acked")]
            result.append(Connection(_endpoint(fields[2]), _endpoint(fields[3]), inode, cookie, owners, *values))
        except (IndexError, KeyError, ValueError):
            continue
    return result


def match(session, process_rows, sockets):
    key = leader_key(session, process_rows)
    if key is None or session.address is None:
        return None
    # На Debian 12 sshd и Debian 13 sshd-session держат сетевой FD
    # в PAM-лидере. Один IP или порт назначения не доказывают совпадение.
    candidates = [sock for sock in sockets if sock.peer[0] == session.address and key[0] in sock.owners]
    return candidates[0] if len(candidates) == 1 else None


def leader_key(session, process_rows):
    leader = process_rows.get(session.leader)
    return leader.key if leader is not None and leader.uid == 0 and leader.name in _SSHD else None


def project(rows, process_rows, sockets, previous, elapsed, uptime):
    matched = [(row, match(row, process_rows, sockets)) for row in rows]
    counts = Counter(sock.key for _, sock in matched if sock is not None)
    current = {}
    output = []
    for row, sock in matched:
        key = leader_key(row, process_rows)
        rx = tx = rx_rate = tx_rate = port = None
        if sock is not None and counts[sock.key] == 1:
            port, rx, tx = sock.peer[1], sock.rx, sock.tx
            identity = (row.id, row.started_us, key, sock.key)
            current[identity] = rx, tx
            old = previous.get(identity)
            if old and elapsed > 0:
                rates = [None if a is None or b is None or a < b else round((a - b) / elapsed)
                         for a, b in zip((rx, tx), old)]
                rx_rate, tx_rate = rates
        output.append({"id": row.id, "user": row.user, "ip": row.address, "port": port, "tty": row.tty,
                       "age_seconds": max(0, int(uptime - row.started_us / 1_000_000)),
                       "rx_bytes": rx, "tx_bytes": tx, "rx_per_second": rx_rate, "tx_per_second": tx_rate})
    return output, current
