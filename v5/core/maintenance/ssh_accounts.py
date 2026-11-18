"""Управление только локальными непривилегированными учётными записями панели."""

import base64
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import struct
import subprocess
import sys

from v5.core.private_files import private_directory, read_private, write_private

ROOT = Path("/var/lib/kvn-v5/ssh-accounts")
LOGIN = re.compile(r"[a-z][a-z0-9_-]{0,31}", re.ASCII)
MARK = re.compile(r"kvn-ssh-[0-9a-f]{32}", re.ASCII)
HOME = Path("/home")
MAX_ACCOUNTS = 48
MAX_TRANSFER = 16 * 1024
MAX_REQUEST = MAX_TRANSFER + 1024
SCHEMAS = {"list": set(), "create": {"login", "password", "key"}, "password": {"login", "password"},
           "disable": {"login"}, "enable": {"login"}, "delete": {"login"},
           "export": set(), "import": {"archive"}}


class AccountError(ValueError):
    pass


def _login(value):
    if (not isinstance(value, str) or not LOGIN.fullmatch(value) or value == "root"
            or value.startswith("kvn-")):
        raise AccountError("ssh_login_invalid")
    return value


def _password(value):
    if (not isinstance(value, str) or not 12 <= len(value) <= 128
            or any(char in value for char in "\n\r\x00:")
            or len(value.encode("utf-8", "surrogatepass")) > 512 or
            any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise AccountError("ssh_password_invalid")
    return value


def _public_key(value):
    # Разрешаем один простой ключ Ed25519, без параметров authorized_keys.
    if not isinstance(value, str) or len(value) > 512 or any(c in value for c in "\r\n\x00"):
        raise AccountError("ssh_key_invalid")
    fields = value.strip().split(None, 2)
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise AccountError("ssh_key_invalid")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError:
        raise AccountError("ssh_key_invalid") from None
    if len(blob) != 51 or not blob.startswith(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)):
        raise AccountError("ssh_key_invalid")
    return b"ssh-ed25519 " + base64.b64encode(blob) + b"\n"


def _run(tool, *args, data=None, identity=None):
    try:
        options = {} if identity is None else dict(user=identity.pw_uid, group=identity.pw_gid, extra_groups=[])
        proc = subprocess.run([tool, *args], input=data if data is not None else b"",
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"},
                              cwd="/", **options)
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        raise AccountError("ssh_operation_failed") from None


def _shadow(login):
    with open("/etc/shadow", encoding="utf-8") as stream:
        for line in stream:
            fields = line.rstrip("\n").split(":")
            if fields[0] == login and len(fields) == 9:
                return fields[1], fields[7]
    raise AccountError("ssh_account_changed")


def _key_for(account, key):
    # Запись идёт с правами пользователя, поэтому ссылка из его home не даёт root-доступа.
    code = """import os, sys
os.umask(0o077)
os.mkdir('.ssh', 0o700, dir_fd=(home := os.open(sys.argv[1], os.O_DIRECTORY | os.O_NOFOLLOW)))
directory = os.open('.ssh', os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
fd = os.open('authorized_keys', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory)
with os.fdopen(fd, 'wb') as stream:
    stream.write(sys.stdin.buffer.read(1024))
"""
    if not _run("/usr/bin/python3", "-I", "-c", code, account.pw_dir, data=key, identity=account):
        raise AccountError("ssh_key_install_failed")


def _export_key(account):
    # Не читаем файлы из home от root. Переносим только одиночный ключ без ограничивающих опций.
    code = """import os, sys, stat
flags = os.O_DIRECTORY | os.O_NOFOLLOW
home = os.open(sys.argv[1], flags)
directory = os.open('.ssh', flags, dir_fd=home)
fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
attrs = os.fstat(fd)
if (stat.S_ISREG(attrs.st_mode) and attrs.st_uid == os.getuid() and
    not any(os.fstat(item).st_mode & 0o022 for item in (home, directory, fd))):
    with os.fdopen(fd, 'rb') as stream:
        sys.stdout.buffer.write(stream.read(513))
"""
    try:
        result = subprocess.run(["/usr/bin/python3", "-I", "-c", code, account.pw_dir],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                                timeout=3, cwd="/", env={"LC_ALL": "C.UTF-8"})
        if result.returncode or len(result.stdout) > 512:
            return ""
        return _public_key(result.stdout.decode("utf-8").strip("\r\n")).decode("ascii").strip()
    except (AccountError, UnicodeError, OSError, subprocess.SubprocessError):
        return ""


def parse_transfer(archive):
    if (not isinstance(archive, dict) or archive.keys() != {"format", "accounts"}
            or archive["format"] != "ssh-accounts/v1" or not isinstance(archive["accounts"], list)
            or len(archive["accounts"]) > MAX_ACCOUNTS):
        raise AccountError("ssh_archive_invalid")
    result = {}
    for row in archive["accounts"]:
        if not isinstance(row, dict) or row.keys() != {"login", "status", "key"}:
            raise AccountError("ssh_archive_invalid")
        name = _login(row["login"])
        key = row["key"]
        if name in result or row["status"] not in ("active", "disabled") or not isinstance(key, str):
            raise AccountError("ssh_archive_invalid")
        result[name] = _public_key(key).decode("ascii").strip() if key else ""
    return result


class Accounts:
    def __init__(self, root=ROOT):
        self.root = root

    def load(self):
        self.root.mkdir(mode=0o700, exist_ok=True)
        private_directory(self.root)
        try:
            rows = json.loads(read_private(self.root / "accounts.json", 16384))
        except FileNotFoundError:
            return {}
        if not isinstance(rows, dict) or len(rows) > MAX_ACCOUNTS:
            raise ValueError("Некорректный реестр SSH")
        for name, row in rows.items():
            _login(name)
            if (not isinstance(row, dict) or row.keys() != {"uid", "gid", "mark"}
                    or not isinstance(row["mark"], str) or not MARK.fullmatch(row["mark"])
                    or any(type(row[k]) is not int or not 1000 <= row[k] < 60000 for k in ("uid", "gid"))):
                raise ValueError("Некорректная запись SSH")
        return rows

    def save(self, rows):
        write_private(self.root / "accounts.json", json.dumps(rows, sort_keys=True).encode("ascii"))

    @staticmethod
    def account(name, row):
        try:
            entry = pwd.getpwnam(name)
            group = grp.getgrgid(entry.pw_gid)
            if (entry.pw_uid != row["uid"] or entry.pw_gid != row["gid"] or entry.pw_gecos != row["mark"]
                    or entry.pw_dir != str(HOME / name) or entry.pw_shell != "/bin/bash"
                    or group.gr_name != name or set(os.getgrouplist(name, entry.pw_gid)) != {entry.pw_gid}):
                raise ValueError
        except (KeyError, OSError, ValueError):
            raise AccountError("ssh_account_changed") from None
        return entry

    @staticmethod
    def status(name):
        digest, expiry = _shadow(name)
        if expiry == "1" and digest.startswith("!"):
            return "disabled"
        if not expiry and digest.startswith("$"):
            return "active"
        raise AccountError("ssh_account_changed")

    def create(self, rows, name, password, key, *, disabled=False):
        if len(rows) >= MAX_ACCOUNTS:
            raise AccountError("ssh_limit")
        if not isinstance(password, str) or not isinstance(key, str):
            raise AccountError("invalid_request")
        public = _public_key(key) if key else None
        if not disabled and (password or not public):
            _password(password)
        self.check_home()
        if name in rows or os.path.lexists(HOME / name):
            raise AccountError("ssh_name_taken")
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(name)
            except KeyError:
                continue
            raise AccountError("ssh_name_taken")
        mark = "kvn-ssh-" + secrets.token_hex(16)
        if not _run("/usr/sbin/useradd", "-m", "-U", "-l", "-K", "HOME_MODE=0700", "-K", "UID_MIN=1000",
                    "-K", "UID_MAX=59999", "-K", "GID_MIN=1000", "-K", "GID_MAX=59999",
                    "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", "-d", str(HOME / name),
                    "-s", "/bin/bash", "-c", mark, "-e", "1", "--", name):
            raise AccountError("ssh_create_failed")
        try:
            account = pwd.getpwnam(name)
            row = {"uid": account.pw_uid, "gid": account.pw_gid, "mark": mark}
            self.account(name, row)
            if public:
                _key_for(account, public)
            if not disabled:
                self.set_password(name, password or secrets.token_urlsafe(32))
            rows[name] = row
            self.save(rows)
            if disabled:
                return
            if not _run("/usr/sbin/usermod", "-e", "-1", "--", name):
                raise AccountError("ssh_operation_failed")
            if self.status(name) != "active":
                raise AccountError("ssh_operation_failed")
        except (AccountError, OSError, ValueError, KeyError):
            # Пока запись создаётся, срок действия не позволяет войти; при ошибке закрываем её.
            try:
                _run("/usr/sbin/usermod", "-L", "-e", "1", "--", name)
                if _run("/usr/sbin/userdel", "--", name) and name in rows:
                    del rows[name]
                    self.save(rows)
            except (OSError, ValueError):
                pass
            raise

    @staticmethod
    def set_password(name, password, *, disabled=False):
        password = _password(password)
        flags = ()
        if disabled:
            # Сохраняем блокировку shadow при смене пароля: аккаунт не включается ни на миг.
            try:
                hashed = subprocess.run(["/usr/bin/openssl", "passwd", "-6", "-stdin"],
                                        input=(password + "\n").encode(), stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=5, check=True,
                                        env={"LC_ALL": "C.UTF-8"}).stdout.strip()
                if not re.fullmatch(rb"\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}", hashed):
                    raise ValueError
            except (ValueError, OSError, subprocess.SubprocessError):
                raise AccountError("ssh_operation_failed") from None
            password = "!" + hashed.decode("ascii")
            flags = ("--encrypted",)
        if not _run("/usr/sbin/chpasswd", *flags, data=f"{name}:{password}\n".encode()):
            raise AccountError("ssh_operation_failed")

    @staticmethod
    def check_home():
        info = HOME.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AccountError("ssh_unavailable")

    def delete(self, rows, name, account):
        self.check_home()
        # Храним домашний каталог отдельно от /home/<логин>, под недоступным пользователям родителем.
        vault = HOME / ".kvn-ssh-retired"
        vault.mkdir(mode=0o700, exist_ok=True)
        private_directory(vault)
        home = HOME / name
        info = home.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid:
            raise AccountError("ssh_account_changed")
        retired = vault / (name + "-" + rows[name]["mark"][8:])
        if os.path.lexists(retired):
            raise AccountError("ssh_account_changed")
        home.rename(retired)
        try:
            if not _run("/usr/sbin/userdel", "--", name):
                raise AccountError("ssh_delete_failed")
        except (OSError, ValueError):
            retired.rename(home)
            raise
        del rows[name]
        self.save(rows)

    def execute(self, action, params):
        if not isinstance(action, str) or action not in SCHEMAS or not isinstance(params, dict) or params.keys() != SCHEMAS[action]:
            raise AccountError("invalid_request")
        rows = self.load()
        if action in ("list", "export"):
            result = []
            for name, row in sorted(rows.items()):
                try:
                    account = self.account(name, row)
                    status = self.status(name)
                except AccountError:
                    status = "changed"
                if action == "list":
                    result.append({"login": name, "uid": row["uid"], "status": status})
                elif status != "changed":
                    result.append({"login": name, "status": status, "key": _export_key(account)})
            if action == "export":
                return {"format": "ssh-accounts/v1", "accounts": result}
            return {"accounts": result}
        if action == "import":
            incoming = parse_transfer(params["archive"])
            added, skipped, failed = [], [], []
            for name, key in incoming.items():
                try:
                    self.create(rows, name, "", key, disabled=True)
                except AccountError as exc:
                    (skipped if str(exc) in ("ssh_name_taken", "ssh_limit") else failed).append(name)
                except (OSError, ValueError, KeyError):
                    failed.append(name)
                else:
                    added.append(name)
            return {"added": added, "skipped": skipped, "failed": failed}
        name = _login(params["login"])
        if action == "create":
            self.create(rows, name, params["password"], params["key"])
            return {}
        if name not in rows:
            raise AccountError("ssh_not_managed")
        account = self.account(name, rows[name])
        status = self.status(name)
        if action == "password":
            self.set_password(name, params["password"], disabled=status == "disabled")
        elif action == "delete":
            if status != "disabled":
                raise AccountError("ssh_disable_first")
            self.delete(rows, name, account)
        elif status != ("disabled" if action == "disable" else "active"):
            if action == "enable" and not _shadow(name)[0].removeprefix("!").startswith("$"):
                if not _export_key(account):
                    raise AccountError("ssh_credentials_required")
                self.set_password(name, secrets.token_urlsafe(32), disabled=True)
            flags = ("-L", "-e", "1") if action == "disable" else ("-U", "-e", "-1")
            if not _run("/usr/sbin/usermod", *flags, "--", name) or self.status(name) == status:
                raise AccountError("ssh_operation_failed")
        return {}


def main():
    import fcntl

    try:
        if os.geteuid() != 0:
            raise AccountError("ssh_unavailable")
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise AccountError("invalid_request")
        request = json.loads(raw)
        if not isinstance(request, dict) or request.keys() != {"action", "params"}:
            raise AccountError("invalid_request")
        private_directory(ROOT)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        with os.fdopen(os.open(ROOT / "lock", flags, 0o600), "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = Accounts().execute(request["action"], request["params"])
        response = {"ok": True, "result": result}
    except AccountError as exc:
        response = {"ok": False, "error": str(exc)}
    except BlockingIOError:
        response = {"ok": False, "error": "ssh_busy"}
    except (ValueError, OSError, KeyError, RecursionError):
        response = {"ok": False, "error": "ssh_unavailable"}
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    main()
