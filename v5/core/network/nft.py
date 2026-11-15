"""Атомарная публикация DNAT только в таблице проекта."""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess

from .plan import Binding, NetworkConflict, NetworkPlan

TABLE = "kvn_v5_ingress"
NFT = Path("/usr/sbin/nft")
_OWNER = "kvn-v5:ingress:"
_MARKER = re.compile(re.escape(_OWNER) + r"[0-9a-f]{64}")
_PREFIX = f"inet {TABLE}"


@dataclass(frozen=True, slots=True)
class NftPlan:
    commands: tuple[str, ...]
    rule_count: int
    table: str = TABLE
    owner: str = _OWNER

    @property
    def comment(self) -> str:
        return self.owner + hashlib.sha256("\n".join(self.commands).encode("ascii")).hexdigest()

    def batch(self, current_handle: int | None) -> bytes:
        lines = []
        if current_handle is not None:
            if type(current_handle) is not int or current_handle <= 0:
                raise NetworkConflict("invalid_nft_handle")
            lines.append(f"delete table inet handle {current_handle}")
        if self.commands:
            lines.append(f'create table inet {self.table} {{ comment "{self.comment}"; }}')
            lines.extend(self.commands)
        return ("\n".join(lines) + "\n").encode("ascii") if lines else b""


def compile_nft(plan: NetworkPlan) -> NftPlan:
    """Создать только DNAT и защиту адресов внутренних backends."""
    redirect = [(item.publication.public, item.publication.redirect)
                for item in plan.publications if item.publication.redirect is not None]
    if not redirect:
        return NftPlan((), 0)
    rules = []
    backends: dict[Binding, set[int]] = {}
    for public, backend in redirect:
        family = "ip" if public.address.version == 4 else "ip6"
        address = "" if public.address.is_unspecified else f"{family} daddr {public.ip} "
        rules.append(f'add rule {_PREFIX} publish iifname != "lo" meta nfproto ipv{public.address.version} '
                     f"fib daddr type local {address}{public.protocol} dport {public.port} "
                     f"dnat {family} to {backend.nginx_address()}")
        backends.setdefault(backend, set()).add(public.port)
    for backend in sorted(backends, key=lambda item: item.sort_key):
        family = "ip" if backend.address.version == 4 else "ip6"
        ports = sorted(backends[backend])
        original = str(ports[0]) if len(ports) == 1 else "{ " + ", ".join(map(str, ports)) + " }"
        match = f'iifname != "lo" {family} daddr {backend.ip} {backend.protocol} dport {backend.port}'
        rules.extend((f"add rule {_PREFIX} guard {match} ct status dnat ct original proto-dst {original} return",
                      f"add rule {_PREFIX} guard {match} drop"))
    chains = (f"add chain {_PREFIX} publish {{ type nat hook prerouting priority -101; policy accept; }}",
              f"add chain {_PREFIX} guard {{ type filter hook input priority -5; policy accept; }}")
    return NftPlan((*chains, *rules), len(rules))


@dataclass(frozen=True, slots=True)
class _Snapshot:
    handle: int
    comment: str
    rules: int


class Nftables:
    table = TABLE
    marker = _MARKER

    def _call(self, *args: str, data: bytes | None = None) -> bytes:
        try:
            return subprocess.run([str(NFT), *args], input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  check=True, timeout=20, env={"LC_ALL": "C"}).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            raise NetworkConflict("nft_apply_failed") from exc

    def _document(self, *args: str) -> list[dict]:
        raw = self._call("-a", "-j", *args)
        try:
            data = json.loads(raw)["nftables"]
            if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
                raise ValueError
            return data
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise NetworkConflict("nft_inventory_invalid") from exc

    def _text_comment(self, handle: int) -> str | None:
        # nftables 1.0.6 (Debian 12) не включает комментарий таблицы в JSON.
        # Не принимать комментарий вложенной цепочки/правила или другой ревизии.
        raw = self._call("-a", "list", "table", "inet", self.table)
        try:
            header, comment, *_ = raw.decode("ascii").splitlines()
        except (UnicodeError, ValueError):
            return None
        if header != f"table inet {self.table} {{ # handle {handle}":
            return None
        match = re.fullmatch(r'\s+comment "([^"\r\n]+)"', comment)
        return match[1] if match else None

    def _snapshot(self, *, required: bool) -> _Snapshot | None:
        if not NFT.is_file() and not required:
            return None
        found = next((table for item in self._document("list", "tables")
                      if isinstance((table := item.get("table")), dict)
                      and (table.get("family"), table.get("name")) == ("inet", self.table)), None)
        if found is None:
            return None
        rows = self._document("list", "table", "inet", self.table)
        table = next((item["table"] for item in rows if "table" in item), {})
        if (not isinstance(table, dict) or type(table.get("handle")) is not int or table["handle"] <= 0
                or (table.get("family"), table.get("name")) != ("inet", self.table)
                or table["handle"] != found.get("handle")):
            raise NetworkConflict("unmanaged_nft_table")
        comment = table["comment"] if "comment" in table else self._text_comment(table["handle"])
        if not isinstance(comment, str) or not self.marker.fullmatch(comment):
            raise NetworkConflict("unmanaged_nft_table")
        return _Snapshot(table["handle"], comment, sum("rule" in item for item in rows))

    def apply(self, plan: NetworkPlan, *, check_only: bool = False, required: bool = False) -> None:
        self.apply_compiled(compile_nft(plan), check_only=check_only, required=required)

    def apply_compiled(self, compiled: NftPlan, *, check_only: bool = False, required: bool = False) -> None:
        if compiled.table != self.table or not self.marker.fullmatch(compiled.comment):
            raise NetworkConflict("invalid_nft_owner")
        current = self._snapshot(required=required or bool(compiled.commands))
        batch = compiled.batch(current.handle if current else None)
        if batch:
            args = ("--check", "-f", "-") if check_only else ("-f", "-")
            self._call(*args, data=batch)

    def verify(self, plan: NetworkPlan, *, required: bool = False) -> None:
        self.verify_compiled(compile_nft(plan), required=required)

    def verify_compiled(self, compiled: NftPlan, *, required: bool = False) -> None:
        if compiled.table != self.table or not self.marker.fullmatch(compiled.comment):
            raise NetworkConflict("invalid_nft_owner")
        observed = self._snapshot(required=required or bool(compiled.commands))
        if not compiled.commands and observed is None:
            return
        if not observed or observed.comment != compiled.comment or observed.rules != compiled.rule_count:
            raise NetworkConflict("nft_state_not_applied")
