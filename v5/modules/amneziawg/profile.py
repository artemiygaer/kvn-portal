"""Поля AmneziaWG, которые допустимы в kernel- и клиентском конфиге."""

from dataclasses import dataclass, field
import re

from v5.modules.host_tunnel.config import AWG, key, render_client, render_server


_DECIMAL_RANGE = re.compile(r"[0-9]{1,10}(?:-[0-9]{1,10})?", re.ASCII)
_JUNK_TAGS = re.compile(r"(?:<(?:b 0x(?:[0-9a-fA-F]{2}){1,128}|r(?:d|c)? [1-9][0-9]{0,2}|t)>)+", re.ASCII)
_V31_LIMITS = (
    ("ContentPaddingAddition", "content_padding", 0, 128),
    ("RekeyAfterTime", "rekey_after", 30, 300),
    ("RekeyTimeout", "rekey_timeout", 1, 15),
    ("RejectAfterTime", "reject_after", 60, 600),
    ("KeepaliveTimeout", "keepalive_timeout", 1, 45),
    ("MaxHandshakeAttempts", "max_handshakes", 1, 30),
)


def bounds(value: str, minimum: int, maximum: int) -> tuple[int, int]:
    if not isinstance(value, str) or not _DECIMAL_RANGE.fullmatch(value):
        raise ValueError("Недопустимый диапазон AWG")
    ends = tuple(int(part) for part in value.split("-"))
    if not minimum <= ends[0] <= ends[-1] <= maximum:
        raise ValueError("Недопустимые границы диапазона AWG")
    return ends[0], ends[-1]


@dataclass(frozen=True, slots=True)
class V31:
    header_key: str = field(repr=False)
    content_padding: str = "16-64"
    rekey_after: str = "120-150"
    rekey_timeout: str = "5-8"
    reject_after: str = "180-240"
    keepalive_timeout: str = "10-15"
    max_handshakes: str = "15-20"
    random_trailers: bool = True
    disable_cookies: bool = False

    def __post_init__(self) -> None:
        key(self.header_key)
        ranges = {name: bounds(getattr(self, name), lo, hi) for _, name, lo, hi in _V31_LIMITS}
        if (ranges["rekey_after"][1] >= ranges["reject_after"][0]
                or ranges["keepalive_timeout"][1] >= ranges["rekey_after"][0]
                or type(self.random_trailers) is not bool or type(self.disable_cookies) is not bool):
            raise ValueError("Несогласованные параметры AWG 3.1")

    def lines(self) -> tuple[str, ...]:
        return (f"HeaderProtectionKey = {self.header_key}",
                *(f"{option} = {getattr(self, name)}" for option, name, _, _ in _V31_LIMITS),
                f"RandomTrailers = {'on' if self.random_trailers else 'off'}",
                f"DisableCookies = {'on' if self.disable_cookies else 'off'}")


@dataclass(frozen=True, slots=True)
class Profile:
    mode: str = "legacy"
    junk_count: int = 4
    junk_min: int = 40
    junk_max: int = 120
    padding: tuple[int, ...] = (80, 120)
    headers: tuple[str, ...] = ("143762019", "203887624", "311448552", "485014192")
    tagged: tuple[str, ...] = ()
    v31: V31 | None = None

    def __post_init__(self) -> None:
        if self.mode not in ("legacy", "3.1") or ((self.mode == "3.1") != isinstance(self.v31, V31)):
            raise ValueError("Выберите один профиль AWG: legacy или 3.1")
        if self.mode == "legacy" and self.v31 is not None:
            raise ValueError("Legacy не принимает расширения AWG 3.1")
        if (any(type(value) is not int for value in (self.junk_count, self.junk_min, self.junk_max))
                or not 0 <= self.junk_count <= 16 or not 0 <= self.junk_min <= self.junk_max <= 65535):
            raise ValueError("Недопустимые параметры junk AWG")
        low = 12 if self.v31 else 0
        if (not isinstance(self.padding, tuple) or len(self.padding) != (4 if self.v31 else 2)
                or any(type(value) is not int or not low <= value <= 128 for value in self.padding)
                or 148 + self.padding[0] == 92 + self.padding[1]):
            raise ValueError("Недопустимое заполнение AWG")
        if not isinstance(self.headers, tuple) or len(self.headers) != 4:
            raise ValueError("Требуются четыре заголовка AWG")
        intervals = sorted(bounds(value, 5, 2**32 - 1) for value in self.headers)
        if any(left[1] >= right[0] for left, right in zip(intervals, intervals[1:])):
            raise ValueError("Заголовки AWG не должны пересекаться")
        if not isinstance(self.tagged, tuple) or len(self.tagged) > 5 or any(
                not isinstance(value, str) or len(value) > 512 or value != "" and not _JUNK_TAGS.fullmatch(value)
                for value in self.tagged):
            raise ValueError("Некорректные сигнатуры пакетов AWG")

    @classmethod
    def modern(cls, header_key: str) -> "Profile":
        return cls(mode="3.1", padding=(80, 120, 32, 48), v31=V31(header_key))

    def lines(self) -> tuple[str, ...]:
        return (f"Jc = {self.junk_count}", f"Jmin = {self.junk_min}", f"Jmax = {self.junk_max}",
                *(f"S{i} = {value}" for i, value in enumerate(self.padding, 1)),
                *(f"H{i} = {value}" for i, value in enumerate(self.headers, 1)),
                *(f"I{i} = {value}" for i, value in enumerate(self.tagged, 1) if value),
                *(self.v31.lines() if self.v31 else ()))


def server(settings, profile: Profile) -> bytes:
    if not isinstance(profile, Profile):
        raise ValueError("Требуется типизированный профиль AWG")
    return render_server(AWG, settings, obfuscation=profile.lines())


def client(settings, peer, profile: Profile, **options) -> bytes:
    if not isinstance(profile, Profile):
        raise ValueError("Требуется типизированный профиль AWG")
    return render_client(AWG, settings, peer, obfuscation=profile.lines(), **options)
