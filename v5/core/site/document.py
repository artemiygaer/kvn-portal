"""Нормализация одностраничного HTML и атомарная публикация без активного кода."""

from html import escape
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import stat
from tempfile import NamedTemporaryFile
from urllib.parse import urlsplit


MAX_HTML_BYTES = 128 * 1024
MAX_SITE_FORM = MAX_HTML_BYTES + 8 * 1024
SITE_CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
            "base-uri 'none'; form-action 'none'; sandbox allow-top-navigation-by-user-activation")
DEFAULT_SITE = ("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><title>KVN</title></head>"
                "<body><main><h1>Добро пожаловать</h1><p>Сервер KVN работает.</p></main></body></html>\n").encode()
_TAGS = frozenset("html head title body main nav header footer section article aside div span h1 h2 h3 h4 h5 h6 "
                  "p a img picture figure figcaption strong em b i s u small code pre blockquote time dl dt dd "
                  "ul ol li br hr table caption thead tbody tfoot tr td th meta style".split())
_VOID = frozenset({"br", "hr", "img", "meta"})
_GLOBAL = frozenset({"id", "class", "lang", "dir", "title", "style"})
_BY_TAG = {"a": {"href"}, "img": {"src", "alt", "height", "width"}, "meta": {"charset", "name", "content"},
           "time": {"datetime"}, "td": {"colspan", "rowspan"}, "th": {"scope", "colspan", "rowspan"}}
_IMAGE = re.compile(r"data:image/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}\Z", re.ASCII)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _safe_href(value: str) -> bool:
    if _CONTROL.search(value) or "\\" in value or value != value.strip():
        return False
    if value.startswith("#"):
        return True
    try:
        url = urlsplit(value)
        return url.scheme == "https" and bool(url.hostname) and url.username is None and url.password is None
    except ValueError:
        return False


class UnsafeDocument(ValueError):
    """Пользовательский HTML не удовлетворяет политике публичной страницы."""


class _StaticHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.output = ["<!doctype html>"]

    def handle_decl(self, decl: str) -> None:
        if decl.strip().lower() != "doctype html":
            raise UnsafeDocument("Допускается только doctype HTML")

    def unknown_decl(self, data: str) -> None:
        raise UnsafeDocument("Недопустимое объявление HTML")

    def handle_pi(self, data: str) -> None:
        raise UnsafeDocument("Инструкции обработки в HTML запрещены")

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _TAGS or len(self.stack) >= 64:
            raise UnsafeDocument("Недопустимый тег или слишком глубокая вложенность HTML")
        values: dict[str, str] = {}
        for name, value in attrs:
            if (name in values or value is None or name not in (_GLOBAL | _BY_TAG.get(tag, set()))
                    or _CONTROL.search(value)):
                raise UnsafeDocument("Недопустимый атрибут HTML")
            values[name] = value
        if tag == "meta":
            charset = set(values) == {"charset"} and values["charset"].lower() == "utf-8"
            viewport = set(values) == {"name", "content"} and values["name"].lower() == "viewport"
            if not (charset or viewport):
                raise UnsafeDocument("Допускаются только meta charset UTF-8 и viewport")
        if "href" in values:
            if not _safe_href(values["href"]):
                raise UnsafeDocument("Ссылка должна быть HTTPS или якорем")
            values["rel"] = "noopener noreferrer"
        if "src" in values and not _IMAGE.fullmatch(values["src"]):
            raise UnsafeDocument("Изображение должно быть встроенным PNG, JPEG, GIF или WebP")
        rendered = "".join(f' {key}="{escape(value, quote=True)}"' for key, value in values.items())
        self.output.append(f"<{tag}{rendered}>")
        if tag not in _VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in _VOID:
            raise UnsafeDocument("Самозакрывающийся тег HTML недопустим")
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack or self.stack[-1] != tag:
            raise UnsafeDocument("Неверная вложенность HTML")
        self.stack.pop()
        self.output.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1] == "style":
            if "<" in data:
                raise UnsafeDocument("Недопустимые символы во встроенном CSS")
            self.output.append(data)
        else:
            self.output.append(escape(data, quote=False))


def validate_html(source: bytes) -> bytes:
    """Один и тот же фильтр для предпросмотра и публикации."""
    if not isinstance(source, bytes) or not 1 <= len(source) <= MAX_HTML_BYTES:
        raise UnsafeDocument("Нужен непустой HTML-файл до 128 КиБ")
    try:
        text = source.decode("utf-8-sig")
    except UnicodeError as exc:
        raise UnsafeDocument("HTML должен быть в UTF-8") from exc
    if not text.strip() or "\x00" in text:
        raise UnsafeDocument("HTML пуст или содержит NUL")
    parser = _StaticHTML()
    parser.feed(text)
    parser.close()
    if parser.stack:
        raise UnsafeDocument("В HTML остались незакрытые теги")
    normalized = "".join(parser.output).encode("utf-8")
    if len(normalized) > MAX_HTML_BYTES:
        raise UnsafeDocument("HTML после обработки превышает 128 КиБ")
    return normalized


class SiteStore:
    """Запись только фиксированного index.html в выделенный каталог сайта."""

    def __init__(self, directory: Path):
        self.directory = directory

    def status(self) -> dict:
        fd = os.open(self.directory / "index.html", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            attrs = os.fstat(stream.fileno())
            if not stat.S_ISREG(attrs.st_mode) or attrs.st_uid != os.geteuid() or attrs.st_mode & 0o022:
                raise OSError("Недопустимый файл публичной страницы")
            return {"customized": stream.read(len(DEFAULT_SITE) + 1) != DEFAULT_SITE}

    def _replace(self, validated: bytes) -> None:
        candidate = None
        try:
            with NamedTemporaryFile(mode="wb", prefix=".page-", dir=self.directory, delete=False) as stream:
                candidate = Path(stream.name)
                stream.write(validated)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
            os.replace(candidate, self.directory / "index.html")
        finally:
            if candidate is not None:
                candidate.unlink(missing_ok=True)

    def publish(self, source: bytes) -> None:
        self._replace(validate_html(source))

    def reset(self) -> None:
        self._replace(DEFAULT_SITE)
