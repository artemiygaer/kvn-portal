"""Размер собственных ресурсов, загружаемых вместе одной страницей."""
import re
from pathlib import Path


def page_asset_bundles(root: Path) -> dict[str, set[Path]]:
    templates = root / "portal/app/templates"
    static = root / "portal/app/static"
    references = re.compile(r"filename=['\"]([^'\"]+\.(?:js|css))['\"]")
    common = set(references.findall((templates / "base.html").read_text(encoding="utf-8")))
    bundles = {}
    for template in templates.glob("*.html"):
        text = template.read_text(encoding="utf-8")
        if 'extends "base.html"' not in text and "extends 'base.html'" not in text:
            continue
        names = common | set(references.findall(text))
        # xterm — отдельная закреплённая vendor-библиотека, не собственный JS.
        bundles[template.name] = {static / name for name in names if not name.startswith("vendor/")}
    return bundles
