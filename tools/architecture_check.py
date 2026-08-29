#!/usr/bin/env python3
"""Проверяет направленность импортов модульного монолита KVN."""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LayerRule:
    path: str
    forbidden: tuple[str, ...]


RULES = (
    LayerRule("tools/kvnlib/core", ("flask", "portal", "tools.kvnlib.runtime", "tools.kvnlib.commands")),
    LayerRule("tools/kvnlib/protocols", ("flask", "portal", "tools.kvnlib.runtime", "tools.kvnlib.commands")),
    LayerRule("tools/kvnlib/exports", ("flask", "portal", "tools.kvnlib.runtime", "tools.kvnlib.commands")),
    LayerRule("tools/kvnlib/runtime", ("flask", "portal", "tools.kvnlib.commands")),
    LayerRule("tools/kvnlib/commands", ("flask", "portal.app")),
    LayerRule("portal/control", ("flask", "portal.app", "portal.agent_handlers")),
    LayerRule("portal/agent_handlers", ("flask", "portal.app")),
    LayerRule("portal/app/routes", ("portal.agent_handlers", "tools.kvnlib.commands")),
    LayerRule("tools/release", ("flask", "portal", "tools.kvnlib.runtime", "tools.kvnlib.commands")),
)


def _module_name(root: Path, path: Path) -> tuple[str, bool]:
    relative = path.relative_to(root).with_suffix("")
    parts = list(relative.parts)
    is_package = bool(parts and parts[-1] == "__init__")
    if is_package:
        parts.pop()
    return ".".join(parts), is_package


def _resolved_imports(root: Path, path: Path) -> list[tuple[int, str]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    current, is_package = _module_name(root, path)
    package = current.split(".") if is_package else current.split(".")[:-1]
    result: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                trim = max(0, node.level - 1)
                base = package[: len(package) - trim] if trim else package
                module = ".".join([*base, *(node.module or "").split(".")]).rstrip(".")
            else:
                module = node.module or ""
            if module:
                names = [alias.name for alias in node.names if alias.name != "*"]
                if names:
                    result.extend((node.lineno, f"{module}.{name}") for name in names)
                else:
                    result.append((node.lineno, module))
    return result


def _matches(module: str, forbidden: str) -> bool:
    return module == forbidden or module.startswith(forbidden + ".")


def check(root: Path) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    for rule in RULES:
        module_root = root / rule.path
        if not module_root.is_dir():
            violations.append({"file": rule.path, "line": 0, "import": "", "rule": "module_missing"})
            continue
        for path in sorted(module_root.rglob("*.py")):
            try:
                imports = _resolved_imports(root, path)
            except (OSError, SyntaxError) as exc:
                violations.append({
                    "file": path.relative_to(root).as_posix(),
                    "line": getattr(exc, "lineno", 0) or 0,
                    "import": "",
                    "rule": "source_invalid",
                })
                continue
            for line, module in imports:
                for forbidden in rule.forbidden:
                    if _matches(module, forbidden):
                        violations.append({
                            "file": path.relative_to(root).as_posix(),
                            "line": line,
                            "import": module,
                            "rule": f"forbidden:{forbidden}",
                        })
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка архитектурных импортов KVN")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    violations = check(root)
    if args.json:
        print(json.dumps({"ok": not violations, "violations": violations}, ensure_ascii=False, sort_keys=True))
    elif violations:
        for item in violations:
            print(
                f"[ОШИБКА] {item['file']}:{item['line']}: {item['rule']} ({item['import']})",
                file=sys.stderr,
            )
        print(f"[ИТОГ] Архитектура: нарушений {len(violations)}", file=sys.stderr)
    else:
        print(f"[OK] Архитектура: {len(RULES)} границ модулей, обратных импортов нет")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
