"""Архитектурная граница независимого доменного ядра v5."""

import ast
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CORE = ROOT / "v5" / "core"
FORBIDDEN = ("portal", "tools.kvnlib.runtime", "tools.kvnlib.commands")


def forbidden_imports(code):
    """Проверить прямой, from- и динамический импорт legacy-компонентов."""
    forbidden = []
    for node in ast.walk(ast.parse(code)):
        names = []
        if isinstance(node, ast.Import):
            names = [item.name for item in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module] + [node.module + "." + item.name for item in node.names]
        for name in names:
            if any(name == prefix or name.startswith(prefix + ".") for prefix in FORBIDDEN):
                forbidden.append(name)
            if name == "importlib" or name.startswith("importlib."):
                forbidden.append(name)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "__import__":
            forbidden.append("__import__")
    return forbidden


class CoreBoundaryTests(unittest.TestCase):
    def test_core_has_no_legacy_ui_or_runtime_imports(self):
        self.assertTrue(CORE.is_dir(), "Ядро отсутствует")
        sources = list(CORE.rglob("*.py"))
        self.assertTrue(sources, "Нет файлов ядра для проверки")
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(forbidden_imports(source.read_text(encoding="utf-8")), [])

    def test_boundary_detects_import_variants(self):
        for statement in ("import portal.app", "from tools.kvnlib import runtime",
                          "from tools.kvnlib.commands import parser", "import importlib",
                          "__import__('portal')"):
            with self.subTest(statement=statement):
                self.assertTrue(forbidden_imports(statement))
        self.assertEqual(forbidden_imports("import json\nfrom pathlib import Path"), [])

    def test_architecture_names_versioned_contracts(self):
        text = (ROOT / "v5" / "ARCHITECTURE.md").read_text(encoding="utf-8")
        for contract in ("core/v1", "adapter/v1", "package/v1", "grants/v1"):
            self.assertIn(contract, text)

    def test_core_exists_and_module_allowlist_excludes_openconnect(self):
        source = CORE / "contracts.py"
        self.assertTrue(source.is_file(), "Ядро отсутствует: проверка импортов была бы пустой")
        spec = importlib.util.spec_from_file_location("v5_contracts_test", source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.validate_module_id("xray"), "xray")
        for value in ("ocserv", "../xray", "Xray", "", None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.validate_module_id(value)


if __name__ == "__main__":
    unittest.main()
