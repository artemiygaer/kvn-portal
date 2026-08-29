"""Контракты тонкого CLI facade и bounded command contexts."""

import argparse
import ast
import subprocess
import sys
import unittest
from pathlib import Path

from tools import kvnctl
from tools.kvnlib.commands import implementation, interactive, operations, parser, protocols, users

ROOT = Path(__file__).resolve().parents[1]
FACADE = ROOT / "tools/kvnctl.py"
COMMANDS = ROOT / "tools/kvnlib/commands"

class CliFacadeTests(unittest.TestCase):
    def test_facade_is_under_900_lines_and_has_no_duplicate_handlers(self):
        source = FACADE.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 900)
        tree = ast.parse(source)
        self.assertEqual([node.name for node in tree.body if isinstance(node, ast.FunctionDef)], [])

    def test_import_is_identity_alias_for_legacy_monkey_patches(self):
        self.assertIs(kvnctl, implementation)
        self.assertIs(users.cmd_add_user, implementation.cmd_add_user)
        self.assertIs(protocols.cmd_amneziawg, implementation.cmd_amneziawg)
        self.assertIs(operations.cmd_render, implementation.cmd_render)
        self.assertIs(interactive.cmd_interactive, implementation.cmd_interactive)
        self.assertIs(parser.build_parser, implementation.build_parser)

    def test_command_modules_do_not_import_flask(self):
        violations = []
        for path in COMMANDS.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                if any(name and name.split(".")[0] == "flask" for name in names):
                    violations.append(f"{path}:{node.lineno}")
        self.assertEqual(violations, [])

    def test_representative_help_and_validation_exit_codes(self):
        help_run = subprocess.run([sys.executable, str(FACADE), "--help"], cwd=ROOT, text=True, capture_output=True, check=False)
        invalid = subprocess.run([sys.executable, str(FACADE), "unknown-command"], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(help_run.returncode, 0)
        self.assertIn("add-user", help_run.stdout)
        self.assertEqual(invalid.returncode, 2)

    def test_parser_handlers_are_shared_between_interactive_and_noninteractive_paths(self):
        built = implementation.build_parser()
        add = next(action for action in built._actions if isinstance(action, argparse._SubParsersAction)).choices["add-user"]
        self.assertIs(add.get_default("func"), implementation.cmd_add_user)
        source = implementation.cmd_interactive.__code__.co_names
        self.assertIn("cmd_add_user", source)
        self.assertIn("cmd_edit_user", source)

if __name__ == "__main__":
    unittest.main()
