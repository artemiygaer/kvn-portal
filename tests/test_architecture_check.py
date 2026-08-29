"""Положительный и отрицательный контракт направленности импортов."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.architecture_check import RULES, check


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureCheckTests(unittest.TestCase):
    def test_current_tree_respects_layer_boundaries(self):
        self.assertEqual(check(ROOT), [])

    def test_synthetic_domain_to_flask_and_runtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for rule in RULES:
                module = root / rule.path
                module.mkdir(parents=True, exist_ok=True)
                (module / "__init__.py").write_text("", encoding="utf-8")
            violation = root / "tools/kvnlib/core/violation.py"
            violation.write_text(
                "import flask\nfrom tools.kvnlib import runtime\n",
                encoding="utf-8",
            )
            violations = check(root)
        self.assertEqual(
            {(item["import"], item["rule"]) for item in violations},
            {
                ("flask", "forbidden:flask"),
                ("tools.kvnlib.runtime", "forbidden:tools.kvnlib.runtime"),
            },
        )


if __name__ == "__main__":
    unittest.main()
