import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DocumentationCheckTests(unittest.TestCase):
    def test_public_documentation_contract(self):
        result = subprocess.run(
            [sys.executable, "tools/docs_check.py"],
            cwd=ROOT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("[OK]", result.stdout)


if __name__ == "__main__":
    unittest.main()
