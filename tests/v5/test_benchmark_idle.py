"""Проверки корректности ограничений измерителя cgroup."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[2] / "v5" / "tools" / "benchmark_idle.py"
SPEC = importlib.util.spec_from_file_location("benchmark_idle", PATH)
BENCHMARK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCHMARK)


class BenchmarkTests(unittest.TestCase):
    def test_reads_cpu_and_memory_without_clamping(self):
        with tempfile.TemporaryDirectory() as temp:
            group = Path(temp)
            (group / "cpu.stat").write_text("usage_usec 400\nuser_usec 200\n", encoding="utf-8")
            (group / "memory.current").write_text("12345\n", encoding="utf-8")
            self.assertEqual(BENCHMARK.read_usage(group), (400, 12345))

    def test_rejects_duplicate_nested_and_outside_groups(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a" / "nested").mkdir(parents=True)
            self.assertEqual(BENCHMARK.validate_groups(["a"], root), [(root / "a").resolve()])
            for paths in (["a", "a"], ["a", "a/nested"], [".."], []):
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    BENCHMARK.validate_groups(paths, root)


if __name__ == "__main__":
    unittest.main()
