"""Контракты независимого ядра состояния v4."""

import ast
import json
import tempfile
import unittest
from pathlib import Path

from tools.kvnlib import JsonStateStore as PublicStore
from tools.kvnlib.core import (
    CURRENT_STATE_SCHEMA_VERSION,
    JsonStateStore,
    ProjectPaths,
    StateRevisionConflict,
    StateValidationError,
    atomic_write_json,
    migrate_state,
    redact_secrets,
    state_revision,
)
from tools.kvnlib.state import JsonStateStore as LegacyStore


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "tools" / "kvnlib" / "core"


class CoreImportBoundaryTests(unittest.TestCase):
    def test_core_has_no_infrastructure_or_protocol_imports(self):
        forbidden = {"flask", "docker", "subprocess", "systemd", "portal", "protocols"}
        violations = []
        for path in sorted(CORE.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    root_name = name.lstrip(".").split(".")[0]
                    if root_name in forbidden:
                        violations.append(f"{path.name}:{node.lineno}:{name}")
        self.assertEqual(violations, [])

    def test_legacy_and_public_imports_are_compatible(self):
        self.assertIs(LegacyStore, JsonStateStore)
        self.assertIs(PublicStore, JsonStateStore)


class CoreMigrationTests(unittest.TestCase):
    def test_v3_migration_is_explicit_idempotent_and_non_mutating(self):
        legacy = {"server": "example.invalid", "users": []}
        before = json.dumps(legacy, sort_keys=True)
        first = migrate_state(legacy)
        second = migrate_state(first)
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], CURRENT_STATE_SCHEMA_VERSION)
        self.assertEqual(json.dumps(legacy, sort_keys=True), before)

    def test_errors_and_log_dto_do_not_expose_secrets(self):
        secret = "DO_NOT_EXPOSE_VALUE"
        with self.assertRaises(StateValidationError) as caught:
            migrate_state({"schema_version": secret, "users": []})
        self.assertNotIn(secret, str(caught.exception))
        safe = redact_secrets({"password": secret, "nested": {"private_key": secret}})
        self.assertNotIn(secret, json.dumps(safe))

    def test_project_paths_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = ProjectPaths.from_root(temporary)
            self.assertEqual(paths.users, paths.root / "users.json")
            self.assertEqual(paths.portal_runtime, paths.root / "portal-runtime" / "users.json")


class CoreTransactionTests(unittest.TestCase):
    def test_migrated_load_and_revision_conflict_are_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "users.json"
            atomic_write_json(path, {"users": [], "counter": 0})
            store = JsonStateStore(path, root / ".lock")
            revision = state_revision(store.load())
            self.assertEqual(store.load(migrate=True)["schema_version"], 3)
            store.update(lambda state: state.update(counter=1))
            before = path.read_bytes()
            with self.assertRaises(StateRevisionConflict):
                store.save({"users": [], "counter": 2}, expected_revision=revision)
            self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
