"""Архитектурные контракты модульных HTTP routes портала."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from portal.app.blueprints.catalog import ROUTES


ROOT = Path(__file__).resolve().parents[1]


class PortalRoutesArchitectureTests(unittest.TestCase):
    def test_views_facade_is_small_and_compat_factory_is_removed(self):
        facade = ROOT / "portal/app/blueprints/views.py"
        self.assertLessEqual(len(facade.read_text(encoding="utf-8").splitlines()), 150)
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "portal/app/blueprints").glob("*.py")
        )
        self.assertNotIn("make_compat_blueprint", source)
        for module in ("auth", "users", "services", "diagnostics", "settings", "updates"):
            self.assertIn("create_blueprint", (ROOT / f"portal/app/blueprints/{module}.py").read_text(encoding="utf-8"))

    def test_route_modules_do_not_depend_on_rpc_js_or_templates(self):
        for name in ("auth", "users", "services", "diagnostics", "settings", "updates"):
            source = (ROOT / f"portal/app/blueprints/{name}.py").read_text(encoding="utf-8")
            with self.subTest(module=name):
                self.assertNotIn("agent_client", source)
                self.assertNotIn("render_template", source)
                self.assertNotIn("static/", source)
                self.assertNotIn("subprocess", source)

    def test_every_portal_mutation_route_is_session_bound(self):
        implementation = ROOT / "portal/app/routes/implementation.py"
        tree = ast.parse(implementation.read_text(encoding="utf-8"))
        factory = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "build_views"
        )
        decorators = {
            node.name: {ast.unparse(item) for item in node.decorator_list}
            for node in factory.body
            if isinstance(node, ast.FunctionDef)
        }
        public_post = {"login", "hysteria_auth"}
        mutations = {
            route.endpoint
            for route in ROUTES
            if "POST" in route.methods and route.endpoint not in public_post
        }
        self.assertTrue(mutations)
        self.assertEqual(
            {name for name in mutations if "require_session" in decorators.get(name, set())},
            mutations,
        )
