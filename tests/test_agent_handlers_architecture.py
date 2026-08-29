"""Архитектурные и security-контракты модульного host-agent."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from portal.agent import AgentApplication, AgentDispatcher, mutation_lock_scope
from portal.agent_handlers.registry import build_handler_registry
from portal.agent_protocol import ALLOWED_METHODS, MUTATION_METHODS, ProtocolError, RpcRequest


class _Runner:
    def __init__(self):
        self.calls = []

    def run(self, argv, **_kwargs):
        self.calls.append(tuple(argv))
        raise AssertionError("Привилегированная команда не должна выполняться.")


class _RejectingDispatcher:
    calls = 0

    def dispatch(self, _request):
        self.calls += 1
        raise AssertionError("Неизвестный RPC не должен доходить до dispatcher.")


class AgentHandlersArchitectureTests(unittest.TestCase):
    def test_registry_is_immutable_complete_and_exactly_classified(self):
        registry = build_handler_registry(AgentDispatcher(Path("/srv/kvn"), _Runner()))
        self.assertEqual(set(registry), set(ALLOWED_METHODS))
        self.assertEqual(
            {name for name, spec in registry.items() if spec.mutates},
            set(MUTATION_METHODS),
        )
        with self.assertRaises(TypeError):
            registry["arbitrary.shell"] = registry["ping"]

    def test_unknown_method_and_extra_params_fail_before_privileged_execution(self):
        runner = _Runner()
        dispatcher = AgentDispatcher(Path("/srv/kvn"), runner)
        with self.assertRaises(ProtocolError) as caught:
            dispatcher.dispatch(RpcRequest("extra", "ping", {"command": "id"}))
        self.assertEqual(caught.exception.code, "invalid_params")
        self.assertEqual(runner.calls, [])

        app = AgentApplication("a" * 64, _RejectingDispatcher())
        response = app.handle_line(json.dumps({
            "version": 1,
            "id": "unknown",
            "secret": "a" * 64,
            "method": "arbitrary.shell",
            "params": {},
        }).encode() + b"\n")
        payload = json.loads(response)
        self.assertEqual(payload["error"]["code"], "method_not_found")

    def test_every_mutation_has_lock_scope_and_reads_do_not(self):
        self.assertTrue(all(mutation_lock_scope(name) != "read-only" for name in MUTATION_METHODS))
        self.assertTrue(all(
            mutation_lock_scope(name) == "read-only"
            for name in set(ALLOWED_METHODS) - set(MUTATION_METHODS)
        ))

    def test_shell_boundary_has_no_output_or_password_logging(self):
        root = Path(__file__).resolve().parents[1]
        source = "\n".join(
            (root / name).read_text(encoding="utf-8")
            for name in (
                "portal/agent.py",
                "portal/agent_handlers/shell.py",
                "portal/agent_handlers/dispatcher.py",
            )
        )
        self.assertNotIn("logging.", source)
        self.assertNotIn("logger.", source)
        self.assertNotIn("print(", source)
        self.assertIn("session_owner", source)
