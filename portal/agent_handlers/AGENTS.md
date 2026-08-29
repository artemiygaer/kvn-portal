# Host-agent handlers

Единственная привилегированная RPC-граница. Каждый метод обязан быть allowlisted, типизирован и классифицирован как read-only или mutation.

## Public API

- immutable `HandlerSpec` registry;
- handlers services/users/dashboard/protocols/updates/backup/shell;
- `AgentDispatcher` как composition adapter.

## Imports

- Разрешены `portal.control`, release/runtime APIs и bounded system adapters.
- Запрещены Flask, portal routes/templates и универсальный exec RPC.
- Secrets не возвращать в response, audit или exception message.

## Проверки

```bash
python3 -m unittest -v tests.test_agent_handlers_architecture tests.test_portal_agent tests.test_runtime_bridge
python3 tools/architecture_check.py
```
