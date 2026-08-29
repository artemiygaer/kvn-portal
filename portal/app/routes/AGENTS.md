# Portal routes

HTTP/UI-адаптер Flask. Route валидирует input, вызывает agent facade/control query и отображает безопасный результат.

## Public API

- blueprint factories auth/users/services/diagnostics/settings/updates;
- route catalog и совместимый `blueprints/views.py` facade.

## Imports

- Разрешены Flask и `portal.app` facade-модули.
- Запрещены `agent_handlers`, root helpers, subprocess, Docker socket и прямое чтение `users.json`.
- POST возвращает в исходную settings-группу; secrets не попадут в audit/HTML.

## Проверки

```bash
python3 -m unittest -v tests.test_portal_routes_architecture
cd portal && PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 tools/architecture_check.py
```
