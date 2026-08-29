# Portal control services

Application services портала: пользователи, протоколы, диагностика, exports и updates без HTTP/RPC транспорта.

## Public API

- функции тематических модулей `users`, `services`, `protocols`, `diagnostics`, `exports`, `updates`;
- совместимый facade `portal/control.py`.

## Imports

- Разрешены stdlib и публичные `tools.kvnlib` API.
- Запрещены Flask, templates, request/session и `agent_handlers`.
- Привилегированные команды сюда не добавлять.

## Проверки

```bash
python3 -m unittest -v tests.test_control_services_architecture tests.test_portal_control
python3 tools/architecture_check.py
```
