# Protocols

Владелец детерминированных render/verify правил VPN-протоколов и SNI. Не применяет конфигурацию и не читает web request.

## Public API

- registry протоколов;
- `render_*`, `verify_*`, SNI collision/policy helpers;
- typed immutable результаты рендера.

## Imports

- Разрешены stdlib и `core`.
- Запрещены Flask, `portal`, CLI, `runtime`, subprocess и запись generated-файлов напрямую.

## Проверки

```bash
python3 -m unittest -v tests.test_host_protocol_packages tests.test_proxy_protocol_packages
python3 tools/architecture_check.py
```
