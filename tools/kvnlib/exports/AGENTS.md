# Exports

Владелец политики endpoint/SNI и сборки пользовательских конфигураций в памяти.

## Public API

- `ExportPolicy` и нормализация address mode;
- renderers ссылок/конфигов;
- allowlisted ZIP bundle без записи secrets на диск.

## Imports

- Разрешены stdlib, `core`, чистые protocol DTO.
- Запрещены Flask, `portal`, CLI, `runtime`, subprocess и Telegram API.

## Проверки

```bash
python3 -m unittest -v tests.test_exports_architecture tests.test_client_export
python3 tools/architecture_check.py
```
