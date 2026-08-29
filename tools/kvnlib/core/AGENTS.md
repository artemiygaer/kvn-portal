# Core

Владелец схемы, валидации, путей, atomic I/O и revision state. Код должен быть чистым от UI и выполнения системных команд.

## Public API

- `StateStore`, `StateSnapshot`, `load_state`, `save_state`;
- schema/default/normalization helpers;
- typed core errors и безопасные path helpers.

## Imports

- Разрешены stdlib и соседние модули `core`.
- Запрещены Flask, `portal`, `commands`, `runtime`, Docker/systemd/subprocess.

## Проверки

```bash
python3 -m unittest -v tests.test_core_state tests.test_kvn_state_apply
python3 tools/architecture_check.py
```
