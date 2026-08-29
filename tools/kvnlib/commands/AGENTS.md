# CLI commands

Адаптер argparse/interactive над core, protocols, exports и runtime. `tools/kvnctl.py` остаётся тонким facade.

## Public API

- `build_parser`, `main`;
- тематические handlers users/protocols/operations;
- совместимые exit codes и русские operator messages.

## Imports

- Разрешены нижние `tools.kvnlib` и безопасные release helpers.
- Запрещены Flask, portal routes и прямое обращение к request/session.
- Новые бизнес-правила выносить из `implementation.py` владельцу домена.

## Проверки

```bash
python3 -m unittest -v tests.test_cli_facade_architecture tests.test_kvnctl_security
python3 tools/architecture_check.py
```
