# Runtime

Владелец plan/result/runner/verification для контролируемого apply.

## Public API

- immutable `ApplyPlan` и шаги;
- `ApplyResult`/status contract v1;
- bounded runner и runtime verification.

## Imports

- Разрешены stdlib, `core` и protocol outputs.
- Запрещены Flask, portal routes и CLI parser.
- Команды только argv-list, без shell/eval; секреты не включать в result.

## Проверки

```bash
python3 -m unittest -v tests.test_runtime_architecture tests.test_kvn_state_apply
python3 tools/architecture_check.py
```
