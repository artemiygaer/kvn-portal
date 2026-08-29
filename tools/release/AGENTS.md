# Release

Владелец canonical staging, deploy/full archive validation, publication manifest и v3→v4 migration.

## Public API

- `inspect_update_artifact`, `validate_release`, `inspect_archive`;
- deterministic canonical staging/full release;
- `plan_migration`, `extract_legacy_bootstrap`.

## Imports

- Разрешены stdlib и self-contained legacy `tools.deploy_archive` seam.
- Запрещены Flask, `portal`, runtime apply, CLI commands и чтение runtime secrets.
- Любая проверка выполняется до source mutation; archive extraction только allowlist.

## Проверки

```bash
python3 -m unittest -v tests.test_release_pipeline_architecture tests.test_deploy tests.test_runtime_images
python3 tools/architecture_check.py
```
