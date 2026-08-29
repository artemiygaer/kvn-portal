# Архитектура KVN VPN v4

KVN VPN v4 — модульный монолит: один репозиторий и единый deploy, но зависимости направлены от интерфейсов к доменным модулям. Это позволяет менять одну область, не загружая агенту весь проект.

## Направление зависимостей

```text
Web routes -> agent facade -> Unix RPC -> agent handlers -> control services
     |                              |                |
     +------------------------------+----------------+
                                    v
CLI commands -----------------> core / protocols / exports / runtime

setup/update/GitHub ----------> release
```

- `tools/kvnlib/core` не знает о Flask, CLI, RPC и выполнении команд.
- `protocols` и `exports` строят данные детерминированно и не применяют их.
- `runtime` исполняет явный plan и возвращает нормализованный result.
- `commands` — адаптер CLI; бизнес-правила должны уходить в нижние модули.
- `portal/control` — application services без Flask и транспорта.
- `portal/agent_handlers` — единственная привилегированная RPC-граница.
- `portal/app/routes` — HTTP/UI-адаптер; root-команды ему недоступны.
- `tools/release` отвечает за canonical tree, артефакты и миграции.

Машинная проверка границ: `python3 tools/architecture_check.py`. Локальные правила каждого владельца находятся в его `AGENTS.md`.

## Маршрутизация задач

Открывайте сначала только файлы из столбца «Минимальный контекст». Расширяйте контекст лишь после воспроизведения проблемы.

| Задача | Владелец | Минимальный контекст | Минимальная проверка |
|---|---|---|---|
| Изменить схему `users.json` | core | `tools/kvnlib/core/schema.py`, `validation.py` | `tests/test_core_state.py` |
| Исправить atomic read/write или revision | core | `tools/kvnlib/core/io.py`, `state.py` | `tests/test_core_state.py`, `tests/test_kvn_state_apply.py` |
| Изменить AmneziaWG render/verify | protocols | `protocols/amneziawg/`, legacy seam в `commands/implementation.py` | `tests/test_host_protocol_packages.py` |
| Изменить WireGuard render/verify | protocols | `protocols/wireguard/` | `tests/test_host_protocol_packages.py` |
| Изменить Xray Reality/XHTTP | protocols | `protocols/xray/`, `protocols/sni/` | `tests/test_proxy_protocol_packages.py` |
| Изменить Hysteria/SNI | protocols | `protocols/hysteria/`, `protocols/sni/` | `tests/test_proxy_protocol_packages.py` |
| Изменить MTProto/Telemt/MTG | protocols | `protocols/mtproto/` | `tests/test_proxy_protocol_packages.py` |
| Изменить ZIP/QR/ссылки пользователя | exports | `tools/kvnlib/exports/` | `tests/test_exports_architecture.py`, `tests/test_client_export.py` |
| Изменить apply/reload/restart | runtime | `tools/kvnlib/runtime/` | `tests/test_runtime_architecture.py`, `tests/test_kvn_state_apply.py` |
| Добавить или изменить CLI-команду | CLI | `tools/kvnlib/commands/parser.py` и один тематический модуль | `tests/test_cli_facade_architecture.py`, тематический CLI-тест |
| Изменить бизнес-операцию портала | control | один файл `portal/control/*.py` | `tests/test_control_services_architecture.py`, тематический portal-тест |
| Добавить RPC host-agent | agent | один handler, `registry.py`, `agent_protocol.py` | `tests/test_agent_handlers_architecture.py`, `tests/test_portal_agent.py` |
| Исправить Unix socket/reconnect | agent bridge | `portal/agent.py`, `agent_client.py`, `install-host-agent.sh` | `tests/test_runtime_bridge.py` |
| Добавить HTTP route или форму | routes | один blueprint, `routes/implementation.py`, один template | `tests/test_portal_routes_architecture.py`, `portal/tests/test_*.py` |
| Исправить dashboard/SWR | routes + agent | `portal/app/cache.py`, dashboard handler и JS | `tests/test_observability.py`, `portal/tests/test_observability.py` |
| Изменить deploy allowlist | release | `tools/deploy_archive.py`, `tools/canonical-files.txt` | `tests/test_deploy.py`, `tests/test_upgrade_contracts.py` |
| Изменить full offline release | release | `tools/release/full_archive.py`, `tools/build-release.sh` | `tests/test_runtime_images.py`, `tests/test_offline_release.py` |
| Изменить v3→v4 bootstrap/rollback | release | `tools/release/migrations.py`, `update.sh` | `tests/test_release_pipeline_architecture.py`, `tests/test_deploy.py` |
| Обновить документацию | docs | нужный `.md`, `tools/docs_check.py` | `python3 tools/docs_check.py` |

## Контракты, которые нельзя обходить

- `users.json` — единственный source of truth; generated/runtime не редактируется вручную.
- Доменный код не импортирует Flask, portal routes или CLI.
- Web-контейнер не получает Docker socket; privileged операции идут только через allowlisted Unix RPC.
- Render и inspection не запускают команды. Применение выполняет только runtime/host-agent.
- Release валидируется до mutation; до Compose действует полный snapshot rollback.
- Публичные facade-модули сохраняются для v3-совместимости, новая логика размещается у владельца.

## Полный gate

```bash
python3 tools/architecture_check.py
python3 tools/docs_check.py
python3 -m unittest discover -s tests -v
cd portal && PYTHONPATH=. python3 -m unittest discover -s tests -v
```

Контейнерные, shell и deploy-проверки перечислены в корневом `AGENTS.md`.
