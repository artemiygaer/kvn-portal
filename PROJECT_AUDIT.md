# Аудит проекта KVN VPN v3

Дата baseline: 23.07.2026. Аудит выполнен по каноническим исходникам без чтения и публикации production-секретов. `users.json`, generated-конфиги, клиентские файлы, сертификаты и runtime-БД не использовались как источник доказательств.

## Итог повторного аудита — 26.07.2026

- Web-приложение разделено на совместимые Blueprints; `portal/app/__init__.py` уменьшен с 2411 до 478 строк.
- Общий frontend заменён page-specific модулями: базовый `app.js` уменьшен до 113 байт, тяжёлые update/users/logs сценарии загружаются только на своих страницах.
- Экспорт использует один renderer и policy для domain/public-IP; ZIP строится в памяти по allowlist, RPC и аудит не содержат client payload.
- GitHub Release backend принимает только фиксированный репозиторий и штатные assets, а скачанный архив проходит digest/manifest validation до появления состояния ready.
- Все 20 поставляемых shell-скриптов используют `set -euo pipefail`; `mktemp` покрыт cleanup trap, `eval` отсутствует. Backup/restore получили атомарную публикацию и проверку вложенного tar.
- Актуальный локальный gate: 338 тестов успешно, 20 ожидаемых platform/Flask skip; Bash syntax, Compose config и deploy archive validator прошли. Реальный systemd/firewall и Docker lifecycle дополнительно проверяются на Debian.
- Light profile отключает до 60 тяжёлых metric samples и около 80 browser background requests в час. Portal plane ограничен суммарно 0.50 CPU, 256 MiB memory и 96 PIDs.

Промежуточные artifact SHA в документацию не записываются. Финальный SHA берётся из готового GitHub Release и `release-manifest.json`.

## Baseline перед оптимизацией портала и экспорта

| Метрика | Значение |
|---|---:|
| `portal/app/__init__.py` | 2411 строк |
| `portal/agent.py` | 2258 строк |
| `portal/control.py` | 1246 строк |
| `tools/kvnctl.py` | 8805 строк |
| Общий `app.js` | 45 834 байта, 41 `addEventListener`, 5 `fetch`, 2 XHR, 1 interval |
| `style.css` | 39 368 байт |
| Page-specific JS | `service-logs.js` 2354 байта; `user-activity.js` 8552 байта |
| Portal route endpoints | 45 |
| Allowlisted host-agent RPC | 43 |
| Linux tests | 294 успешно от root, 9 Flask cases пропущены вне portal image |
| Portal image tests | 77 успешно в Docker test target |

`app.js` загружается из `base.html` на каждой странице, хотя dashboard polling,
upload progress, shell PTY, logs, users и network используют независимые DOM
контракты. Desktop navigation, mobile navigation и command palette содержат три
ручные копии одного списка. Это основной измеримый источник frontend-избыточности.

Standard profile допускает один непересекающийся dashboard refresh и history
request; light profile устанавливает `monitoring=false` и
`background_refresh=false`, поэтому автоматические dashboard/history/network
запросы должны равняться нулю. Ручное обновление остаётся доступным.

Обезличенный контракт зафиксирован в
`tests/fixtures/baseline-contract.json` и
`tests/test_baseline_contracts.py`: default domain endpoints всех клиентских
протоколов, HAPP/Karing/legacy profiles, CLI commands, 45 portal endpoints и
43 RPC methods.

Source publication дополнительно защищена `.gitignore`: `.env`,
`portal-data/`, `portal-runtime/`, `output/`, deploy/full-release archives и
backup archives не могут попасть в обычный `git add`. Канонический deploy
по-прежнему строится только из `tools/canonical-files.txt`.

## Итог

Проект имеет зрелую архитектуру безопасности: `users.json` остаётся единственным source of truth, web-портал работает без Docker socket и root, privileged-действия ограничены версионированным RPC host-agent, deploy строится из allowlist и проверяется до распаковки. Итоговый Linux suite состоит из 294 тестов; девять Flask-тестов ожидаемо пропускаются вне portal Docker test image, где отдельно проходят 77 тестов.

Критических findings не обнаружено. Все выявленные high/medium/low defects закрыты canonical source + regression tests; большой размер Python entry points принят как контролируемый архитектурный долг. Debian systemd/firewall/Certbot и доступность у конкретного мобильного оператора остаются production verification, а не локальным доказательством.

## Область проверки

| Зона | Объём | Результат baseline |
|---|---:|---|
| Канонические shell-скрипты | 20 | Все используют `set -euo pipefail`, `bash -n` проходит |
| Shell-копии в `deploy/` | 19 | Побайтово совпадают с canonical; `build-deploy.sh` намеренно не поставляется |
| Legacy shell fixture | 1 | Воспроизводит updater до появления archive validator |
| Крупные Python-зоны | 4 | `kvnctl`, portal app, host-agent, control/RPC; compile проходит |
| Compose-сервисы | 8 | 6 data-plane + portal + portal-gateway по profiles |
| Уникальные release images | 7 | nginx используется двумя сервисами; AWG/WG работают на host |
| Документация | 6 entry points | `AGENTS.md`, `README.md`, `deploy/DEPLOY.md`, `MTPROTO.md`, update notes и handoff согласованы |

## Shell inventory

| Скрипт | Строк | Назначение | Root | Риск/защита |
|---|---:|---|---|---|
| `setup.sh` | 1403 | Установка, мастер state, certs, host-службы, Compose | да | Bounded maintenance lock, reboot boundary, effective service plan |
| `update.sh` | 399 | Staged source/full-release update и rollback до Compose | да | Shared lock, archive validator, staging, snapshot, cleanup trap |
| `tools/build-deploy.sh` | 231 | Canonical deploy mirror и безопасный tar.gz | нет | Allowlist, denylist runtime, пакетное Python-копирование, temp tree |
| `tools/build-release.sh` | 147 | Семь linux/amd64 images и release manifest | нет | Temp workspace, checksums, platform/image-set validation |
| `tools/project-backup.sh` | 171 | Root-only runtime + Docker images в `/backup` | да | Shared lock; архив содержит секреты; root-only target и cleanup trap |
| `tools/restore-backup.sh` | 108 | Restore в новый абсолютный каталог | да | Shared lock; проверяет имя, target и пустой каталог |
| `tools/cleanup-project.sh` | 144 | Удаление только локальных кешей | нет | Dry-run по умолчанию, protected paths, без runtime deletion |
| `tools/install-letsencrypt-renewal.sh` | 44 | systemd timer renew | да | Фиксированные unit paths |
| `tools/renew-letsencrypt.sh` | 8 | Wrapper штатного cert deploy | фактически да | Делегирует `kvnctl`, не содержит собственной мутации |
| `tools/tune-host-network.sh` | 20 | Только постоянный IPv4 forwarding | да | Нет агрессивного sysctl tuning |
| `tools/update-portal-wheelhouse.sh` | 46 | Обновление offline wheelhouse и lock | нет | Явный operator step; SHA-256 проверяет Docker build |
| `amneziawg/install-kernel-module.sh` | 106 | Официальный Debian package/kernel path | да | Проверяет режим/пакеты и reboot requirement |
| `amneziawg/install-host-service.sh` | 115 | Установка `kvn-amneziawg.service` | да | Фиксированный unit и project config |
| `amneziawg/sync-host-service.sh` | 133 | Peer syncconf или structural restart | да | Temp files + cleanup trap; различает peer/structure |
| `amneziawg/check-mode.sh` | 22 | Проверка kernel mode | да | Read-only диагностика |
| `amneziawg/tune-host.sh` | 6 | Compatibility wrapper | наследуется | Делегирует минимальному network helper |
| `wireguard/install-host-service.sh` | 106 | Установка `kvn-wireguard.service` | да | Отдельный `wg0`/51821, не смешивается с AWG |
| `wireguard/sync-host-service.sh` | 138 | Peer syncconf или structural restart | да | Temp files + cleanup trap; различает peer/structure |
| `portal/install-host-agent.sh` | 156 | Root-agent, socket, secret, systemd unit | да | Идемпотентные права, restart только при изменении |
| `ocserv/entrypoint.sh` | 45 | Runtime users и запуск ocserv | контейнер root/capability | Использует сгенерированные read-only inputs |

Deploy содержит 19 зеркальных копий production-скриптов; их SHA-256 проверяет canonical mirror contract. Единственный fixture `tests/fixtures/legacy-deploy/update.sh` намеренно несовместим с новым validator и покрывает bootstrap-переход.

## Python и privilege boundaries

| Зона | Размер baseline | Ответственность | Наблюдение |
|---|---:|---|---|
| `tools/kvnctl.py` | 8805 строк | state validation, render, links, certs, apply, CLI | Монолит велик; изменения ограничены helpers + characterization tests |
| `portal/app/__init__.py` | 2401 строк | Flask routes, auth, UI actions | Не выполняет root-команды напрямую |
| `portal/agent.py` | 2258 строк | Allowlisted privileged RPC, locks, systemd/Docker calls | Bounded output, activity adapters и mutation serialization |
| `portal/control.py` | 1246 строк | Транзакции `users.json`, render/apply, безопасные файлы | Единый lifecycle plan и privacy-safe activity subject |
| `portal/app/storage.py` | 458 строк | Sessions, blocking, settings, audit | Structured target type/name и миграция индекса |

RPC разделён на `READ_ONLY_METHODS` и `MUTATION_METHODS`, ограничивает request/response size и редактирует секретоподобный вывод. Web-контейнер не монтирует `/var/run/docker.sock`, не использует host network/privileged и обращается только к `/run/kvn-portal/control.sock`.

## Версии

| Компонент | Compose/source baseline | Capability metadata | Проверяемый кандидат | Статус |
|---|---|---|---|---|
| nginx | `1.31.1-alpine` | совпадает | `1.31.1-alpine` | version tag; digest записывает full release |
| Xray | `26.3.27` | совпадает | только совместимый stable; pre-release не принимать автоматически | рабочий Reality baseline |
| Hysteria | `v2.10.0` | совпадает | `v2.10.0` | обновлён, config smoke пройден |
| Telemt | `3.4.24` | совпадает | `3.4.24` | обновлён, config smoke пройден |
| mtg | `2.2.8` | совпадает | `2.2.8` | версия актуальна |
| ocserv | Debian trixie image, package `1.3.0-2` | ошибочно «bookworm» | оставить после package smoke | base закреплён digest |
| Flask | `3.1.3` | — | `3.1.3` | offline wheelhouse |
| Gunicorn | `26.0.0` | — | `26.0.0` | offline wheelhouse + SHA-256 |

Кандидат не считается внедрённым до config/start smoke, тестов и синхронизации release manifest/documentation.

## Container baseline

| Сервис | read-only | cap drop | no-new-privileges | pids | healthcheck | Finding |
|---|---|---|---|---:|---|---|
| portal | да | ALL | да | 64 | да | Base image закреплён digest |
| portal-gateway | да | ALL + минимальные add | да | 32 | нет | Приемлемо, readiness зависит от portal |
| telemt | да | ALL | да | 64 | нет | tmpfs только `/tmp/telemt`, stop 15s |
| mtg | да | ALL | да | 64 | нет | writable path не нужен, stop 15s |
| hysteria | да | ALL | да | 64 | нет | tmpfs `/tmp`, stop 15s |
| nginx | да | ALL + CHOWN/SETGID/SETUID | да | 64 | нет | writable runtime/cache tmpfs, stop 10s |
| xray | да | ALL | да | 128 | нет | tmpfs `/tmp`, stop 15s |
| ocserv | да | ALL + NET_ADMIN/CHOWN/SETGID/SETUID | да | 256 | нет | TUN/NAT, `/run` и config snapshot `/tmp`, stop 20s |

Все восемь сервисов используют общий `json-file` budget `10m × 2`, то есть теоретически до 160 МиБ. Надёжный healthcheck добавлен только там, где есть корректный локальный readiness signal; детали — в `CONTAINER_SECURITY.md`.

## Findings и очередь исправлений

| Severity | Finding | Доказательство | Решение/фаза | Статус |
|---|---|---|---|---|
| high | Setup/update поднимали все Compose-сервисы независимо от `services.*.enabled` | [`tools/kvnlib/services.py`](tools/kvnlib/services.py), `tests.test_upgrade_contracts.test_setup_and_update_use_effective_targeted_service_plan` | Единый service plan, phase 2 | resolved |
| high | Setup/update/backup/restore не имели общей host maintenance-блокировки | [`setup.sh`](setup.sh), [`update.sh`](update.sh), `tests.test_upgrade_contracts.test_maintenance_operations_share_bounded_flock_before_mutation` | Host maintenance lock, phase 2 | resolved |
| medium | Capability versions расходились с Compose | [`tools/kvnlib/apply.py`](tools/kvnlib/apply.py), `tests.test_kvn_state_apply.KvnStateApplyTests.test_capability_versions_match_pinned_compose_images` | Version parity, phase 2–3 | resolved |
| medium | Container hardening и resource limits были неодинаковы | [`docker-compose.yml`](docker-compose.yml), `tests.test_safety_contracts.test_container_logging_and_hardened_services_are_bounded` | Совместимый hardening, phase 3 | resolved |
| medium | MTProto не имел формального own-SNI/local-decoy режима и полного mobile config | [`MTPROTO.md`](MTPROTO.md), `tests.test_kvnctl_security.test_mtproto_*` | Internal decoy, keepalive, bounded diagnose, phase 4 | resolved |
| medium | Карточка пользователя не показывала безопасную runtime-активность | `portal/agent.py::_user_activity`, `tests.test_portal_agent.test_user_activity_*` | Typed adapters и targeted audit migration, phase 5 | resolved |
| low | Логи были доступны только на общей странице | `portal/app/static/service-logs.js`, `portal/tests/test_services.py` | Lazy inline logs без initial fetch/polling, phase 6 | resolved |
| low | Кнопки сервисов растягивались/обрезались | `portal/app/static/style.css`, `tests.test_portal_ui_source` | Content-sized responsive actions, phase 6 | resolved |
| medium | HAPP/Karing использовали один URL, AWG рисковал выглядеть как WG | `tools/kvnctl.py::*subscription*`, golden tests | Раздельные endpoints/builders и Karing WG Clash profile, phase 7 | resolved |
| high | Portal обрывал долгий `state.apply` общим 10-секундным socket timeout и возвращал ложный HTTP 502 | `portal/app/__init__.py`, domain/IP source-deploy E2E | Отдельный bounded mutation timeout 300 секунд, phase 9 | resolved |
| high | Updater использовал `json.loads` в inline-блоке формирования `.env` без `import json` | [`update.sh`](update.sh), `tests.test_portal_setup.SetupSourceTests.test_update_script_preserves_runtime_and_applies_host_services` | Явный импорт и heredoc regression-test, post-audit hotfix | resolved |
| medium | Karing WireGuard QR генерировался, но его новый kind не входил в strict preview allowlist | `QR_FILE_KINDS`, portal/E2E tests | Добавлен `karing-wireguard-qr`, phase 9 | resolved |
| medium | Source deploy без `portal/tests` не собирался legacy builder из-за порядка Docker stages | `portal/Dockerfile`, runtime image contract | Runtime stage перед test stage, phase 9 | resolved |
| low | `sni.diagnose` был реализован в dispatcher, но отсутствовал в RPC allowlist | [`portal/agent_protocol.py`](portal/agent_protocol.py), `tests.test_safety_contracts.test_agent_dispatch_matches_versioned_rpc_allowlist` | Добавлен в `READ_ONLY_METHODS`, phase 1 | resolved |
| low | Крупные Python entry points увеличивают blast radius | Размеры модулей в таблице | Только bounded helpers; без wholesale rewrite | accepted |

## Existing safety net и добавленные контракты

- `tests/test_safety_contracts.py`: deploy/runtime boundary, portal privilege boundary, host peer/structural apply, локальные UI assets.
- Добавлено: точный shell inventory/mirror, legacy fixture, legacy service preference default, fixture-only Reality Vision/subscription order, совпадение RPC handlers с versioned allowlist, bounded container logging/hardening assumptions.
- `tests/test_kvnctl_security.py`: SNI, MTProto, Reality TCP/xHTTP golden, legacy/HAPP/Karing payload, URL modes, AWG/WG separation.
- `tests/test_portal_agent.py` и `tests/test_portal_control.py`: RPC validation, concurrency, staged update, service preferences, reconcile/apply.
- `tests/test_upgrade_contracts.py`, `tests/test_deploy.py`, `tests/test_offline_release.py`: archive traversal/runtime exclusions, canonical schema, rollback/release contracts.

Новые тесты используют только documentation IP `203.0.113.0/24`, `.example.test` и фиктивные идентификаторы; production state и generated-файлы не читаются.

## Ограничения среды baseline

- Windows + WSL2 Ubuntu подходят для Python/Bash/Compose tests.
- Docker Desktop запущен; cached portal image build проходит.
- WSL/Docker DNS периодически не разрешает npm registry и Docker Hub. Cached Docker builds проходят; full release подтверждён через validated `KVN_RELEASE_OFFLINE=1` из семи заранее подготовленных images, а online pull остаётся отдельной внешней проверкой.
- ShellCheck отсутствует. В фазе 1 обязательна `bash -n`; ShellCheck можно добавить только как воспроизводимый необязательный tooling step.
- systemd, firewall, Certbot HTTP-01/IP profile и реальный lifecycle окончательно проверяются на Debian.

## Правило закрытия findings

Finding переводится в `resolved` только после изменения canonical source, regression test, обязательных команд фазы и синхронизации deploy через `tools/build-deploy.sh`. Ошибка внешнего DNS помечается отдельно и не маскирует падение исходников.

## Модульные границы портала — 23.07.2026

Application factory разделён без изменения внешнего HTTP-контракта:

| Метрика | До | После |
|---|---:|---:|
| `portal/app/__init__.py` | 2411 строк | 465 строк |
| Совместимые portal routes | 45 | 45 |
| Blueprint-группы | 0 | 5 |
| Прямые host/Docker вызовы из Blueprints | 0 | 0 |

- `blueprints/catalog.py` фиксирует URL, методы и прежние endpoint names.
- `PortalBoundary` централизует session, CSRF, IP blocking, no-store и security headers.
- `AgentFacade` оставляет единственный ленивый путь к allowlisted RPC по Unix socket.
- Реализации views удалены из factory; дублированных route registrations нет.
- Verification: 297 project tests (9 ожидаемых skip), 79 Flask/portal tests в Docker, compileall и route-map contract.

## Облегчение портала и сборщика — 23.07.2026

Навигация теперь описана один раз в `portal/app/navigation.py`. Из этого
контракта рендерятся desktop, mobile и command palette. В основном меню оставлены
Сводка, Пользователи, Сервисы и Настройки; остальные разделы доступны через
«Дополнительно» максимум за два действия.

| Ресурс/страница | До | После | Изменение |
|---|---:|---:|---:|
| JS на users | 45 834 байта | 13 783 байта | −69,9% |
| JS на settings | 45 834 байта | 17 861 байт | −61,0% |
| JS на dashboard | 45 834 байта | 22 412 байт | −51,1% |
| CSS | 39 368 байт | 39 995 байт | +1,6%, бюджет 40 КБ соблюдён |
| `build-deploy.sh`, Git Bash | 60,2 с | 7,3 с | −87,9% |

Общий frontend разделён на `base.js` и page modules: dashboard, update,
root-shell, logs, users, network и services. Browser network probe подтвердил:
users загружает только `base.js + users.js`, settings — `base.js + update.js`,
services — `base.js + services.js + service-logs.js`; dashboard polling не
попадает на остальные страницы.

Chromium smoke на 1440 px и 320 px не выявил console errors и горизонтального
overflow. Первый `Tab` переводит фокус на skip-link с видимым `outline: solid`,
`Ctrl+K` открывает доступный dialog. Скриншоты сохранены в локальном
`output/playwright/`: `dashboard|users|settings-{desktop,mobile}.png`.

Light mode по-прежнему не запускает history/activity/background refresh, а
ручные действия остаются доступны; это покрывают portal Docker tests.
Verification: 298 project tests успешно (18 platform/Flask skip), 79 portal
Docker tests, browser smoke и compileall.

Отдельно устранена сборочная избыточность: `tools/build_deploy_tree.py` заменил
сотни процессов `mkdir/cp` двумя пакетными операциями. Корневой `.dockerignore`
исключает runtime-секреты из BuildKit context; `tests/Dockerfile.root` закрепляет
Linux/root suite для CI и WSL/Docker среды.

## Политика адреса клиентского экспорта — 23.07.2026

Добавлен независимый от протоколов блок:

```json
{
  "client_export": {
    "address_mode": "server",
    "public_ip": "",
    "include_alternate": false
  }
}
```

Legacy state без блока продолжает использовать `server` и не переписывается.
Режим `public-ip` принимает только явно заданный глобальный IPv4; private,
loopback, link-local, multicast, unspecified, reserved, IPv6 и некорректные
значения отклоняются до сохранения.

`client_connection_host` является чистым resolver: он не меняет `server`,
`subscription.public_host`, SNI-маршруты, Reality `serverName`, цели
сертификатов и nginx route map. Готовность HTTPS-подписки по IP требует
одновременно настроенный маршрут и точное совпадение IP SAN сертификата.

Verification: 8 protocol-independent tests, 306 project tests успешно
(18 platform/Flask skip), render завершён без ошибки; deploy синхронизирован
по 118 каноническим файлам.

## Client renderers и export CLI — 23.07.2026

Единый `client_connection_host` подключён к VLESS TLS/Reality xHTTP/TCP,
Hysteria2, Telemt, mtg, AmneziaWG, WireGuard, OpenConnect, Xray JSON,
sing-box и HAPP/Karing payload. В IP-режиме меняется только сетевой endpoint:
SNI, Reality `serverName`, TLS identity и service-level camouflage domains
остаются доменными. AWG и WG сохраняют разные порты `51820` и `51821`.

`user_links_text`, `user_send_text` и общий manifest теперь используют
`ExportSection`. Добавлен `export-user` с text/JSON, временным endpoint и
атомарной записью `0600`; `export-links` сохранён. `kvnctl.py` уменьшен с
8814 до 8762 строк, parser/output primitives вынесены в `tools/kvnlib/cli.py`
и `client_export.py`.

Verification: server-mode byte compatibility, IP-матрица всех протоколов,
certificate gate, CLI help, 310 project tests и полный domain-mode Docker
deploy runtime E2E успешно; deploy содержит 119 канонических файлов.
