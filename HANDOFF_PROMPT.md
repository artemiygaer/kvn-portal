# Передача KVN VPN v4.2.0 новому ИИ-агенту

Работай по-русски, коротко и по делу. Комментарии и документация — на русском.
Проект — модульный VPN-стек для Debian 12/13. Разработка на Windows,
Linux/root-проверки — WSL и изолированный Docker.

## Начало

Не привязывайся к пути или диску. Найди корень workspace по `AGENTS.md`,
`VERSION`, `docker-compose.yml`, `setup.sh`, каталогам `portal/` и `tools/`.
Прочитай `AGENTS.md`, task-routing в `ARCHITECTURE.md` и ближайший вложенный
`AGENTS.md`. Подробности: `README.md`, `DEPLOY.md`, `CONTAINER_SECURITY.md`,
`PORTAL_UPDATE_NOTES.md`.

Проверь git status и commits. Чужие изменения не откатывай. `relay/` вне
задачи: не читай, не обходи, не включай в git/release. При продолжении текущего
supergoal прочитай STATE.md и PROTOCOL.md в
`.supergoal/kvn-console-migration-optimization-Rxc6l0/`.

## Архитектура и инварианты

- `users.json` — source of truth; generated/runtime не редактировать вручную.
- Не публиковать users, keys, certs, clients, `.env`, DB, migration/backup,
  agent secret и socket. Docker socket у web-контейнера запрещён.
- Root-действия — только host-agent, allowlisted Unix RPC и portal session.
- Консоль: xterm → WebSocket → Unix RPC → PTY. ANSI/C0 не фильтровать;
  повтор ACK не дублирует ввод. MC/HTOP остаются интерактивными.
- Перенос VPN-пользователей зашифрован GnuPG. Merge сохраняет identity цели;
  restore переносит VPN identity только в пустую цель. OS/SSH/portal credentials
  и TLS-сертификаты не переносятся. Конфликты отклоняются целиком.
- Отключённые сервисы не поднимаются после reconcile/update, конфиги сохраняются.
  Nginx/portal/agent нельзя отключить из портала.
- Self-steal включается явно. Update не меняет действующий Reality mode/SNI/keys.
- Опубликованные tags/assets не перемещать и не перезаписывать.

## Полный gate

Вычисляй WSL-путь из фактического workspace через `wslpath`. Linux E2E —
Ubuntu/root: обычный пользователь не воспроизводит deployment ownership.
Не заходи автоматически на production. Не используй глобальный Docker prune.

Минимальный gate выбирается по task-routing; перед выпуском:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q portal tools
python3 tools/architecture_check.py
python3 tools/docs_check.py
python3 tools/source_safety.py --mode worktree
docker compose -f docker-compose.yml config --quiet
docker build --target test -t kvn-portal:test portal
python3 tests/deploy_runtime_e2e.py
python3 tests/self_steal_e2e.py
```

Отдельно suite в `portal/`. Safe.directory и исключение `relay/` для WSL/git
задавай только в окружении процесса; образец и repo-state helper — в PROTOCOL.md.

## Release и публикация

С v4.1.1 сначала устанавливается отдельный bridge v4.1.2, затем v4.2.0.
Инструкция — `PORTAL_UPDATE_NOTES.md`. Не предлагай вручную копировать tools.
Обычный update сохраняет runtime. Full release: семь Linux/amd64 images,
source deploy и manifest. Старые transport refs нужны inspector; реальные
aliases восстанавливаются только после image-ID verify. В containerd descriptor
ID не равен config digest: используй штатный verifier.
Полный offline update применяет Compose с `--no-build --pull never`.

Публичный Release содержит ровно четыре файла:

- `kvn-vpn-release-linux-amd64.tar.gz`;
- `kvn-vpn-deploy.tar.gz`;
- `publication-manifest.json`;
- `SHA256SUMS`.

Проверь embedded source против canonical tree. SHA бери из manifest/checksums,
не вписывай сюда: этот файл сам входит в deploy. Тестовые архивы
`output/phase6-e2e` и `output/phase7-e2e` не публиковать.

GitHub фиксирован: `artemiygaer/kvn-portal`. Публичному repo token не нужен.
Private token при необходимости вводится только через `updates configure
--set-token` на сервере, хранится root-only и не выводится.

## Статус и доказательства

Исходники относятся к v4.2.0. В проверке подготовки 507 тестов проекта прошли
(один пропуск); Docker suite портала — 110 тестов (один пропуск). Это не
заменяет новый gate после изменений. Результаты, commits и события аудита —
в STATE.md плана, точные архивы и SHA — в publication-manifest.json.
Фактическое состояние публикации проверяй по GitHub API/assets и portal
check/download/ready/start/up_to_date, а не по наличию локального архива.

Debian kernel/AWG/firewall/Certbot проверяются отдельно. Docker systemd shim
не доказывает работу production systemd.
