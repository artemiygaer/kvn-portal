# Передача KVN VPN v3 новому ИИ-агенту

Работай из корня проекта. Отвечай по-русски, коротко и по делу; комментарии и документацию пиши на русском. Сначала полностью прочитай `AGENTS.md`, затем нужные разделы `README.md`, `deploy/DEPLOY.md`, `PROJECT_AUDIT.md`, `MTPROTO.md`, `CONTAINER_SECURITY.md` и `PORTAL_UPDATE_NOTES.md`.

## Статус

Глубокий аудит и основной цикл оптимизации завершены 26.07.2026:

- портал разделён на совместимые Blueprints и page-specific frontend modules;
- добавлены компактный UX, lazy inline logs, activity пользователя и light profile;
- экспорт пользователя формирует allowlisted ZIP в памяти и `send.txt`;
- Domain/IP policy применяется ко всем клиентским endpoint, не меняя SNI и certificate identity;
- GitHub Releases работает через фиксированный `artemiygaer/kvn-portal`: check → download/verify → ready → отдельный start;
- setup/update/backup/restore и management CLI актуализированы; deploy строится только из canonical allowlist.

Последний локальный gate: 338 тестов успешно, 20 ожидаемых platform/Flask skip; `compileall`, Bash syntax, Compose config и deploy validator прошли. Docker Desktop доступен, но текущий sandbox блокирует named pipe, поэтому финальный Docker lifecycle нужно повторить на Debian либо в среде с разрешённым Docker API. Последний полноценный portal image gate до текстовых правок: 94 теста.

## Неприкосновенные границы

- `users.json` — единственный source of truth. Generated/runtime из `AGENTS.md` вручную не редактировать.
- Не включать в deploy/git/logs users, clients, ключи/certs, `.env`, portal/metrics DB, sockets, agent/GitHub token, logs или backup.
- Web-портал остаётся непривилегированным контейнером без Docker socket. Root-действия выполняет только `kvn-portal-agent.service` через versioned allowlisted RPC.
- `/backup` содержит runtime-секреты и Docker images. Передавать только по защищённому каналу.
- Предпочитать hot update/reload. Не удалять пользовательский runtime при очистке.

## Архитектура

- Compose: nginx, portal, portal-gateway, xray, hysteria, telemt, mtg, ocserv.
- Host: `kvn-amneziawg.service` (`awg0`, `51820/udp`), `kvn-wireguard.service` (`wg0`, `51821/udp`), `kvn-portal-agent.service`.
- Setup/update/portal apply/reconcile используют один effective service plan; disabled-сервис не pull/build/start.
- Peer-only AWG/WG delta применяет `syncconf`, structural delta — controlled restart.
- Full release содержит source deploy и семь `linux/amd64` images; на слабом сервере updater использует `--no-build --pull never`.
- GitHub URL/repository не задаются браузером. Private token хранится только в `/etc/kvn-portal/github.token` с root-only правами и не выводится.

## Клиенты и экспорт

- Legacy `/<token>` сохранён. HAPP и Karing имеют отдельные URL/QR.
- Karing standard WireGuard — отдельный Clash URL/QR/YAML на `wg0:51821`.
- AmneziaWG выдаётся только для AmneziaWG app на `awg0:51820`.
- ZIP для Telegram скачивается как attachment и прикрепляется вручную. Прямого Telegram API и bot token нет.
- `public-ip` меняет endpoint подключения, но сохраняет SNI, Reality `serverName` и certificate identity.
- HTTPS subscription URL по IP выдаётся только при direct route и точном IP SAN.

## Обновление Debian

До обновления:

```bash
cd /srv/kvn-vpn
sudo ./tools/project-backup.sh
```

Портал: «Настройки» → GitHub либо ручная загрузка → «Проверить/подготовить» → дождаться ready → отдельно «Запустить обновление» с системным root-паролем.

Ручной эквивалент:

```bash
cd /srv/kvn-vpn
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

Для старого updater:

```bash
sudo ./update.sh --bootstrap-only ./kvn-vpn-deploy.tar.gz
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

Если сам старый updater не понимает bootstrap, используй безопасный временный worker из `deploy/DEPLOY.md`. Не распаковывай шаблонный `users.json` поверх production.

GitHub public Release не требует token. Для private Release:

```bash
sudo python3 tools/kvnctl.py updates configure --enable true --channel stable --asset-preference release --set-token
sudo python3 tools/kvnctl.py updates status
```

Token вводится только через `getpass`; не вставлять его в portal/chat/argv.

## Release и публикация

Промежуточные SHA и Build ID в документацию не записывать. Финальные значения брать из готового артефакта и `release-manifest.json`.

```bash
bash tools/build-deploy.sh
KVN_BUILD_ID=YYYYMMDD-release1 bash tools/build-release.sh
# При заранее подготовленных семи образах и недоступном registry:
KVN_RELEASE_OFFLINE=1 KVN_BUILD_ID=YYYYMMDD-release1 bash tools/build-release.sh
```

В GitHub Release публикуются только:

- `kvn-vpn-release-linux-amd64.tar.gz`;
- `kvn-vpn-deploy.tar.gz`;
- `publication-manifest.json`;
- `SHA256SUMS`.

`.github/workflows/ci.yml` проверяет source safety, документацию, тесты, Compose,
portal image и deploy. `.github/workflows/release.yml` запускается только вручную:
сначала создаёт проверяемый draft, сверяет точный состав assets и лишь затем
публикует Release. Перед публикацией проверить, что нет `.supergoal`, runtime,
backup, DB, ключей, сертификатов и client files.

## Полный gate

```bash
python3 -m py_compile tools/kvnctl.py
python3 -m compileall -q portal tools
python3 tools/docs_check.py
python3 -m unittest discover -s tests -v
bash -n setup.sh update.sh tools/*.sh amneziawg/*.sh wireguard/*.sh ocserv/*.sh portal/*.sh
docker compose -f docker-compose.yml config --quiet
docker build --target test -t kvn-portal:test portal
python3 tools/kvnctl.py render
python3 tests/deploy_runtime_e2e.py
bash tools/build-deploy.sh
```

Debian-only: systemd units, socket ownership, host/cloud firewall, Certbot HTTP-01/IP profile и реальная доступность у мобильных операторов. Универсального SNI для РФ нет; server-side diagnose не заменяет проверку клиента у нужного оператора.
