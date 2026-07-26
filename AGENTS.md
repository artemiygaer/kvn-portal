# KVN VPN v3: краткая инструкция для ИИ-ассистента

Говорить с пользователем по-русски, коротко и по делу. Комментарии и документацию писать на русском. Перед правками сначала смотреть код вокруг задачи; подробности есть в `README.md` и `deploy/DEPLOY.md`.

## Суть проекта

KVN VPN v3 — мультипротокольный VPN-стек для Debian 12/13. Основные сервисы идут через Docker Compose. Host-службы:

- `kvn-amneziawg.service`: AmneziaWG, `awg0`, `51820/udp`;
- `kvn-wireguard.service`: стандартный WireGuard, `wg0`, `51821/udp`;
- `kvn-portal-agent.service`: привилегированный agent портала.

Поддерживаемые `systems`: `tls`, `reality-xhttp`, `reality-tcp`, `hysteria`, `telemt`, `mtg`, `amneziawg`, `wireguard`, `ocserv`.

Порты: `80/tcp` HTTP-проверка домена/редирект/Certbot HTTP-01, `443/tcp` nginx SNI-router, `443/udp` Hysteria2, `4443/udp` ocserv DTLS, `51820/udp` AmneziaWG, `51821/udp` WireGuard, `2096/tcp` резервная подписка, `2443-2448/tcp` прямые backends. Порты должны быть открыты и на host, и в cloud firewall.

## Жёсткие правила

- `users.json` — единственный source of truth.
- GitHub-источник обновлений фиксирован как `artemiygaer/kvn-portal`; browser/RPC не могут подменить repository или URL. Token для private Release хранится только в `/etc/kvn-portal/github.token` с root-only правами и никогда не выводится.
- Не редактировать вручную generated/runtime: `nginx/nginx.conf`, `nginx/site/index.html`, `nginx/portal-gateway.conf`, `xray/config.json`, `hy2/config.yaml`, `amneziawg/awg0.conf`, `wireguard/wg0.conf`, `telemt/config.toml`, `mtg/config.toml`, `ocserv/ocserv.conf`, `ocserv/users.txt`, `ocserv/ocserv.env`, `clients/`, `CLIENT_LINKS.md`, `nginx/web/`.
- Не включать в deploy и не логировать секреты/runtime: `users.json`, `clients/`, certs, `.env`, portal DB/WAL/SHM, metrics DB/WAL/SHM, `/etc/kvn-portal/agent.secret`, `/run/kvn-portal/control.sock`.
- Backup-архивы `kvn-vpn-backup-*.tar` в `/backup` содержат runtime-секреты и Docker images; не класть их в deploy, git, `nginx/web/` или публичные ссылки.
- Web-порталу нельзя монтировать Docker socket; не монтировать Docker socket в контейнер портала. Привилегированные действия только через `kvn-portal-agent.service` и allowlisted RPC по Unix socket.
- Интерактивный root shell портала разрешён только через `kvn-portal-agent.service`: запрос системного root-пароля при открытии, проверка через `/etc/shadow` с резервной PAM-проверкой `systemd-run --uid=nobody su`, привязка к текущей portal session, PTY-проксирование, xterm.js в браузере, raw-ввод, ANSI/curses, лимит сессий и таймаут. Docker socket по-прежнему запрещён.
- После изменений предпочитать hot-update/reload. Restart — только когда технически нужен.
- Не удалять пользовательские runtime-данные при очистке. Удалять можно кеши, временные тестовые каталоги и явно сборочные артефакты.

## Важные решения

- Стандартный WireGuard — отдельный сервис. Нельзя выдавать `wireguard.conf`, указывающий на `51820/udp` AmneziaWG: tunnel может подняться, но трафик не будет работать из-за AWG handshake/обфускации.
- AmneziaWG и WireGuard синхронизируются host-скриптами:
  - `amneziawg/install-host-service.sh`, `amneziawg/sync-host-service.sh`;
  - `wireguard/install-host-service.sh`, `wireguard/sync-host-service.sh`.
- Peer-only изменения AWG/WG применяются через `syncconf`; structural delta — controlled restart.
- SNI-пулы управляются через портал «Настройки» или `sni-routes`; пересечения SNI между сервисами, сайтом/подпиской и ocserv должны отклоняться до применения.
- Per-user SNI разрешён для `tls`, `reality-xhttp`, `reality-tcp` и `hysteria`; HAPP должен получать выбранные значения после render/apply. Reality SNI должен быть заранее в `sni_routes.<system>.aliases`, чтобы nginx и Xray были согласованы.
- Telemt/mtg/ocserv имеют service-level SNI. Telemt менять через default сервиса (`sni-routes set-default telemt <domain>` или портал), иначе QR/secret и `telemt/config.toml` разойдутся.
- Универсального SNI «белого списка» для РФ нет. До применения можно выполнить ограниченную 3 секундами проверку `sni-routes diagnose <domain>` (или кнопку портала): она не меняет state и не выдаёт IP/сертификат, но не подтверждает доступность у другого оператора.
- Portal: HTTPS + login/password + custom path + блок IP на 12 часов после 5 ошибок. Пароли только через `getpass`/hash, reset инвалидирует сессии.
- Dashboard использует stale-while-revalidate: последний успешный snapshot остаётся актуальным во время фонового сбора. `stale` допустим только при ошибке источника, отсутствии данных или просрочке вне активного refresh.
- Карточка контейнеров определяет проблему по текущим `state/health`; исторический `RestartCount` после штатного update сам по себе не должен давать тревогу.
- HAPP получает URL-подписку с base64-списком URI. OpenConnect выдаётся отдельно в `openconnect.txt`.
- Пользовательский экспорт строится в памяти по allowlist. ZIP предназначен для ручного вложения в Telegram; прямого Telegram API и хранения bot token нет.
- Режим export по IP меняет только endpoint. SNI, Reality `serverName` и certificate identity не переписываются; HTTPS subscription по IP требует direct route и точный IP SAN.

## Типовой apply

После изменения `users.json` или state через CLI/портал:

```bash
python3 tools/kvnctl.py render
sudo ./amneziawg/sync-host-service.sh
sudo ./wireguard/sync-host-service.sh
docker compose -f docker-compose.yml up -d --build --remove-orphans
```

На Windows:

```powershell
$env:PYTHONIOENCODING='utf-8'; python tools\kvnctl.py render
```

## CLI

```bash
python3 tools/kvnctl.py interactive
python3 tools/kvnctl.py add-user USER --systems hysteria,reality-tcp,amneziawg,wireguard --restart
python3 tools/kvnctl.py edit-user USER --restart
python3 tools/kvnctl.py remove-user USER --restart
python3 tools/kvnctl.py links USER
python3 tools/kvnctl.py sni-routes diagnose example.com
python3 tools/kvnctl.py portal status|configure|reset-credentials|unlock-ip
python3 tools/kvnctl.py amneziawg diagnose USER
python3 tools/kvnctl.py wireguard diagnose USER
python3 tools/kvnctl.py amneziawg verify
python3 tools/kvnctl.py wireguard verify
```

## Setup, update, deploy

- `setup.sh`: устанавливает Docker/Compose/Python/qrencode/Certbot/wireguard-tools, проверяет AmneziaWG apt/kernel, на reboot выходит до вопросов, настраивает домены/портал/users, делает `render --certs`, ставит host-службы, запускает Compose и проверяет контейнеры/AWG/WG.
- Для 1 vCPU/1 ГБ использовать `kvn-vpn-release-linux-amd64.tar.gz`: `update.sh` проверяет release/images, загружает их до source mutation и запускает Compose с `--no-build --pull never`. Source-only deploy остаётся online fallback.
- `update.sh`: положить full release или `kvn-vpn-deploy.tar.gz` в корень установленного проекта и выполнить `sudo ./update.sh [архив]`. Скрипт не затирает `users.json`, certs, clients, portal/metrics DB. Web-портал принимает те же архивы через host-agent.
- `tools/build-deploy.sh`: собирает deploy только из canonical source-файлов и пишет `.kvn-canonical-files` в архив. В архиве запрещены пользователи, QR/clients, private keys/certs, DB/WAL/SHM, sockets, logs, generated server configs включая `wireguard/wg0.conf`.
- `tools/build-release.sh`: на рабочей машине собирает полный воспроизводимый Linux/amd64 release с семью Compose images, source deploy и `release-manifest.json`.
- `tools/project-backup.sh`: root-only backup проекта и Docker images в `/backup`; портал запускает его через host-agent на странице «Бэкапы».
- `tools/restore-backup.sh`: root-only restore backup-архива в новый абсолютный каталог с проверкой имени архива и target.
- `tools/cleanup-project.sh`: dry-run по умолчанию; `--apply` удаляет только кеши/временные файлы и отказывается трогать runtime/generated и `/backup`.
- `deploy/users.json` должен быть шаблоном без секретов и пользователей: `portal.enabled=false`.

## Проверки перед сдачей

```bash
python3 -m py_compile tools/kvnctl.py
python3 -m compileall -q portal
python3 -m unittest discover -s tests -v
bash -n setup.sh update.sh tools/*.sh amneziawg/*.sh wireguard/*.sh ocserv/*.sh portal/*.sh
docker compose -f docker-compose.yml config --quiet
docker build --target test -t kvn-portal:test portal
python3 tools/kvnctl.py render
python3 tests/deploy_runtime_e2e.py
bash tools/build-deploy.sh
KVN_BUILD_ID=20260713-staged-update1 bash tools/build-release.sh
```

Debian-only: systemd, socket права, firewall, Certbot HTTP-01, реальный Compose lifecycle. Если Docker/WSL недоступен локально, явно указать это в ответе.

## Передача проекта

Для новой ИИ-сессии использовать `HANDOFF_PROMPT.md`. Он короче и содержит текущий статус, последние проверки и SHA deploy-артефакта.
