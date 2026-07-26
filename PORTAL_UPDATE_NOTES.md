# Заметки об обновлении KVN Portal

## Артефакты

- Рекомендуемый архив: `kvn-vpn-release-linux-amd64.tar.gz`
- Source-only: `kvn-vpn-deploy.tar.gz`

Полный release предназначен для Debian amd64 и содержит чистый source deploy и семь готовых Compose images. На сервере images не собираются и не скачиваются. Build ID, SHA-256 и размер публикуются в GitHub Release и `release-manifest.json`; текущий документ намеренно не фиксирует промежуточные хэши.

## Что изменено

- Добавлен экспорт пользователя: ZIP-вложение для ручной отправки через Telegram, `send.txt` для копирования и временный Domain/IP выбор без записи политики в `users.json`.
- Режим public-IP заменяет endpoint всех клиентских конфигураций, но сохраняет SNI, Reality `serverName` и certificate identity; subscription URL по IP закрыт без direct route и точного IP SAN.
- Добавлен фиксированный источник `artemiygaer/kvn-portal` GitHub Releases: check → download/verify → ready → отдельный start. Для private Release token хранится только в root-only файле и не попадает в portal/chat.
- `setup.sh` больше не повторяет apt/Compose операции без необходимости; WireGuard tools ставятся только для включённого standard WireGuard.
- Backup публикуется атомарно на одном filesystem и не дублирует release/deploy archives. Restore проверяет внешний и вложенный tar до создания target.
- Исправлен release-blocker в `update.sh`: inline-блок формирования `.env` теперь явно импортирует `json`. Ошибка происходила до Compose apply, поэтому штатный snapshot безопасно восстанавливал исходники; повторять обновление нужно уже с этим release.
- Setup/update/reconcile используют единый effective service plan: отключённые оператором сервисы не запускаются повторно после обслуживания.
- Все host maintenance операции защищены общей bounded `flock`; конкурентный setup/update/backup/restore завершается до мутации с понятной причиной.
- Telemt/mtg получили external/local-site own-SNI режим с внутренним `nginx:8443` decoy без public-443 loop, mobile keepalive/timeout и bounded diagnosis. Полную блокировку IP/TCP/TLS это не обещает обойти.
- Карточка пользователя показывает privacy-safe activity по protocol adapters и последние management events без IP, endpoint, UUID, ключей, паролей и содержимого файлов. В light mode остаётся только ручной запрос.
- В service cards добавлены lazy inline logs без initial fetch и polling; полный раздел логов сохранён.
- Кнопки и action groups стали content-sized на широком экране, mobile touch targets остаются не меньше 44 px.
- Legacy subscription endpoint сохранён побайтно; HAPP/Karing получили отдельные URL/QR. Для Karing standard WireGuard добавлены Clash URL/QR/YAML на `wg0:51821`; AmneziaWG остаётся только для AmneziaWG app на `awg0:51820`.
- Исправлен ложный HTTP 502 при создании, изменении, включении/выключении пользователя и reconcile: долгие `state.apply`/`state.reconcile` используют отдельный ограниченный timeout 300 секунд вместо общего socket-default 10 секунд.
- Исправлен preview/inline QR `karing-wireguard.png`; его тип теперь входит в строгий разрешённый список QR.
- Portal runtime stage перенесён перед test stage: source deploy без `portal/tests` собирается как `target: runtime` и legacy Docker builder не читает отсутствующие тесты.
- Добавлен validated offline-release builder для недоступного DNS: без build/pull, с проверкой семи локальных образов, portal build ID, linux/amd64, RepoDigest и manifest.

- В «Настройки» добавлены профили нагрузки «Стандартный», «Облегчённый» и «Свой». Облегчённый режим реально останавливает сбор истории метрик и фоновый polling; ручные обновления остаются доступны, БД не удаляется.
- Портал теперь разворачивается без домена по белому IPv4 и отдельному HTTPS-порту. Поддержаны Certbot 5.4+ short-lived IP certificate и явно подтверждаемый self-signed fallback с IP SAN; при неподходящем сертификате route остаётся закрытым.
- Интерфейс стал компактнее на desktop и сохраняет touch targets не менее 44 px на mobile. Настройки разделены на «Интерфейс», «Нагрузка», «Безопасность», «Обновление» и «SNI»; мобильная SNI-таблица преобразуется в карточки.
- Исправлен `sync_script_failed` при создании, включении и отключении пользователей AWG/WG: peer-sync больше не пытается повторно писать sysctl из защищённого host-agent. Peer-only delta применяется через `awg/wg syncconf`, structural delta — через controlled restart.
- Добавлен раздел «Сеть»: безопасная схема ingress → routing/direct → backend, карточки всех девяти систем и агрегированное runtime-состояние из существующего dashboard snapshot.
- Для VLESS/Reality добавлен типизированный редактор SNI и `xray.xhttp_mode`; произвольные backend/port/raw-конфиги из браузера не принимаются.
- Раздел пользователей получил переключаемую матрицу user × protocol с девятью системами, effective SNI и отдельными состояниями per-user/service/no-SNI.
- Добавлен read-only советник DNS-зоны: семь ограниченных проверок без IP/сертификатов, предупреждение Reality self-target и план DNS → SAN → route → client verification.
- Новые экраны проверены при 1440/768/390 px и в тёмной теме; добавлены двуязычные подписи, локальный favicon, keyboard/live-region/reduced-motion и WCAG AA контракты.
- Исправлена ревизия read-only DTO для старых минимальных `users.json`: нормализация SNI на копии больше не вызывает ложный HTTP 409 при следующей мутации.
- Web-обновление разделено на независимые этапы. Загрузка показывает 0–100%, затем host-agent выполняет read-only inspect, а портал сохраняет проверенный SHA-256 и карточку «Готов к обновлению» в SQLite. Root-пароль нужен только для отдельной команды запуска.
- Исправлен сбой загрузки full release на 0%: Werkzeug больше не буферизует большой multipart-файл в 16-МиБ `/tmp`. Браузер отправляет raw-поток прямо в `portal-data/updates`, no-JS fallback использует тот же диск, nginx допускает 2 ГиБ, а updater восстанавливает права каталога.
- Запуск принимает от браузера только opaque ID и режим, атомарно переводит запись `ready → starting`, повторно проверяет SHA-256 и создаёт не более одного systemd unit. Ошибка agent возвращает запись в `ready`; успешный schedule фиксирует `started`.
- Подготовленный архив переживает reload и новый вход администратора. Неуспешная замена не удаляет прежний ready-архив; доступны отмена загрузки, повтор, удаление подготовленного файла и no-JS fallback.
- Archive upload/RPC и gunicorn допускают до 30 минут; обычный read-only RPC timeout остаётся 10 секунд, а state mutation/reconcile ограничены 300 секундами. Файл читается блоками по 1 МиБ, действует лимит 2 ГиБ и резерв диска 512 МиБ.
- Dashboard переведён на stale-while-revalidate: во время штатного фонового сбора последний успешный snapshot не получает ложную метку «устарело», а UI не показывает «Собираю сводку…». Предупреждение сохраняется для реальной ошибки или отсутствия данных.
- Единичный исторический restart контейнера во время обновления больше не считается текущей аварией; карточка контейнеров оценивает фактические `state/health`.
- Исправлена проверка образов после `docker load` в Docker с containerd image store: verifier по одному экспортирует каждый не распознанный через inspect tag и строго сверяет исходный config digest. Это устраняет ложные ошибки для `kvn-portal:local`, `nginx:1.31.1-alpine` и остальных upstream-образов без ослабления проверки и без большого временного архива всех семи образов.
- Xray и Telemt получают строгие конфиги `0600` с UID закреплённых непривилегированных образов; после render/update контейнеры больше не падают с `permission denied`.
- Python-healthcheck портала заменён на лёгкий `wget`, поэтому на 1 vCPU исчезли ложные `unhealthy` и лишние пики CPU. Ожидание запуска host-agent увеличено до 30 секунд.
- Deploy-архив теперь детерминированно упаковывается стандартным Python `tarfile`, включая WSL/BusyBox без GNU tar.
- С публичной сервисной страницы удалены устаревшие ссылки на тестовые файлы 10/20 МБ; nginx больше не создаёт эти файлы в tmpfs и не публикует `/speed/`.
- Устранена высокая фоновая нагрузка dashboard: один snapshot RPC, single-flight/stale cache, batched Docker inspect, интервалы polling и жёсткие лимиты portal/gateway/host-agent для 1 vCPU/1 ГБ.
- Добавлен полный воспроизводимый `linux/amd64` release с семью закреплёнными Compose images. `setup.sh`, ручной `update.sh` и портал используют общий validator и офлайн Compose `--no-build --pull never`.
- Загрузка release через портал потоковая и ограниченная по размеру/свободному месту; публикация выполняется через temp+fsync+atomic rename. Images проверяются до изменения source, а pre-Compose ошибка восстанавливает snapshot.
- Исправлены обновления со старых установок: bootstrap updater самодостаточен, единый canonical manifest содержит все обязательные файлы, legacy bootstrap-only переходит на full release без server-side build/pull.
- Web-update стал двухконтурным: перед распаковкой archive validator допускает только обычные source-файлы из `deploy/`, чистый manifest и шаблонный `users.json`; `update.sh` повторяет проверку, работает через staging и при ошибке до Compose apply восстанавливает source snapshot.
- Запуск web-update требует системный root-пароль, привязанный к текущей portal session. Поле явно объясняет назначение пароля, очищается в браузере после формирования отправки и не попадает в audit/result/local storage.
- В мобильной версии меню перенесено в поток страницы: оно не перекрывает кнопки и терминал, закрывается по Escape или вне меню и возвращает фокус. Основные text/status tokens проверяются на WCAG AA, внешние UI-assets отсутствуют.
- Добавлена безопасная диагностика SNI из CLI и портала: проверка DNS+TLS ограничена по времени, ничего не меняет и не раскрывает IP/сертификат. Единого «белого списка» SNI для РФ нет; результат сервера не заменяет проверку у нужного оператора.
- Hysteria `trafficStats` слушает только `127.0.0.1` контейнера; host-agent читает агрегированные метрики по authenticated loopback, порт статистики не публикуется.
- Hysteria `v2.10.0`, Telemt `3.4.24` и mtg `2.2.8` закреплены; fallback canonical-list `update.sh` синхронизирован с builder, включая wheelhouse hashes, local xterm.js и terminal template.
- Исправлен запуск контейнера `portal`: WSGI factory `app:create_app()` в `portal/Dockerfile` теперь передаётся в `sh -c` в кавычках, поэтому `/bin/sh` больше не падает с `syntax error: unexpected "("`.
- HTTP-корень `80/tcp` теперь отдаёт `200 OK` для внешних проверок домена, а остальные HTTP-пути продолжают редиректиться на HTTPS; документация дополнена проверкой apex DNS и Nodeloc/Free Domain health.
- `update.sh` теперь запускает `render --restart`, чтобы после обновления уже работающий nginx перечитал изменённый `nginx.conf`, а не оставался на старом `301`.
- Web-обновление через портал теперь запускает `deploy/update.sh` из загруженного архива, а не старый updater из установленной папки проекта.
- Docker build портала больше не обращается к PyPI во время setup/update: Flask 3.1.3, Gunicorn 26.0.0 и зависимости ставятся из `portal/wheels/` через `pip --no-index`; SHA-256 проверяется до установки.
- Явный выпуск `letsencrypt issue --domain ...` теперь заменяет старый site SAN-список, чтобы в сертификате не оставались прежние домены вместо нового выбранного домена.
- Ручной выпуск site-сертификата теперь автоматически добавляет домен включённого портала в SAN, чтобы `https://<portal-domain>:<portal-port>/...` не получал `SSL_ERROR_BAD_CERT_DOMAIN`.
- UI/UX портала доведён до релизного состояния: выровнены размеры кнопок и полей, статусы не зависят только от цвета, добавлены empty/error/status states.
- Логи портала обновляются через JSON endpoint без полного HTML refresh. UI показывает время обновления, параметры выборки, cursor и статус команды.
- Пользовательские файлы разделены по смыслу: HAPP/Karing, Telegram proxy, WireGuard/AmneziaWG, OpenConnect и прочие файлы.
- Settings разделяет per-user SNI и service-level SNI. Telemt/mtg/OpenConnect не смешиваются с пользовательскими SNI.
- Services показывают runtime active и постоянное enabled-состояние.
- В shell портала добавлена палитра быстрых команд `Ctrl+K`; страница «Сервисы» получила поиск, фильтр состояния и фильтр host/container.
- Раздел «Консоль» расширен: быстрые root-команды обслуживания остаются в allowlist, дополнительно добавлен интерактивный root shell с запросом root-пароля, PTY-проксированием и автоматическим закрытием по таймауту.
- Root shell переведён на полноценный xterm.js-терминал в браузере: PTY-ввод идёт прямо из окна консоли, поддержаны ANSI/curses, cursor, resize, Enter, Tab, стрелки, Backspace, Ctrl-сочетания и paste; отдельная форма «команда + отправить» удалена.
- Root shell вынесен в отдельный пункт меню «Консоль» и отдельную полноразмерную страницу; allowlisted-команды обслуживания перенесены в пункт «Команды».
- Улучшена отзывчивость root shell: polling вывода ускорен, ввод отправляется меньшими задержками, краткие обрывы Unix socket показываются статусом reconnect и не попадают в вывод терминала.
- Host-agent больше не пишет traceback `BrokenPipeError` в journal, если web-клиент закрыл Unix-socket до получения ответа.
- Палитра xterm упрощена до нейтрального тёмного фона со стандартными ANSI-цветами, чтобы curses-приложения вроде `mc` выглядели предсказуемо.
- Сборка `ocserv` в Docker Compose переведена на `build.network=host`, чтобы setup не падал на `Temporary failure resolving 'deb.debian.org'` внутри BuildKit.
- CSP портала оставляет `script-src 'self'`, но `style-src` теперь включает `'unsafe-inline'` для динамических размеров и cursor xterm.js.
- Root shell на Debian/systemd запускается transient unit `kvn-portal-root-shell-*` через `systemd-run --pty`; команды и вывод shell не пишутся в аудит, аудитируются только open/close и ошибки входа.
- Исправлена проверка root-пароля для shell: если Python не умеет проверить hash из `/etc/shadow` или hash не совпал, agent выполняет резервную PAM-проверку через `systemd-run --uid=nobody su root -c /bin/true`.
- Цветовая схема портала стала нейтральнее, кнопки выровнены по высоте с полями ввода, terminal/root shell больше не выглядит как отдельная зелёная тема.
- Снижена фоновая нагрузка портала: dashboard обновляется реже, тяжёлые виджеты кэшируются дольше, история графиков и логи запрашиваются с большими интервалами.
- Дополнительно снижена нагрузка UI: повторяющиеся карточки получили CSS containment, root shell не опрашивается в скрытой вкладке, лог tail обновляется раз в 20 секунд.
- Контейнер портала переведён на ресурсный профиль `1 worker / 2 threads` с env-переопределением `KVN_PORTAL_WORKERS`, `KVN_PORTAL_THREADS`, `KVN_PORTAL_TIMEOUT`, `KVN_PORTAL_KEEPALIVE`, `KVN_PORTAL_MAX_REQUESTS`.
- Графики dashboard показывают не только проценты, но и абсолютные значения RAM/disk used/total и load для CPU.
- Update result показывает unit name, journal command, build до обновления и команды проверки после обновления.
- Добавлена страница «Бэкапы»: создание `kvn-vpn-backup-*.tar` в `/backup`, список архивов и скачивание через authenticated portal session.
- Добавлена страница «Проект»: описание архитектуры, портов, source/runtime/generated путей и команды с кнопками копирования.
- Добавлены `tools/project-backup.sh`, `tools/restore-backup.sh`, `tools/cleanup-project.sh`.
- `setup.sh`, `update.sh`, `tools/build-deploy.sh` и control-path проверены на сохранение runtime, denylist generated files и обязательный AWG/WG host sync.

## Портал без домена

При новой установке передайте setup белый IPv4, выберите для портала отдельный TCP-порт, например `8443`, и откройте его в host/cloud firewall:

```bash
sudo ./setup.sh <БЕЛЫЙ_IP>
sudo python3 tools/kvnctl.py portal status
curl -kI https://<БЕЛЫЙ_IP>:8443/<ПУТЬ>/login
```

IP-портал на `443/tcp` не допускается. DNS не требуется. Certbot 5.4+ используется со штатным short-lived IP profile; старая версия Certbot не заменяется пакетами из PyPI/unstable. Self-signed включается только явным подтверждением и вызывает предупреждение браузера. HTTPS route появляется только после проверки совпадающего IP SAN.

## Обновление через портал

1. Откройте портал и перейдите в «Настройки».
2. Выберите `kvn-vpn-release-linux-amd64.tar.gz`, нажмите «Загрузить и проверить» и дождитесь 100%.
3. Дождитесь отдельного состояния «Проверяю архив» и карточки «Готов к обновлению». После этого страницу можно закрыть и открыть снова.
4. В карточке выберите режим, повторно введите системный root-пароль и подтвердите отдельную команду «Запустить обновление».
5. В результате операции откройте journal command и дождитесь строки `[OK] Обновление завершено`.
6. Проверьте build id в shell портала и повторно откройте карточки пользователей с QR/preview.

Если проверка нового файла завершилась ошибкой, прежний подготовленный архив остаётся доступен. Если запуск сообщает `archive_changed` или `not_found`, удалите карточку готовности и загрузите release заново. Ответ `409` на повторный запуск означает, что этот ID уже занят, заменён или запущен; второй unit при этом не создаётся.

Если старая версия отклоняет full release, первый проход выполните с `kvn-vpn-deploy.tar.gz` в режиме «Только updater и host-agent», затем повторите обновление с full release. Это переход без server-side build/pull.

## Ручное обновление

```bash
cd /srv/kvn-vpn
sudo cp /path/to/kvn-vpn-release-linux-amd64.tar.gz .
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

`update.sh` без аргумента предпочитает полный release. Source-only deploy остаётся совместимым online fallback и явно предупреждает о возможной сборке/загрузке images.

Для сборок, где старый updater падает из-за отсутствующих файлов, не запускайте его. Извлеките новый bootstrap из source deploy во временный root-only каталог и примените сначала режим bootstrap-only:

```bash
cd /srv/kvn-vpn  # или фактический каталог установленного проекта
sudo rm -rf /root/kvn-update-bootstrap
sudo install -d -m 0700 /root/kvn-update-bootstrap
sudo tar -xzf ./kvn-vpn-deploy.tar.gz -C /root/kvn-update-bootstrap --strip-components=1
sudo env KVN_UPDATE_ROOT="$PWD" KVN_UPDATE_MODE=bootstrap-only \
  /bin/bash /root/kvn-update-bootstrap/update.sh ./kvn-vpn-deploy.tar.gz
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

Bootstrap не заменяет `users.json`, `.env`, clients, сертификаты или portal/metrics DB. Перед обновлением всё равно создайте приватный backup проекта.

## Backup и restore

Через портал: откройте «Бэкапы», создайте архив и скачайте готовый файл из `/backup`.

Ручной backup:

```bash
cd /srv/kvn-vpn
sudo ./tools/project-backup.sh
sudo ls -lh /backup/kvn-vpn-backup-*.tar
```

Restore на другой Debian:

```bash
sudo ./tools/restore-backup.sh /backup/kvn-vpn-backup-YYYYMMDD-HHMMSS-host.tar /opt/kvn-vpn
cd /opt/kvn-vpn
sudo ./setup.sh <NEW_SERVER_IP_OR_DOMAIN>
```

Backup-архив содержит runtime-секреты, ключи, сертификаты, portal DB и Docker images. Не кладите его в deploy, git, `nginx/web/` или публичные ссылки.

## Rollback

1. Для полного отката используйте предыдущий рабочий deploy-архив и запустите `sudo ./update.sh /path/to/old-kvn-vpn-deploy.tar.gz`.
2. Runtime-настройки `users.json` и `.env` сохраняются в `.update-backups/<timestamp>/`.
3. Если нужно вернуть только runtime-настройки, восстановите файлы из backup и примените конфиги:

```bash
sudo cp .update-backups/<timestamp>/users.json users.json
sudo cp .update-backups/<timestamp>/.env .env
python3 tools/kvnctl.py render
sudo ./amneziawg/sync-host-service.sh
sudo ./wireguard/sync-host-service.sh
docker compose -f docker-compose.yml up -d --build --remove-orphans
```

## Проверки после обновления

```bash
python3 tools/kvnctl.py portal status
python3 tools/kvnctl.py amneziawg verify
python3 tools/kvnctl.py wireguard verify
./tools/cleanup-project.sh --dry-run
docker compose -f docker-compose.yml ps
journalctl -u kvn-portal-agent.service -n 100 --no-pager
```

Для проблем с обновлением через портал смотрите unit из результата операции:

```bash
journalctl -u kvn-project-update-<id> -n 200 --no-pager
```
