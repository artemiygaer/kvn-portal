# KVN VPN v3

Мультипротокольный VPN-стек для Debian 12/13. Основные сервисы запускаются через Compose.

AmneziaWG работает на хосте как systemd-служба `kvn-amneziawg.service`. Стандартный WireGuard работает отдельно как `kvn-wireguard.service`.

Поддерживаются VLESS TLS Vision, VLESS Reality xHTTP, VLESS Reality TCP Vision, Hysteria 2, AmneziaWG, стандартный WireGuard, OpenConnect/ocserv, Telemt и mtg FakeTLS.

Runtime-образы закреплены на проверенных версиях: Hysteria `v2.10.0`, Xray `26.3.27`, Telemt `3.4.24`, mtg `2.2.8`. Для ocserv используется закреплённый Debian 13 base с пакетом `1.3.0-2` из stable/security archive; testing/unstable пакеты не подключаются автоматически. Версии, capabilities и writable paths описаны в `CONTAINER_SECURITY.md`.

Веб-портал управляет пользователями, сервисами, логами, статистикой, сертификатами, диагностикой и аудитом. Привилегированные операции выполняет отдельный host-agent по Unix socket; web-контейнер не получает Docker socket и root-доступ.

## Изменения релиза

- транзакционное управление пользователями с проверяемым AmneziaWG/WireGuard apply и `reconcile`;
- история нагрузки за 72 часа и адаптивные графики без внешних assets;
- QR/preview/download для AmneziaWG app, стандартного WireGuard, HAPP и Karing;
- SNI-пулы в портале: добавление aliases, проверка пересечений и выбор SNI в профиле пользователя;
- бэкапы через портал и CLI: `/backup`, `tools/project-backup.sh`, `tools/restore-backup.sh`;
- встроенный раздел «Проект» с copyable командами установки, обновления, backup/restore и диагностики;
- консоль обслуживания через host-agent: быстрые root-команды из allowlist и полноценный браузерный root shell после проверки root-пароля;
- безопасная очистка локального мусора через `tools/cleanup-project.sh` с dry-run по умолчанию;
- профили нагрузки портала: «Стандартный», «Облегчённый» и «Свой»; облегчённый режим полностью останавливает сбор истории метрик и фоновый polling, оставляя ручное обновление;
- HTTPS-портал без домена по публичному IPv4 и отдельному порту: доверенный краткоживущий IP-сертификат Certbot 5.4+ либо явно разрешённый self-signed сертификат с IP SAN;
- релизная визуальная иерархия действий, быстрые команды `Ctrl+K`, фильтры сервисов, мобильное меню, IP текущей сессии, build id и AA-контраст;
- идемпотентный host-agent installer и чистый deploy denylist для runtime/QR/секретов.
- единый lifecycle-план: отключённые через портал сервисы не поднимаются снова при setup/update/reconcile;
- безопасная активность пользователя по доступным protocol adapters без IP, endpoint, ключей и содержимого конфигов;
- inline-логи прямо в карточках сервисов: первый bounded-запрос выполняется только при раскрытии панели, polling отсутствует;
- MTProto external/local-site camouflage с внутренним decoy без public-443 loop, mobile keepalive и bounded-диагностикой;
- раздельные legacy/HAPP/Karing endpoints и отдельный Karing Clash-профиль standard WireGuard.
- экспорт пользователя одним ZIP-вложением для Telegram либо текстом для копирования; прямой вызов Telegram API намеренно отсутствует;
- резервный экспорт всех клиентских endpoint по публичному IPv4 без замены SNI, Reality `serverName` и certificate identity;
- проверка и подготовка обновления из фиксированного GitHub Releases с тем же отдельным запуском, что и при ручной загрузке.

> Команды с `sudo`, `systemctl`, `journalctl`, firewall и Certbot выполняются только на Debian-сервере. Сборка deploy, `--help`, компиляция и unit-тесты доступны на рабочей машине.

## Установка и обновление

Итоги релиза и краткая памятка для обновления: [PORTAL_UPDATE_NOTES.md](PORTAL_UPDATE_NOTES.md).

Для сервера с 1 vCPU/1 ГБ ОЗУ соберите полный Linux/amd64 release на рабочей машине:

```bash
KVN_BUILD_ID=YYYYMMDD-release1 ./tools/build-release.sh
```

Перенесите один файл `kvn-vpn-release-linux-amd64.tar.gz`. В нём находятся чистый source deploy, семь готовых Docker images и подписанный хэшами manifest. Новая установка:

```bash
tar -xzf kvn-vpn-release-linux-amd64.tar.gz kvn-vpn-deploy.tar.gz
tar -xzf kvn-vpn-deploy.tar.gz
cd deploy
sudo ./setup.sh --release ../kvn-vpn-release-linux-amd64.tar.gz <IP_ИЛИ_ДОМЕН_СЕРВЕРА>
```

Домен для VPN-сервисов необязателен. Если портал тоже работает без домена, передайте белый IPv4 сервера, выберите для портала отдельный HTTPS-порт, например `8443`, и откройте его в host/cloud firewall. Setup не выполняет DNS-проверку для IP. Certbot 5.4+ может выпустить доверенный краткоживущий IP-сертификат; иначе мастер предложит только явный self-signed fallback с предупреждением браузера. Портал по IP на общем `443/tcp` не разрешён.

Обновление установленного сервера без повторного мастера setup:

```bash
cd /srv/kvn-vpn
sudo cp /path/to/kvn-vpn-release-linux-amd64.tar.gz .
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

Этот путь загружает и сверяет images до изменения source, затем вызывает Compose с `--no-build --pull never`. Source-only `kvn-vpn-deploy.tar.gz` сохранён для совместимости, но может строить или скачивать images и не рекомендуется для слабого сервера.

Включённый web-портал принимает полный release в разделе «Настройки» в два этапа. Сначала кнопка «Загрузить и проверить» показывает прогресс передачи, потоково пишет temp-файл, проверяет размер, свободное место, структуру и SHA-256, затем сохраняет portal-wide состояние «Готов к обновлению». Оно переживает reload и новый вход администратора. Только отдельная кнопка «Запустить обновление» запрашивает системный root-пароль и запускает тот же updater через host-agent; пароль не сохраняется и не попадает в аудит.

Большой файл из JavaScript передаётся как `application/octet-stream` сразу в `portal-data/updates`; multipart fallback также использует этот дисковый каталог, а не 16-МиБ tmpfs `/tmp`. Основной и custom nginx-маршруты допускают до 2 ГиБ. Установщик host-agent при каждом update восстанавливает точные права `10001:kvn-portal` на каталог загрузок.

Не закрывайте страницу во время передачи файла. После появления карточки готовности страницу можно закрыть и вернуться позже. Ошибка проверки не заменяет уже подготовленный архив; ошибка запуска возвращает его в состояние готовности. При сообщении об отсутствующем или изменившемся архиве удалите подготовленный файл и загрузите release заново. Повторный запуск уже занятого ID отклоняется без второго systemd unit.

Если старая версия портала ещё не принимает full release, сначала загрузите `kvn-vpn-deploy.tar.gz` и выберите режим «Только updater и host-agent». После завершения снова откройте портал и загрузите full release в обычном режиме. Bootstrap-only не запускает render, build/pull или VPN-контейнеры.

GitHub Releases — дополнительный источник, а не отдельный updater. Репозиторий зафиксирован в коде как `artemiygaer/kvn-portal`; портал умеет проверить latest stable либо заданный tag, скачать и проверить штатный asset, после чего показывает ту же карточку «Готов к обновлению». Для публичного репозитория token не нужен. Для приватного создайте credential только на сервере:

```bash
sudo python3 tools/kvnctl.py updates configure --enable true --channel stable --asset-preference release --set-token
sudo python3 tools/kvnctl.py updates status
```

Token вводится через `getpass`, хранится только в `/etc/kvn-portal/github.token` с root-only правами и никогда не вставляется в портал, командную строку, чат или документацию.

До создания transient unit host-agent проверяет gzip/tar-структуру: допустим только `deploy/`, обычные файлы, ограниченный размер, обязательный manifest и чистый `deploy/users.json`; traversal, ссылки, device/FIFO, runtime-пути и лишние файлы отклоняются до распаковки. `update.sh` повторяет проверку, сначала собирает staging и root-only snapshot исходников, а при ошибке до Compose apply восстанавливает source snapshot.

`update.sh` не затирает `users.json`, сертификаты, `portal-data/`, `clients/` и runtime БД. При полном release он проверяет SHA-256, `linux/amd64`, точный image set и свободное место, загружает images до source mutation, затем делает render и синхронизацию host-служб. При ошибке до Compose apply source snapshot восстанавливается.

Новые архивы содержат `.kvn-canonical-files`; updater берёт список обновляемых source-файлов из этого manifest и отклоняет runtime-пути вроде `users.json`, certs, clients, DB и generated-конфигов.

`setup.sh`:

1. Установит недостающие Docker, Compose, Python 3, `qrencode` и Certbot; `wireguard-tools` ставится только при включённом standard WireGuard.
2. Не повторяет package-manager операции для уже рабочего Compose; сетевые загрузки ограничены timeout/retry.
3. При обновлении ядра или AmneziaWG остановится и красным сообщит о перезагрузке. Выполните `sudo reboot`, затем снова запустите ту же команду `setup.sh`.
4. Запросит необязательные домены сайта, подписки и ocserv, заголовок сайта и SNI сервисов. Домен можно пропустить.
5. Предложит настроить HTTPS-портал: имя, публичный домен либо белый IPv4, порт, URL-путь, логин и пароль.
6. Предложит создать пользователей, сгенерирует конфиги и запустит сервисы.
7. Установит systemd-таймер продления Let's Encrypt.

AmneziaWG и стандартный WireGuard не запускаются в контейнерах. После установки должны существовать интерфейсы `awg0`/`wg0` и активные службы `kvn-amneziawg.service`/`kvn-wireguard.service`.

## Архитектура

`nginx` принимает `80/tcp` и `443/tcp`: HTTP-корень `/` отвечает `200 OK` для внешних доменных проверок, остальные HTTP-пути редиректятся на HTTPS, а HTTPS через `ssl_preread` читает SNI из TLS ClientHello и направляет соединение в нужный backend без расшифровки. Hysteria 2, DTLS ocserv, AmneziaWG и WireGuard используют UDP напрямую.

| Порт | Назначение |
|---|---|
| `443/tcp` | nginx SNI-router |
| `443/udp` | Hysteria 2 |
| `4443/udp` | ocserv DTLS |
| `51820/udp` | AmneziaWG |
| `51821/udp` | WireGuard |
| `2096/tcp` | резервная HTTPS-подписка |
| `2443/tcp` | прямой VLESS TLS |
| `2444/tcp` | прямой Reality xHTTP |
| `2445/tcp` | прямой Reality TCP |
| `2446/tcp` | прямой Telemt |
| `2447/tcp` | прямой mtg FakeTLS |
| `2448/tcp` | прямой OpenConnect TCP |
| `80/tcp` | HTTP-проверка домена, редирект на HTTPS для не-root путей, Certbot HTTP-01 во время выпуска/renew |

Порт портала выбирается в setup: `443/tcp` через общий SNI-router либо отдельный TCP-порт. Отдельный порт предпочтителен для точного учёта IP клиента и независимого rate limit; его также нужно открыть в host/cloud firewall.

Откройте необходимые порты в firewall хоста и в панели облачного провайдера. Проект не предполагает наличие конкретного firewall-менеджера. Для нормальной скорости OpenConnect особенно важен `4443/udp`; без него клиент перейдёт на TCP.

## Веб-портал

Публичный URL имеет вид `https://<ДОМЕН_ИЛИ_IP>:<ПОРТ>/<ПУТЬ>`. Для домена setup добавляет имя в Let's Encrypt SAN и не открывает route до появления подходящего live-сертификата. DNS уже должен указывать на сервер, а `80/tcp` должен быть доступен извне.

Для режима без DNS укажите белый IPv4 и отдельный порт: `https://<БЕЛЫЙ_IP>:8443/admin/`. Route открывается только при совпадающем IP SAN. Доверенный вариант требует Certbot 5.4+ и профиль short-lived; self-signed вариант включается только явно и вызывает штатное предупреждение браузера. Проверить итоговый URL и готовность сертификата:

```bash
sudo python3 tools/kvnctl.py portal status
sudo ss -ltnp | grep ':8443'
curl -kI https://<БЕЛЫЙ_IP>:8443/<ПУТЬ>/login
```

Защита входа:

- пароль хранится только как scrypt hash;
- сессия и CSRF-токен хранятся в локальной SQLite БД `portal-data/portal.db`;
- после пяти ошибок IP блокируется на 12 часов;
- cookie имеет `Secure`, `HttpOnly`, `SameSite=Strict` и ограниченный URL path;
- HTTPS boundary передаёт запросы только на точный настроенный path.

Восстановление доступа на Debian:

```bash
sudo python3 tools/kvnctl.py portal status
sudo python3 tools/kvnctl.py portal reset-credentials --login <НОВЫЙ_ЛОГИН>
sudo python3 tools/kvnctl.py portal unlock-ip <IP_АДРЕС>
```

Сброс credentials закрывает все активные сессии. Пароль вводится через `getpass` и не передаётся в аргументах процесса.

Изменение домена/IP, порта или path выполняется мастером, а не ручной правкой nginx:

```bash
sudo python3 tools/kvnctl.py portal configure
sudo python3 tools/kvnctl.py letsencrypt reissue --target site --restart
sudo python3 tools/kvnctl.py portal status
```

В портале откройте «Настройки» → «Нагрузка». «Стандартный» режим сохраняет историю и фоновые обновления; «Облегчённый» отключает оба источника нагрузки без рестарта VPN; «Свой» позволяет переключать их независимо. История и БД при отключении не удаляются.

После смены порта синхронно обновите host/cloud firewall. После смены домена сначала обновите DNS и доступность `80/tcp`. Для apex-записи `@` держите один активный IP сервера; несколько `@ A` на разные VPS допустимы только если каждый IP отдаёт одинаковый HTTP/HTTPS и имеет подходящий сертификат. До успешного выпуска сертификата новый route закрыт снаружи.

Основные разделы портала:

- пользователи: create/edit/enable/disable, ротация ключей и безопасная выдача файлов;
- сервисы: start/stop/reload/restart и постоянное enable/disable с подтверждением опасных действий;
- быстрые команды: `Ctrl+K` открывает переходы к пользователям, сервисам, логам, shell, бэкапам, проекту и настройкам;
- консоль: отдельная полноразмерная страница root shell; открывается после ввода системного root-пароля и работает как xterm.js-терминал в браузере: PTY, ANSI/curses, cursor, resize, Enter, Tab, стрелки, Backspace, Ctrl-сочетания и paste;
- команды: фиксированные root-команды обслуживания через host-agent (`systemctl`, `ss`, `df`, `docker compose ps`, `kvnctl verify/reconcile/render`) с CSRF, подтверждением опасных действий и аудитом;
- логи и статистика: bounded tail журналов, lazy inline-логи в карточках сервисов, безопасная активность пользователя, KPI и SVG-графики CPU/RAM/disk/load/network с диапазоном 1/6/24/72 часа и шагом 1/5/15/60 минут;
- сертификаты: status/issue/renew/reissue/deploy с минимальным reload потребителей;
- бэкапы: запуск создания архива, список файлов из `/backup` и скачивание `kvn-vpn-backup-*.tar`;
- проект: описание архитектуры, портов, runtime/generated путей и copyable команды;
- диагностика и аудит: причины проблем, безопасные команды и журнал действий без секретов.

Архитектурная граница: `portal` работает непривилегированным read-only контейнером, читает синхронизированную runtime-копию `portal-runtime/users.json` и обращается к `kvn-portal-agent.service` через `/run/kvn-portal/control.sock`. Единственным источником правды остаётся корневой `users.json`; runtime-копия нужна для безопасного directory bind mount и обновляется автоматически. Agent имеет фиксированный RPC allowlist и фиксированные argv для быстрых команд. Монтировать `/var/run/docker.sock` в web-контейнер запрещено. Интерактивный root shell доступен только после ввода системного root-пароля, привязан к текущей portal session, ограничен лимитом сессий и таймаутом простоя; браузерный xterm.js отправляет raw-ввод в PTY небольшими батчами и принимает ANSI-вывод, команды и вывод shell не пишутся в аудит, аудитируется только open/close и ошибки входа. При кратком обрыве Unix socket UI показывает reconnect-статус и не пишет служебную ошибку в терминальный вывод. CSP держит `script-src 'self'`; `style-src` дополнительно разрешает `'unsafe-inline'`, потому что xterm динамически выставляет размеры и позицию cursor. На Debian/systemd проверка пароля использует `/etc/shadow` и резервную PAM-проверку через `systemd-run --uid=nobody su root -c /bin/true`, а сам shell запускается как transient unit `kvn-portal-root-shell-*` через `systemd-run --pty`. Если root-пароль не задан или root заблокирован, задайте его на сервере командой `sudo passwd root`.

Обычный AWG/WG sync только проверяет уже настроенный `net.ipv4.ip_forward=1` и не меняет kernel tunables из sandbox host-agent. Постоянная настройка forwarding выполняется при setup/install или вручную командой `sudo ./tools/tune-host-network.sh`; peer-only delta применяется через `awg/wg syncconf`, structural delta — через controlled restart.

Host-agent снимает метрики раз в 60 секунд и хранит не более 72 часов в `/var/lib/kvn-portal/metrics.db`. Endpoint `metrics/history.json` доступен только после входа, ограничивает диапазон и число точек. Dashboard использует stale-while-revalidate: во время фонового сбора последний успешный snapshot остаётся актуальным; «устарело» показывается только при ошибке источника или отсутствии данных. Тяжёлые карточки кэшируются 30–60 секунд, сертификаты — 15 минут; polling останавливается в скрытой вкладке. Контейнер портала по умолчанию запускает один `gunicorn` worker с 2 threads и timeout 1800 секунд для больших upload-запросов; archive RPC использует тот же предел, а обычные RPC сохраняют timeout 10 секунд. При необходимости можно задать `KVN_PORTAL_WORKERS`, `KVN_PORTAL_THREADS`, `KVN_PORTAL_TIMEOUT`, `KVN_PORTAL_KEEPALIVE`, `KVN_PORTAL_MAX_REQUESTS`. Повторный setup сохраняет историю, portal DB, credentials и пользователей; installer перезапускает agent только при изменении unit или его исходников.

Docker-образ портала ставит Flask/gunicorn из `portal/wheels/` через `pip --no-index`, поэтому первичная установка не зависит от доступности PyPI внутри build-сети Docker. SHA-256 wheel-файлов проверяется во время build. При изменении `portal/requirements.txt` синхронизируйте `portal/wheelhouse.lock`, выполните `bash tools/update-portal-wheelhouse.sh` и обновите canonical manifest перед сборкой deploy.

### Активность пользователей и inline-логи

Карточка пользователя показывает только штатно доступные конкретному протоколу поля: суммарные байты, время последней активности или число подключений. IP, endpoint, UUID, public/private keys, пароли и содержимое client files в RPC/JSON/UI/audit не возвращаются. Для mtg с общим secret честно показывается отсутствие персональной атрибуции; недоступность одного adapter не скрывает остальные результаты.

В стандартном режиме активность загружается при открытии карточки и обновляется не чаще раза в 60 секунд только в видимой вкладке. В облегчённом режиме initial/background request отключён, остаётся кнопка «Обновить». Inline-логи сервиса не загружаются вместе со страницей и не имеют polling: первый запрос выполняется при раскрытии панели, последующие — только кнопкой обновления. Полная страница логов остаётся для фильтрации и скачивания.

`services.*.enabled` — постоянное operator preference. Setup, update, portal apply и reconcile используют один effective service plan: отключённый сервис исключается из Compose profiles/действий и не «оживает» после обновления. Runtime stop без изменения enabled-предпочтения не заменяет постоянное отключение.

## Пользователи и клиентские файлы

Интерактивное управление:

```bash
python3 tools/kvnctl.py interactive
```

Основные команды:

```bash
python3 tools/kvnctl.py add-user USER --systems hysteria,reality-tcp,amneziawg,wireguard,ocserv --restart
python3 tools/kvnctl.py add-user USER --ocserv-password 'PASSWORD' --restart
python3 tools/kvnctl.py edit-user USER --systems hysteria,reality-xhttp,reality-tcp --restart
python3 tools/kvnctl.py edit-user USER --ocserv-password 'NEW_PASSWORD' --restart
python3 tools/kvnctl.py remove-user USER --restart
python3 tools/kvnctl.py list-users
python3 tools/kvnctl.py show USER
python3 tools/kvnctl.py links USER
python3 tools/kvnctl.py export-links USER
python3 tools/kvnctl.py export-user USER --format text
python3 tools/kvnctl.py export-user USER --address-mode public-ip --public-ip PUBLIC_IPV4 --format json --output ./USER-export.json
```

Доступные значения `--systems`: `tls`, `reality-xhttp`, `reality-tcp`, `hysteria`, `telemt`, `mtg`, `amneziawg`, `wireguard`, `ocserv`.

`export-user` собирает единый структурированный export для отправки пользователю.
Без `--output` результат со всеми необходимыми secret выводится только в stdout;
файл создаётся атомарно с mode `0600`. Временные `--address-mode` и
`--public-ip` не сохраняются в `users.json`. Старый `export-links` оставлен
совместимой командой.

В портале кнопка «Экспорт» формирует ZIP в памяти и отдаёт его как attachment:
скачайте «ZIP для Telegram» и прикрепите файл к сообщению вручную. Для короткой
передачи можно скопировать `send.txt`. Портал не обращается к Telegram API, не
просит bot token и не отправляет конфигурации третьей стороне.

Постоянный блок `client_export` выбирает endpoint во всех клиентских
конфигурациях, но не меняет `server`, SNI, Reality `serverName` и цели
сертификатов. Режим `public-ip` принимает только глобальный IPv4. HAPP/Karing
payload получает IP endpoints сразу, а HTTPS URL подписки по IP выдаётся только
когда direct route включён и сертификат содержит точный IP SAN.

Файлы конкретного пользователя создаются в `clients/<user>/`. Старый endpoint `/<token>` и его payload сохранены побайтно для ранее подключённых клиентов.

| Клиент | Что импортировать | Поддерживаемый набор | Важно |
|---|---|---|---|
| HAPP | `happ-subscription.txt` или QR | Reality xHTTP/TCP, Hysteria2, VLESS TLS | Для self-signed subscription endpoint включить insecure |
| Karing | `karing-subscription.txt` или QR | Reality xHTTP/TCP, Hysteria2, VLESS TLS | Использовать актуальную версию Karing |
| Karing + standard WG | `karing-wireguard.txt`/QR либо `karing-wireguard.yaml` | Clash WireGuard profile | Только `wg0`, `51821/udp`; это не AmneziaWG |
| WireGuard app | `wireguard.conf` или `wireguard.png` | Стандартный WireGuard | `wg0`, `51821/udp` |
| AmneziaWG app | `amneziawg.conf` или `amneziawg.png` | AmneziaWG с J/S/H/I obfuscation | Только `awg0`, `51820/udp`; не импортировать как обычный WG |
| Telegram | `telemt.txt`, `mtg.txt`, `telegram-proxy.txt` или QR | Telemt/mtg FakeTLS | Ссылки открываются в Telegram, не в HAPP/Karing |
| OpenConnect | `openconnect.txt` | ocserv | Отдельный клиент OpenConnect/AnyConnect |

Персональные SNI попадают в соответствующие HAPP/Karing URI после render/apply. Karing standard WG выдаётся отдельным Clash profile; AmneziaWG никогда не маскируется под WireGuard.

Команды CLI с `--restart` и операции портала сначала сравнивают сгенерированные файлы. Если содержимое не изменилось, сервисы не перезапускаются. Изменение доступа AmneziaWG/WireGuard синхронизируется с host-службой; peer-only изменения применяются через host sync без полной переустановки unit.

## Домены и SNI

Домены сайта и ocserv задаются в `setup.sh`; пустой ввод сохраняет текущее значение, `-`, `none` или `нет` сбрасывает необязательное значение. При отсутствии доменов стек работает по IP с локальными сертификатами там, где это допустимо клиентом.

Управление SNI после установки:

```bash
python3 tools/kvnctl.py sni-routes list
python3 tools/kvnctl.py sni-routes set-default reality-tcp example.com --restart
python3 tools/kvnctl.py sni-routes set-aliases reality-xhttp example.com,www.example.com --restart
python3 tools/kvnctl.py sni-routes add-alias tls edge.example.com
python3 tools/kvnctl.py edit-user USER --sni reality-tcp=example.com --restart
python3 tools/kvnctl.py edit-user USER --sni reality-tcp=default --restart
```

Домены сайта и подписки направляются на внутренний HTTPS-сайт. SNI ocserv направляется в `ocserv:443`. Неизвестный или пустой SNI открывает сайт-заглушку. Явные SNI VLESS, Telemt и mtg направляются в соответствующие backend.

В портале SNI добавляются в разделе «Настройки». При применении проверяются пересечения с SNI других сервисов, доменами сайта/подписки и ocserv, чтобы nginx не маршрутизировал один домен в разные backend.

Не существует универсального «белого списка» SNI для РФ: доступность DNS, TCP/TLS и QUIC меняется по региону и оператору. Перед сменой маршрута проверьте домен с сервера командой `python3 tools/kvnctl.py sni-routes diagnose <domain>` или кнопкой в портале. Диагностика ограничена 3 секундами, показывает только статус DNS/TLS без IP, сертификатов и секретов и не меняет конфигурацию; успешный результат не гарантирует доступность у другого оператора.

Индивидуальный выбор SNI пользователя поддерживается для `tls`, `reality-xhttp`, `reality-tcp` и `hysteria`. Пользователь получает выбранные значения в раздельных ссылках HAPP/Karing после render/apply. Для Reality домен сначала должен быть в `sni_routes.<system>.aliases`, чтобы nginx и Xray имели один и тот же список `serverNames`.

`telemt`, `mtg` и `ocserv` используют service-level SNI. Для Telemt нельзя безопасно выдать разные SNI разным пользователям в одном инстансе: `telemt/config.toml` содержит один `tls_domain`, а QR/secret должны ему соответствовать. Меняйте глобальный default через портал или CLI `sni-routes set-default telemt <domain>`.

Telemt и MTG поддерживают `camouflage_origin=external|local-site`. Для собственного SNI используйте `local-site`: backend обращается к внутреннему decoy `nginx:8443`, не зацикливаясь через публичный `443`. Настройка, bounded-диагностика и честные ограничения описаны в [`MTPROTO.md`](MTPROTO.md); CLI — `python3 tools/kvnctl.py mtproto status|diagnose|set-origin`. MTG остаётся shared endpoint без точной user attribution. Полную блокировку IP/TCP/TLS эта схема не гарантирует обойти.

Hysteria использует per-user SNI из разрешённого маршрута; `trafficStats` слушает только `127.0.0.1` внутри контейнера и запрашивается host-agent через authenticated loopback. Порт `9090` не публикуется наружу.

### Собственная зона и советник доменов

В разделе «Сеть» есть read-only советник: он проверяет фиксированный набор имён с общим лимитом времени, не меняет `users.json`, DNS, сертификаты или routes и не возвращает IP/содержимое сертификата. Рекомендуемая политика:

| Система | Политика домена |
|---|---|
| site / portal / subscription / VLESS TLS / Hysteria / ocserv | отдельные реальные hostname собственной зоны с DNS и подходящим SAN |
| Reality xHTTP / Reality TCP | внешний cover предпочтительнее; собственный server/route как target создаёт риск self-loop и блокировки |
| Telemt / mtg | service-level camouflage; один согласованный домен на инстанс |
| AmneziaWG / WireGuard | SNI не используется |

Для собственной зоны разделите роли, например `site.example.net`, `portal.example.net` и `sub.example.net`. Новые `tls`, `hy` или `oc` hostname сначала добавьте в DNS и сертификат. Не публикуйте в документации фактический production IP, состав SAN или срок действия сертификата.

Порядок применения: DNS → выпуск/проверка сертификата → SNI route → render/apply → проверка клиента. Советник не подтверждает доступность у другого оператора и не заменяет проверку клиента.

## Сертификаты

Во время первого `render --certs` рабочие сертификаты нужны ещё до готовности DNS и порта 80. Поэтому логика разделена:

| Каталог | Источник |
|---|---|
| `site-certs/` | Let's Encrypt для сайта/подписки, иначе временный self-signed |
| `ocserv/certs/` | Let's Encrypt для SNI ocserv, иначе временный self-signed |
| `certs/` | намеренно self-signed сертификат Xray с pin |
| `hy2/certs/` | намеренно self-signed сертификат Hysteria с pin |

Первичный выпуск после настройки DNS:

```bash
python3 tools/kvnctl.py letsencrypt status
python3 tools/kvnctl.py letsencrypt issue-configured --target all --restart
```

Для HTTP-01 домены должны указывать на сервер, а `80/tcp` должен быть доступен снаружи. Если фронтовый nginx уже запущен, CLI/портал временно останавливают его на время standalone-проверки Certbot и поднимают обратно. Если доменов для одного из targets нет, команда его пропустит.

Если портал использует отдельный домен или порт, например `ztv.example.com:8443`, site-сертификат обслуживает и сайт, и `portal-gateway`. Поэтому SAN должен включать домен сайта и домен портала. Команда `issue-configured` берёт этот набор из `users.json`; ручной `letsencrypt issue --target site` автоматически добавляет домен включённого портала.

Контроль и обслуживание:

```bash
python3 tools/kvnctl.py letsencrypt status --target all
python3 tools/kvnctl.py letsencrypt renew --restart
python3 tools/kvnctl.py letsencrypt reissue --target all --restart
sudo python3 tools/kvnctl.py letsencrypt install-renewal
systemctl list-timers kvn-letsencrypt-renew.timer
```

`renew` продлевает уже существующие сертификаты и разворачивает их в проект. Первый выпуск выполняет `issue-configured`. После обновления сертификата ocserv клиентские файлы регенерируются, так как содержат pin.

## Источник данных

`users.json` является единственным источником правды. Не редактируйте вручную:

- `nginx/nginx.conf`;
- `xray/config.json`, `hy2/config.yaml`;
- `amneziawg/awg0.conf`;
- `wireguard/wg0.conf`;
- `telemt/config.toml`, `mtg/config.toml`;
- `ocserv/ocserv.conf`, `ocserv/users.txt`, `ocserv/ocserv.env`;
- `nginx/portal-gateway.conf`;
- `clients/`, `CLIENT_LINKS.md`, `nginx/web/`.

`portal-data/portal.db` — runtime БД сессий, блокировок и аудита. Её нельзя переносить в чистый deploy или редактировать вручную; для backup копируйте файл только вместе с закрытым portal либо через SQLite backup.

После ручного изменения `users.json`:

```bash
python3 tools/kvnctl.py render
sudo ./amneziawg/sync-host-service.sh
sudo ./wireguard/sync-host-service.sh
docker compose -f docker-compose.yml up -d --build --remove-orphans
```

## Backup, restore и очистка

Портал имеет раздел «Бэкапы». Он вызывает host-agent RPC `project.backup`, запускает `tools/project-backup.sh` через systemd и показывает готовые архивы из `/backup`. Контейнер портала монтирует `/backup:/backup:ro`, поэтому скачивание доступно только для файлов `kvn-vpn-backup-*.tar`.

Ручной backup на Debian:

```bash
cd /srv/kvn-vpn
sudo ./tools/project-backup.sh
sudo ls -lh /backup/kvn-vpn-backup-*.tar
```

Backup-архив содержит runtime-секреты: папку проекта, пользовательские ключи, токены, сертификаты, portal DB и Docker images, нужные для переноса. Не кладите `kvn-vpn-backup-*.tar` в deploy-архив, `nginx/web/`, публичные ссылки, issue, чат или git.

Восстановление на другом Debian-сервере:

```bash
sudo ./tools/restore-backup.sh /backup/kvn-vpn-backup-YYYYMMDD-HHMMSS-host.tar /opt/kvn-vpn
cd /opt/kvn-vpn
sudo ./setup.sh <NEW_SERVER_IP_OR_DOMAIN>
```

После restore проверьте DNS/firewall, перевыпустите Let's Encrypt при смене доменов и выполните `portal status`, `amneziawg verify`, `wireguard verify`.

Очистка локального мусора проекта:

```bash
./tools/cleanup-project.sh --dry-run
./tools/cleanup-project.sh --apply
```

Скрипт удаляет только кеши и временные файлы (`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `*.pyc`, `*.tmp`, `*.bak`, `*.orig`, `*~`). Он отказывается трогать `users.json`, `clients/`, сертификаты, portal/metrics DB, generated-конфиги и `/backup`.

## Диагностика

Базовые проверки:

```bash
python3 tools/kvnctl.py render
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.yml ps
docker compose -f docker-compose.yml logs --tail=100 nginx xray hysteria telemt mtg ocserv
systemctl status kvn-amneziawg.service --no-pager
systemctl status kvn-wireguard.service --no-pager
systemctl status kvn-portal-agent.service --no-pager
journalctl -u kvn-portal-agent.service -n 100 --no-pager
stat /run/kvn-portal/control.sock /etc/kvn-portal/agent.secret
```

Если портал возвращает `502`, сначала проверьте agent, socket/group и журнал. Если route возвращает `404` после настройки, проверьте `portal status`, DNS, `80/tcp`, SAN live-сертификата и выполните `letsencrypt issue-configured --target site --restart`.

Если сайт или портал не открываются, сначала отделите внешний firewall/DNS от Docker publish. `ping` не доказывает доступность TCP-портов: ICMP может проходить, а `80/443/<portal_port>` блокироваться или ломаться на Docker bridge. В примерах ниже замените `8443` на фактический порт портала, если он другой.

```bash
sudo ss -ltnp | grep -E ':(80|443|8443)\b'
curl -4I --connect-timeout 3 http://127.0.0.1/
curl -4kI --connect-timeout 3 --resolve <domain>:443:127.0.0.1 https://<domain>/
curl -4kI --connect-timeout 3 --resolve <domain>:<portal_port>:127.0.0.1 https://<domain>:<portal_port>/<portal_path>/
```

Если с host namespace есть reset/timeout, но внутри контейнера nginx отвечает, пересоздайте Compose-сеть и перезапустите Docker. Для портала на отдельном порту нужен profile `portal-custom`; если портал висит на общем `443/tcp`, используйте только `COMPOSE_PROFILES=portal`.

```bash
docker compose -f docker-compose.yml exec -T nginx sh -lc 'wget -S -O- http://127.0.0.1/ 2>&1 | head -80'
sudo env COMPOSE_PROFILES=portal,portal-custom KVN_PORTAL_PORT=<portal_port> docker compose -f docker-compose.yml down --remove-orphans
sudo systemctl restart docker
sudo env COMPOSE_PROFILES=portal,portal-custom KVN_PORTAL_PORT=<portal_port> docker compose -f docker-compose.yml up -d --remove-orphans
```

Если direct container IP работает, а опубликованный порт нет, проблема в Docker publish/bridge или host firewall. Если опубликованный порт локально работает, а домен снаружи нет, проверьте cloud firewall/provider security group.

Если в портале логи отстают, проверьте время на сервере, `kvn-portal-agent.service`, доступность Docker CLI для agent и используйте `journalctl`/`docker compose logs` напрямую. Портал показывает tail журналов без секретов и не заменяет systemd-журналы при аварийной диагностике.

AmneziaWG:

```bash
python3 tools/kvnctl.py amneziawg diagnose USER
sudo awg show awg0
sudo journalctl -u kvn-amneziawg.service -n 100 --no-pager
```

Если клиент бесконечно ожидает рукопожатие, сначала обновите пакет AmneziaWG через `apt update` и повторный запуск `setup.sh`, затем проверьте DNS endpoint, `51820/udp`, состояние службы и наличие peer в project/host конфигурациях. Для проверки входящих пакетов можно отдельно установить `tcpdump` и выполнить:

```bash
sudo tcpdump -ni any 'udp port 51820'
```

WireGuard:

```bash
sudo python3 tools/kvnctl.py wireguard diagnose USER
sudo wg show wg0
sudo journalctl -u kvn-wireguard.service -n 100 --no-pager
```

Если стандартный WireGuard подключается, но трафик не идёт, проверьте `51821/udp`, свежий `wireguard.conf`, `AllowedIPs = 0.0.0.0/0` и совпадение peers:

```bash
sudo python3 tools/kvnctl.py wireguard verify
sudo tcpdump -ni any 'udp port 51821'
```

Если project/host конфиги различаются, выполните:

```bash
python3 tools/kvnctl.py render
sudo ./amneziawg/sync-host-service.sh
sudo ./wireguard/sync-host-service.sh
sudo python3 tools/kvnctl.py amneziawg verify
sudo python3 tools/kvnctl.py wireguard verify
sudo python3 tools/kvnctl.py reconcile
```

`reconcile` повторно применяет уже сохранённое desired state без нового изменения пользователя и сообщает `applied`, `applied_with_fallback`, `reconcile_required` либо `failed`.

В web-портале то же действие доступно на странице «Сервисы»: у `amneziawg` и `wireguard` нажмите «Применить конфиг». Кнопка повторно рендерит desired state и запускает host sync даже без новых изменений в `users.json`.

OpenConnect: ответ nginx вместо ocserv означает неверный SNI. Медленная работа обычно означает недоступный DTLS-порт `4443/udp`.

Прямые порты `2443-2448/tcp` позволяют проверить backend в обход nginx. Если прямое подключение работает, а `443/tcp` нет, проверяйте SNI-карту и логи nginx.

## Проверка проекта

```bash
python3 -m py_compile tools/kvnctl.py portal/agent.py portal/control.py
python3 -m compileall -q portal tools
python3 -m unittest discover -s tests -v
python3 tools/docs_check.py
bash -n setup.sh update.sh tools/*.sh amneziawg/*.sh wireguard/*.sh ocserv/*.sh portal/*.sh
./tools/cleanup-project.sh --dry-run
docker compose -f docker-compose.yml config --quiet
docker build --target test -t kvn-portal:test portal
./tools/build-deploy.sh
KVN_BUILD_ID=YYYYMMDD-release1 ./tools/build-release.sh
```

Deploy-архив создаётся из явного списка файлов. В него не попадают пользователи, клиенты, приватные ключи, сертификаты и сгенерированные конфиги. Шаблон `deploy/users.json` всегда должен содержать пустой список `users`.

## Передача проекта

Для продолжения в другой ИИ-сессии используйте `HANDOFF_PROMPT.md` как стартовый prompt. Он содержит текущий статус, границы безопасности, проверочные команды, SHA deploy-артефакта и свежие диагностические заметки без runtime-секретов.

При передаче на другой ПК передавайте source tree и `kvn-vpn-deploy.tar.gz`. Не передавайте `users.json`, `clients/`, сертификаты, `.env`, portal/metrics DB и backup-архивы, если новому агенту не нужен доступ к реальному установленному серверу. Если нужен полный перенос production-состояния, используйте только защищённый backup `kvn-vpn-backup-*.tar` и считайте его секретом.

На новом ПК сначала сверить артефакт:

```bash
sha256sum kvn-vpn-deploy.tar.gz
cat PORTAL_UPDATE_NOTES.md
```

На Windows:

```powershell
Get-FileHash -Algorithm SHA256 .\kvn-vpn-deploy.tar.gz
Get-Content .\PORTAL_UPDATE_NOTES.md
```
