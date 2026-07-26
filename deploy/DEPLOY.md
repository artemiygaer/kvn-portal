# Установка и обновление KVN VPN v3

Каталог `deploy/` является чистым пакетом для Debian 12/13. Он не содержит пользователей, portal credentials/DB, клиентских файлов, сертификатов, приватных ключей и сгенерированных серверных конфигов.

## Контексты команд

- **Рабочая машина:** сборка архива, unit-тесты, syntax и hash-проверки.
- **Debian-сервер:** все команды с `sudo`, `systemctl`, `journalctl`, firewall, Certbot и host-agent.

Не запускайте Debian-only команды на Windows. Проект не предполагает наличие UFW: правила firewall настраиваются тем средством, которое используется на сервере и в cloud provider.

## До установки

1. Если используются домены, создайте DNS A/AAAA для домена сайта и отдельного домена портала, если они отличаются. Для установки только по белому IPv4 DNS не нужен.
   Для apex-записи `@` используйте один активный IP сервера, где реально слушают `80/tcp` и `443/tcp`. Не держите несколько `@ A` на разные VPS, если на каждом нет одинакового nginx/сертификата: внешние health-checker'ы будут попадать на случайный IP и помечать HTTP/SSL как ошибку.
2. Для доменного режима дождитесь, пока домены разрешаются в публичный IP сервера.
3. Откройте порты одновременно на хосте и в cloud firewall.

| Порт | Назначение |
|---|---|
| `443/tcp` | nginx SNI-router; портал также может использовать этот порт |
| `<PORTAL_PORT>/tcp` | отдельный HTTPS-порт портала, если выбран в setup |
| `80/tcp` | HTTP-проверка домена, редирект на HTTPS, Let's Encrypt HTTP-01 во время выпуска/renew |
| `443/udp` | Hysteria 2 |
| `4443/udp` | OpenConnect DTLS |
| `51820/udp` | AmneziaWG |
| `51821/udp` | WireGuard |
| `2096/tcp` | резервная подписка |
| `2443-2448/tcp` | прямые диагностические входы протоколов |

Отдельный portal port рекомендуется: он сохраняет реальный IP для блокировки входа. При размещении портала за общим `443/tcp` L4/SNI-схема может объединить клиентов по адресу промежуточного proxy.

## Fresh install / Fresh setup

Команды на Debian-сервере:

```bash
sudo install -d -m 0750 /srv/kvn-vpn
sudo tar -xzf kvn-vpn-deploy.tar.gz -C /srv/kvn-vpn --strip-components=1
cd /srv/kvn-vpn
sudo ./setup.sh <PUBLIC_IP_OR_ENDPOINT>
```

Setup:

1. Установит Docker/Compose, Python 3, Certbot и остальные зависимости.
2. Проверит обновление ядра и пакета AmneziaWG. При требовании reboot завершится до вопросов конфигурации.
3. Запросит домены/SNI, параметры HTTPS-портала, login/password и пользователей.
4. Для домена выпустит обычный Let's Encrypt. Для IPv4 попробует Certbot 5.4+ с краткоживущим IP-сертификатом либо предложит явный self-signed fallback с IP SAN. До подходящего сертификата public route остаётся закрытым.
5. Установит `kvn-amneziawg.service`, `kvn-wireguard.service`, `kvn-portal-agent.service` и timer продления сертификатов.
6. Запустит только требуемые Compose profiles и проверит health.

Повторный setup и последующий update используют сохранённый `services.*.enabled`: отключённые оператором сервисы не запускаются снова. Постоянно включайте/отключайте сервис через портал или typed CLI; одиночный `docker stop` меняет только текущий runtime.

После запуска compose `nginx` постоянно публикует `80/tcp`: корень `/` отвечает `200 OK` для внешних доменных health-checker'ов, остальные HTTP-пути редиректятся на HTTPS. При выпуске и продлении Let's Encrypt используется standalone HTTP-01: если фронтовый nginx уже запущен, CLI/портал временно останавливают его и поднимают обратно после Certbot.

### Установка портала только по белому IPv4

Передайте setup реальный публичный IPv4 сервера. В мастере портала укажите тот же адрес и отдельный HTTPS-порт, например `8443`; IP-портал на общем `443/tcp` запрещён. Откройте этот TCP-порт в firewall хоста и облака.

```bash
cd /srv/kvn-vpn
sudo ./setup.sh <БЕЛЫЙ_IP>
sudo python3 tools/kvnctl.py portal status
sudo ss -ltnp | grep ':8443'
curl -kI https://<БЕЛЫЙ_IP>:8443/<ПУТЬ>/login
```

IP-ветка не выполняет DNS lookup. Certbot 5.4+ вызывается со штатными `--preferred-profile shortlived --ip-address`; setup не устанавливает нестабильный Certbot из PyPI или Debian unstable. Если версия Certbot старее или CA недоступен, self-signed разрешается только отдельным подтверждением. В этом случае браузер показывает предупреждение, но HTTPS, login, custom path, CSRF и блокировка входа продолжают работать. Route открывается только при совпадении IP SAN и выбранной политики.

Если setup потребовал reboot:

```bash
sudo reboot
cd /srv/kvn-vpn
sudo ./setup.sh <PUBLIC_IP_OR_ENDPOINT>
```

## Проверка после установки

Debian-only:

```bash
sudo systemctl status kvn-amneziawg.service --no-pager
sudo systemctl status kvn-wireguard.service --no-pager
sudo systemctl status kvn-portal-agent.service --no-pager
sudo journalctl -u kvn-portal-agent.service -n 100 --no-pager
sudo stat /run/kvn-portal/control.sock /etc/kvn-portal/agent.secret
sudo docker compose -f docker-compose.yml ps
sudo python3 tools/kvnctl.py portal status
sudo python3 tools/kvnctl.py letsencrypt status --target all
```

В `docker compose config` web-портал не должен иметь `/var/run/docker.sock`, privileged mode или host network. Socket управления создаёт только systemd agent.

Проверьте метрики и полное совпадение AmneziaWG/WireGuard desired/generated/host/runtime:

```bash
sudo python3 tools/kvnctl.py amneziawg verify
sudo python3 tools/kvnctl.py wireguard verify
sudo python3 tools/kvnctl.py reconcile
sudo test -f /var/lib/kvn-portal/metrics.db
```

Если пользователь создан или изменён через web, а AmneziaWG/WireGuard peer не появился в runtime, используйте в портале страницу «Сервисы» → `amneziawg`/`wireguard` → «Применить конфиг». Это повторяет render + host sync и работает даже без изменений в `users.json`.

## Эксплуатация портала

Публичный URL: `https://<PORTAL_DOMAIN_OR_IP>:<PORTAL_PORT><PORTAL_PATH>`.

```bash
sudo python3 tools/kvnctl.py portal status
sudo python3 tools/kvnctl.py portal configure
sudo python3 tools/kvnctl.py portal reset-credentials --login <NEW_LOGIN>
sudo python3 tools/kvnctl.py portal unlock-ip <CLIENT_IP>
```

- Пароль вводится через `getpass`, не через argv.
- «Настройки» → «Нагрузка» содержит профили «Стандартный», «Облегчённый» и «Свой». Облегчённый профиль останавливает sampler/history и фоновый polling без рестарта VPN-сервисов; ручное обновление остаётся доступно, накопленная БД не удаляется.
- Карточка пользователя показывает protocol activity без IP, endpoint, UUID, ключей, паролей и client-file content. В light mode initial/background activity request отсутствует; доступно только ручное обновление.
- В каждой service card есть lazy inline-log: до раскрытия панели запросов журнала нет, polling не запускается, вывод bounded и вставляется как text. Для расширенной диагностики используйте общую страницу логов или `journalctl`/Compose на сервере.
- Обновление через «Настройки» разделено на загрузку/проверку и отдельный запуск. Root-пароль текущей portal session требуется только при запуске; архив проверяется до публикации готовности, а `update.sh` повторяет проверку в staging. Пароль не сохраняется и не записывается в audit.
- Release передаётся напрямую в `portal-data/updates`, без 16-МиБ `/tmp`; оба nginx-маршрута имеют лимит 2 ГиБ. Если старая версия падает на 0%, один раз обновите её вручную с сервера, затем новые архивы можно снова загружать через портал.
- Пять неверных входов блокируют IP на 12 часов.
- Reset credentials инвалидирует все portal sessions.
- Смена domain/IP/port/path выполняется только через `portal configure`, затем требуется актуальный firewall, а для домена также DNS. IP требует отдельный порт и сертификат с совпадающим IP SAN.
- Быстрые переходы открываются кнопкой «Команды» или `Ctrl+K`; на странице «Сервисы» доступны поиск, фильтр состояния и фильтр host/container.
- Раздел «Консоль» — отдельный полноразмерный root shell. Он открывается после ввода системного root-пароля, привязан к текущей portal session, проксируется через PTY и работает как xterm.js-терминал в браузере: ANSI/curses, cursor, resize, Enter, Tab, стрелки, Backspace, Ctrl-сочетания и paste. При кратком обрыве Unix socket UI показывает reconnect-статус и не пишет служебную ошибку в терминальный вывод. CSP сохраняет `script-src 'self'`, но `style-src` включает `'unsafe-inline'` для динамических размеров xterm. На Debian/systemd shell запускается transient unit `kvn-portal-root-shell-*` через `systemd-run --pty`. Проверка пароля сначала использует `/etc/shadow`, затем резервную PAM-проверку через `systemd-run --uid=nobody su root -c /bin/true`, чтобы не зависеть от поддержки yescrypt в Python. Команды и вывод shell не пишутся в аудит; аудитируются open/close и ошибки входа. Если root-пароль не задан, выполните `sudo passwd root` на сервере.
- Раздел «Команды» выполняет быстрые root-команды обслуживания через список разрешённых действий host-agent; команды `render`/`reconcile` требуют подтверждения и пишутся в аудит.
- Графики хранят историю до 72 часов; доступны диапазоны 1/6/24/72 часа и шаг 1/5/15/60 минут.
- Графики CPU/RAM/disk/network показывают текущие/минимальные/максимальные значения; RAM/disk дополнительно показывают абсолютные значения used/total.
- Для экономии VPS dashboard кэширует тяжёлые widget-запросы 60 секунд, сертификаты 15 минут; логи обновляются раз в 20 секунд и polling останавливается в скрытой вкладке.
- Контейнер портала по умолчанию запускает `gunicorn` как `1 worker / 2 threads` с timeout 1800 секунд для больших upload-запросов. Только archive inspect/update RPC получают этот длинный timeout; обычные RPC сохраняют 10 секунд. Dashboard обновляет тяжёлые источники в фоне и сохраняет последний успешный snapshot актуальным; `stale` означает реальную ошибку или отсутствие данных. При нехватке или избытке ресурсов задайте env `KVN_PORTAL_WORKERS`, `KVN_PORTAL_THREADS`, `KVN_PORTAL_TIMEOUT`, `KVN_PORTAL_KEEPALIVE`, `KVN_PORTAL_MAX_REQUESTS`.
- Docker build портала использует локальный `portal/wheels/` и `pip --no-index`; PyPI во время setup/update не требуется. Если build всё равно падает на DNS, проблема уже в pull базовых Docker images или apt-слоях, а не в Python-зависимостях портала.
- Docker build `ocserv` использует `build.network=host`, потому что на части VPS DNS внутри BuildKit не резолвит `deb.debian.org`, хотя host `apt` работает. Это применяется только на этапе сборки образа.
- В карточке пользователя доступны раздельные QR AmneziaWG app, стандартного WireGuard, HAPP/Karing и отдельный Karing WireGuard Clash-профиль; preview и скачивание требуют portal session.
- Для Telegram proxy портал отдаёт `telemt.txt`, `mtg.txt`, `telegram-proxy.txt` и QR только при включённых `telemt`/`mtg`.
- При `reconcile_required` выполните `sudo python3 tools/kvnctl.py reconcile` и проверьте итоговый outcome.

Для SNI нет универсального «белого списка» для РФ: DNS/TLS/QUIC меняются по оператору и региону. Перед применением проверьте домен с сервера, это не меняет маршруты и не раскрывает IP/сертификат:

```bash
sudo python3 tools/kvnctl.py sni-routes diagnose example.com
```

Успешный ответ полезен только как проверка с этого сервера: отдельно проверьте подключение у нужного оператора. Hysteria statistics доступны только локально внутри контейнера и не требуют открытия дополнительного порта.

В портале раздел «Сеть» содержит read-only советник доменов. Он проверяет не более семи фиксированных hostnames за общий ограниченный интервал, показывает только статусы DNS/TLS/SAN/same-server и ничего не сохраняет. Используйте раздельные реальные hostname для site, portal, subscription, VLESS TLS, Hysteria и ocserv. Для Reality xHTTP/TCP выбирайте внешний cover; target/serverNames должны соответствовать внешнему сайту и его SAN, а same-server target считается опасным. Telemt/mtg используют service-level camouflage, AWG/WG не используют SNI.

Для собственного SNI Telemt/MTG включайте в портале «Настройки → MTProto → Собственный сайт» только после создания DNS и добавления SNI в SAN `site-certs`. В этом режиме camouflage идёт на внутренний `nginx:8443`, а не обратно на public `443`. Проверка: `sudo python3 tools/kvnctl.py mtproto diagnose telemt|mtg`. DNS-недоступность остаётся bounded-предупреждением; конфликт route или отсутствующий SAN блокируют переключение. MTG использует shared secret без user attribution; полную IP/TCP/TLS-блокировку схема не гарантирует обойти. Подробности — `MTPROTO.md`.

Матрица импорта клиентов:

| Клиент | Файл/URL | Порты и ограничения |
|---|---|---|
| HAPP | `happ-subscription.txt`/QR | Reality xHTTP/TCP, Hysteria2, TLS; self-signed требует insecure |
| Karing | `karing-subscription.txt`/QR | Отдельный endpoint Reality xHTTP/TCP, Hysteria2, TLS |
| Karing WireGuard | `karing-wireguard.txt`/QR или `.yaml` | Clash standard WG, только `wg0:51821/udp` |
| WireGuard app | `wireguard.conf`/QR | Standard WG, `51821/udp` |
| AmneziaWG app | `amneziawg.conf`/QR | AWG, `awg0:51820/udp`; не выдавать как standard WG |
| Telegram | `telemt.txt`, `mtg.txt`, общий файл/QR | Только Telegram; MTG имеет shared attribution |
| OpenConnect | `openconnect.txt` | ocserv TCP/DTLS, отдельный клиент |

Для собственной зоны используйте отдельные hostname для сайта, портала и подписки. Для новых `tls`, `hy` и `oc` ролей сначала создайте A/AAAA records и добавьте точные имена в SAN. Безопасный порядок: DNS → сертификат → route → render/apply → проверка реальным клиентом.

Если новый домен ещё не получил сертификат:

```bash
sudo python3 tools/kvnctl.py letsencrypt issue-configured --target site --restart
sudo python3 tools/kvnctl.py portal status
```

Проверьте DNS и входящий `80/tcp`. После запуска `curl -I http://<domain>/` должен получать `200 OK` от nginx на `/`; остальные HTTP-пути могут получать `301` на HTTPS. Fail-closed route до успешного выпуска возвращает `404`, не публикуя self-signed fallback. Если портал открыт на отдельном домене, например `ztv.example.com:8443`, site-сертификат должен содержать и домен сайта, и домен портала в SAN; используйте `issue-configured` или добавьте оба домена в ручной `issue`.

Если Free Domain/Nodeloc показывает `HTTP error` при `DNS ok`, проверьте, что apex `@` не содержит старые IP:

```bash
dig +short A <domain> @1.1.1.1
curl -4I --resolve <domain>:80:<IP> http://<domain>/
curl -4Ik --resolve <domain>:443:<IP> https://<domain>/
```

Если сайт или портал всё равно не открываются, не ограничивайтесь `ping`: ICMP может отвечать при недоступных TCP-портах. Сначала проверьте публикацию портов на самом сервере; в примере замените `8443` на фактический порт портала, если он другой:

```bash
sudo ss -ltnp | grep -E ':(80|443|8443)\b'
curl -4I --connect-timeout 3 http://127.0.0.1/
curl -4kI --connect-timeout 3 --resolve <domain>:443:127.0.0.1 https://<domain>/
curl -4kI --connect-timeout 3 --resolve <domain>:<portal_port>:127.0.0.1 https://<domain>:<portal_port>/<portal_path>/
```

Если host `curl` получает reset/timeout, а nginx внутри контейнера отвечает, пересоздайте Compose-сеть и Docker publish rules. Для портала на отдельном порту нужен profile `portal-custom`; если портал висит на общем `443/tcp`, используйте только `COMPOSE_PROFILES=portal`.

```bash
sudo docker compose -f docker-compose.yml exec -T nginx sh -lc 'wget -S -O- http://127.0.0.1/ 2>&1 | head -80'
sudo env COMPOSE_PROFILES=portal,portal-custom KVN_PORTAL_PORT=<portal_port> \
  docker compose -f docker-compose.yml down --remove-orphans
sudo systemctl restart docker
sudo env COMPOSE_PROFILES=portal,portal-custom KVN_PORTAL_PORT=<portal_port> \
  docker compose -f docker-compose.yml up -d --remove-orphans
```

Если локальный published port работает, а снаружи нет, причина почти всегда в cloud firewall/security group или provider layer. Если direct container IP работает, а published port нет, ищите проблему в Docker bridge/NAT/firewall на host.

Если портал возвращает `502`:

```bash
sudo systemctl status kvn-portal-agent.service --no-pager
sudo journalctl -u kvn-portal-agent.service -n 100 --no-pager
sudo stat /run/kvn-portal/control.sock /etc/kvn-portal/agent.secret
sudo docker compose -f docker-compose.yml logs --tail=100 portal
```

Проверьте группу `kvn-portal`, права socket/secret и совпадение project root в systemd unit. Не обходите agent выдачей Docker socket контейнеру.

## Backup

Основной вариант — штатный архив проекта. Его можно создать в портале: раздел «Бэкапы» запускает host-agent, пишет `kvn-vpn-backup-*.tar` в `/backup` и даёт скачать файл из authenticated session. Ручной вариант на Debian:

```bash
cd /srv/kvn-vpn
sudo ./tools/project-backup.sh
sudo ls -lh /backup/kvn-vpn-backup-*.tar
```

`setup.sh` создаёт `/backup` с группой `kvn-portal`, а portal container монтирует его read-only. Архив содержит папку проекта, runtime-данные и Docker images для переноса.

Backup содержит секреты: `users.json`, ключи пользователей, сертификаты, portal DB, metrics DB и Docker state. Храните файл как root-only, шифруйте при переносе и не кладите `kvn-vpn-backup-*.tar` в deploy-архив, `nginx/web/`, публичные ссылки или git.

Fallback перед upgrade, если новый backup-скрипт ещё недоступен: остановите portal на короткое время для согласованной SQLite-копии.

```bash
cd /srv/kvn-vpn
sudo docker compose -f docker-compose.yml --profile portal stop portal
sudo tar -czf /root/kvn-state-backup.tar.gz \
  users.json .env portal-data clients certs site-certs hy2/certs ocserv/certs
sudo tar -czf /root/kvn-agent-backup.tar.gz /etc/kvn-portal
sudo cp -a /var/lib/kvn-portal /root/kvn-metrics-backup
sudo docker compose -f docker-compose.yml --profile portal start portal
```

Если какого-либо необязательного пути нет, исключите его из команды. Backup содержит секреты: храните его с правами root и шифруйте при переносе.

## Restore на другой сервер

Debian-only:

```bash
sudo ./tools/restore-backup.sh /backup/kvn-vpn-backup-YYYYMMDD-HHMMSS-host.tar /opt/kvn-vpn
cd /opt/kvn-vpn
sudo ./setup.sh <PUBLIC_IP_OR_ENDPOINT>
sudo python3 tools/kvnctl.py portal status
sudo python3 tools/kvnctl.py amneziawg verify
sudo python3 tools/kvnctl.py wireguard verify
```

Restore-скрипт отказывается распаковывать архив с небезопасным именем, в широкий target (`/`, `/etc`, `/var`, `/usr`) или в непустой каталог. Docker images из backup загружаются, если Docker уже доступен. После переноса на новый IP/домен проверьте DNS, firewall и сертификаты Let's Encrypt.

## Upgrade

Обновление выполняется тем же `update.sh`: через портал после загрузки архива или вручную из корня установленного проекта. В обоих вариантах runtime-данные сохраняются.

## Обновление через портал

Краткая памятка по текущему релизу и проверкам после обновления: `PORTAL_UPDATE_NOTES.md`.

Через портал: откройте «Настройки», выберите `kvn-vpn-release-linux-amd64.tar.gz` и нажмите «Загрузить и проверить». Дождитесь 100% передачи и отдельного состояния «Проверяю архив». Файл пишется потоково через temp+fsync+atomic rename; до публикации готовности проверяются лимиты, свободное место, SHA-256, `linux/amd64`, точный набор images и чистый вложенный deploy. Карточка «Готов к обновлению» сохраняется в portal DB и доступна после reload или нового входа.

В карточке готовности выберите режим, введите системный root-пароль и отдельно подтвердите «Запустить обновление». Путь архива браузер не передаёт: portal извлекает его по opaque ID, атомарно блокирует повторный запуск и передаёт host-agent сохранённый SHA-256. При ошибке запуска карточка снова становится готовой; при `archive_changed`/`not_found` удалите её и загрузите архив заново. Пароль привязан к текущей session, не сохраняется и не попадает в аудит. Результат показывает source/images SHA-256, unit, журнал и recovery-команду.

Полный release — рекомендуемый вариант для 1 vCPU/1 ГБ: images загружаются и проверяются до изменения source, а Compose запускается только с `--no-build --pull never`. Source-only deploy совместим, но использует online build/pull fallback.

### Обновление из GitHub Releases

Источник зафиксирован как `artemiygaer/kvn-portal`; URL и произвольный repository из браузера или RPC не принимаются. «Проверить GitHub» только читает метаданные Release, а «Скачать и проверить» готовит архив. Обновление запускается отдельной кнопкой с системным root-паролем.

Публичный репозиторий работает без token. Для приватного Release credential создаётся только на Debian-сервере:

```bash
sudo python3 tools/kvnctl.py updates configure \
  --enable true --channel stable --asset-preference release --set-token
sudo python3 tools/kvnctl.py updates status
```

Token вводится через `getpass`, сохраняется в `/etc/kvn-portal/github.token` как root-only файл и не выводится командой status. Не вставляйте token в портал, аргументы shell, чат или документацию. При недоступности GitHub, DNS, API rate limit или несовпадении digest используйте ручную загрузку того же штатного архива.

Update, setup и portal apply используют единый effective service plan. Сервис с `services.<name>.enabled=false` не включается в Compose profiles и не запускается как скрытая зависимость; updater также удаляет orphan-контейнеры.

Для старого портала, который ещё не принимает full release: загрузите source-only `kvn-vpn-deploy.tar.gz`, выберите «Только updater и host-agent», дождитесь завершения и затем загрузите full release в обычном режиме. Первый шаг не выполняет render, build/pull или restart VPN-контейнеров.

После завершения проверьте build id в shell портала, список пользователей, выдачу QR/preview и актуальность логов. Если операция упала, откройте журнал unit из результата операции:

```bash
sudo journalctl -u kvn-project-update-<ID> -n 200 --no-pager
sudo systemctl status kvn-project-update-<ID> --no-pager
```

## Ручное обновление через update.sh

Положите новый архив в корень проекта и запустите updater. Он не затирает `users.json`, certificates, clients, portal DB и metrics DB. Debian-only:

```bash
cd /srv/kvn-vpn
sudo cp /path/to/kvn-vpn-release-linux-amd64.tar.gz .
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
sudo python3 tools/kvnctl.py amneziawg verify
sudo python3 tools/kvnctl.py wireguard verify
sudo docker compose -f docker-compose.yml ps
```

Без аргумента `update.sh` предпочитает `kvn-vpn-release-linux-amd64.tar.gz`, затем source deploy. Путь к архиву можно передать первым аргументом. Source-only вариант явно предупреждает о разрешённой сборке/загрузке images.

Новые архивы содержат `.kvn-canonical-files`; updater берёт список обновляемых source-файлов из manifest архива и отклоняет runtime-пути (`users.json`, certs, clients, DB, generated-конфиги). Перед заменой source-файлы проходят staging-проверку, создаётся root-only snapshot в `.update-backups/`; если ошибка случилась до `docker compose up`, source автоматически возвращаются из snapshot. Это позволяет добавлять новые source-файлы без правки уже установленного списка.

SNI-пулы управляются в портале через «Настройки» или CLI `sni-routes`. Пересечения доменов между сервисами, сайтом/подпиской и ocserv отклоняются до применения.

Индивидуальные SNI в портале применяются к `tls`, `reality-xhttp`, `reality-tcp` и `hysteria`; отдельные HAPP/Karing endpoints получают Reality xHTTP/TCP, Hysteria2 и TLS с выбранными значениями после render/apply. Standard WireGuard для Karing выдаётся отдельным Clash URL на `wg0:51821`. AmneziaWG остаётся импортом для AmneziaWG app на `awg0:51820`. Старый `/<token>` не изменён. Telemt и mtg имеют service-level SNI: для Telemt меняйте глобальный default через портал или `sudo python3 tools/kvnctl.py sni-routes set-default telemt <domain> --restart`, иначе QR/secret и `telemt/config.toml` разойдутся.

Кнопка «Экспорт» формирует ZIP в памяти: скачайте «ZIP для Telegram» и прикрепите его к сообщению либо скопируйте `send.txt`. Прямой отправки через Telegram API нет: портал не принимает bot token и не передаёт конфигурации третьей стороне. Режим public-IP меняет только endpoint подключения; SNI, Reality `serverName` и certificate identity остаются доменными. HTTPS URL подписки по IP выдаётся только при включённом direct route и точном IP SAN.

## Проверка после обновления

После portal/manual upgrade проверьте:

```bash
sudo python3 tools/kvnctl.py portal status
sudo python3 tools/kvnctl.py letsencrypt status --target all
sudo python3 tools/kvnctl.py amneziawg verify
sudo python3 tools/kvnctl.py wireguard verify
sudo docker compose -f docker-compose.yml ps
```

В портале дополнительно проверьте build id, IP текущей сессии, список пользователей, QR/preview для HAPP/Karing, AmneziaWG/WireGuard и Telegram proxy.

## Fallback для очень старой установки

Если установленный updater падает из-за отсутствующих файлов, сначала запустите новый updater из source deploy во временном каталоге. Старый `update.sh` при этом не используется:

```bash
cd /srv/kvn-vpn  # либо фактический каталог проекта
sudo rm -rf /root/kvn-update-bootstrap
sudo install -d -m 0700 /root/kvn-update-bootstrap
sudo tar -xzf ./kvn-vpn-deploy.tar.gz -C /root/kvn-update-bootstrap --strip-components=1
sudo env KVN_UPDATE_ROOT="$PWD" \
  /bin/bash /root/kvn-update-bootstrap/update.sh --bootstrap-only ./kvn-vpn-deploy.tar.gz
sudo ./update.sh ./kvn-vpn-release-linux-amd64.tar.gz
```

Bootstrap обновляет source/updater/agent, но не запускает render или Compose и не заменяет runtime. Если обновляется очень старая установка без `update.sh`, не распаковывайте чистый `users.json` поверх рабочей конфигурации.

```bash
sudo rm -rf /root/kvn-release-next
sudo install -d -m 0700 /root/kvn-release-next
sudo tar -xzf kvn-vpn-deploy.tar.gz -C /root/kvn-release-next --strip-components=1
sudo rm /root/kvn-release-next/users.json
sudo cp -a /root/kvn-release-next/. /srv/kvn-vpn/
cd /srv/kvn-vpn
sudo ./setup.sh <PUBLIC_IP_OR_ENDPOINT>
```

`portal-data/`, `/var/lib/kvn-portal/metrics.db`, `users.json`, credentials, certificates и clients сохраняются. Setup повторно проверяет системные пакеты, синхронизирует agent unit и применяет Compose profiles. Неизменённый agent не перезапускается; VPN-сервисы применяются только по фактическому ChangeSet.

## Логи и диагностика

Портал показывает безопасный tail журналов, но первичная диагностика на Debian остаётся через systemd и Compose:

```bash
sudo journalctl -u kvn-portal-agent.service -n 200 --no-pager
sudo journalctl -u kvn-amneziawg.service -n 100 --no-pager
sudo journalctl -u kvn-wireguard.service -n 100 --no-pager
sudo docker compose -f docker-compose.yml logs --tail=200 nginx xray hysteria telemt mtg ocserv portal
```

Если события в UI появляются с задержкой, проверьте `kvn-portal-agent.service`, системное время, нагрузку сервера и доступ agent к Docker CLI. Для аварийной проверки используйте команды выше: UI не должен быть единственным источником логов.

WireGuard после web-apply:

```bash
sudo python3 tools/kvnctl.py wireguard verify
sudo wg show wg0
sudo tcpdump -ni any 'udp port 51821'
```

AmneziaWG после web-apply:

```bash
sudo python3 tools/kvnctl.py amneziawg verify
sudo awg show awg0
sudo tcpdump -ni any 'udp port 51820'
```

Для SNI-проблем сравните `sni-routes list`, пользовательский preview/QR и сгенерированные backend-конфиги через `render`; generated-файлы вручную не правьте.

## Rollback

Храните предыдущий чистый release отдельно. При неуспешном upgrade:

```bash
cd /srv/kvn-vpn
sudo docker compose -f docker-compose.yml down
sudo cp -a /root/kvn-release-previous/. /srv/kvn-vpn/
sudo tar -xzf /root/kvn-state-backup.tar.gz -C /srv/kvn-vpn
sudo tar -xzf /root/kvn-agent-backup.tar.gz -C /
sudo python3 tools/kvnctl.py render --certs
sudo ./amneziawg/sync-host-service.sh
sudo ./wireguard/sync-host-service.sh
sudo ./portal/install-host-agent.sh
sudo ./setup.sh <PUBLIC_IP_OR_ENDPOINT>
```

После rollback повторите проверки systemd, Compose, portal status и сертификатов. Не восстанавливайте `nginx/portal-gateway.conf` отдельно: это generated-файл из `users.json`.

## Prod verification / локальная проверка пакета

На рабочей машине:

```bash
python3 -m compileall -q portal tools
python3 -m unittest discover -s tests -v
python3 tools/docs_check.py
bash -n setup.sh update.sh tools/*.sh amneziawg/*.sh wireguard/*.sh ocserv/*.sh portal/*.sh
./tools/cleanup-project.sh --dry-run
./tools/build-deploy.sh
KVN_BUILD_ID=YYYYMMDD-release1 ./tools/build-release.sh
tar -tzf kvn-vpn-deploy.tar.gz
python3 -m tools.release_archive inspect kvn-vpn-release-linux-amd64.tar.gz
```

Release builder собирает ровно семь Compose images для `linux/amd64`, нормализует image tar и записывает SHA-256/ID в `release-manifest.json`. Builder deploy использует единый canonical allowlist и останавливается при missing source, unexpected deploy file, runtime/secret или malformed portal template.

Если registry/DNS уже недоступны, но все семь финальных runtime-образов заранее загружены, используйте проверяемую offline-сборку:

```bash
KVN_RELEASE_OFFLINE=1 KVN_BUILD_ID=YYYYMMDD-release1 bash tools/build-release.sh
```

Offline-режим не делает `build`/`pull`; `kvn-portal:local` нужно заранее собрать с тем же `KVN_BUILD_ID`. Отсутствие образа, несовпадение build ID, неверная платформа, пустой RepoDigest или ошибка manifest/archive по-прежнему останавливают сборку.
