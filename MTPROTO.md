# MTProto: Telemt и MTG

Стек использует два независимых backend: Telemt 3.4.24 как основной и MTG 2.2.8 как резервный. Оба принимаются nginx по публичному `443/tcp` через SNI; прямые резервные порты — `2446/tcp` и `2447/tcp`.

Telemt хранит отдельный 16-байтный secret каждого пользователя, поддерживает FakeTLS (`ee`) на публичном SNI и secure/padded (`dd`) на прямом порту. MTG технически имеет один shared secret на весь инстанс: по нему нельзя честно атрибутировать трафик конкретному пользователю. Secrets не печатаются в статусе, диагностике или startup-ссылках Telemt.

## Camouflage origin

- `external` — прежнее поведение: неизвестный/проверочный TLS-трафик передаётся на внешний `<SNI>:443`;
- `local-site` — режим для собственного домена: Telemt идёт на `nginx:8443`, а MTG резолвит свой SNI через Docker DNS alias того же nginx и тоже идёт на `8443`.

Схема `local-site`:

```text
клиент → public :443 → nginx SNI-router → telemt:3129 / mtg:3128
                                              │
                                              └→ internal nginx:8443 → decoy site
```

Публичный SNI не добавляется в web-route сайта: он остаётся маршрутом MTProto. Сертификат `site-certs/server.crt` при этом обязан содержать этот SNI в SAN. Так исключается петля `backend → public :443 → backend`.

## Профиль мобильных сетей

Рендер Telemt включает middle-proxy fallback/fast mode, keepalive каждые `8 ± 2` секунды со случайным payload, reconnect backoff `500 ms…30 s`, client keepalive `15 s`, мягкий/hard relay idle `120/360 s` и replay window `120 s`. MTG использует IPv4 preference, TCP/handshake timeout `5/10 s`, idle `5m`, TCP keepalive `15 s × 9` и anti-replay. Эти значения ограничивают зависания и быстрее восстанавливают соединение при смене LTE/5G/Wi‑Fi, но не заменяют доступный IP/TCP маршрут.

Не увеличивайте keepalive и concurrency наугад: это повышает фоновые пакеты/CPU и может сделать профиль заметнее. Настройки генерируются из `users.json`; `telemt/config.toml` и `mtg/config.toml` вручную не править.

## Настройка собственного SNI

1. Создайте отдельные A/AAAA-записи, например `telemt.example.com` и `mtg.example.com`, на адрес сервера.
2. Добавьте оба имени в SAN site-сертификата вместе с текущим главным доменом.
3. Назначьте разные SNI сервисам.
4. Проверьте диагностику и включите `local-site`.

```bash
sudo python3 tools/kvnctl.py letsencrypt issue \
  --domain site.example.com --domain telemt.example.com --domain mtg.example.com --restart
sudo python3 tools/kvnctl.py sni-routes set-default telemt telemt.example.com --restart
sudo python3 tools/kvnctl.py sni-routes set-default mtg mtg.example.com --restart
sudo python3 tools/kvnctl.py mtproto diagnose telemt
sudo python3 tools/kvnctl.py mtproto diagnose mtg
sudo python3 tools/kvnctl.py mtproto set-origin telemt local-site --restart
sudo python3 tools/kvnctl.py mtproto set-origin mtg local-site --restart
```

Те же настройки находятся в портале: «Настройки → MTProto». DNS-сбой показывается как bounded-предупреждение и не зависает; конфликт маршрута, неверный backend или отсутствующий SAN блокируют небезопасное переключение. `mtg doctor` и ответ внутреннего decoy выполняются только при доступном Docker, с таймаутом и без публикации вывода.

Проверка после применения:

```bash
sudo python3 tools/kvnctl.py mtproto status
sudo python3 tools/kvnctl.py mtproto diagnose telemt
sudo python3 tools/kvnctl.py mtproto diagnose mtg
sudo docker compose -f docker-compose.yml logs --tail=100 telemt mtg nginx
sudo ss -ltnp | grep -E ':(443|2446|2447)\b'
```

Если direct `2446/2447` работает, а public `443/tcp` нет, проверяйте SNI route/nginx и cloud firewall. Если оба пути недоступны, сначала проверяйте IP/TCP доступность у оператора; смена FakeTLS-домена не исправит заблокированный IP.

## Ограничения

Собственный SNI делает DNS, сертификат и decoy согласованными с IP сервера, но не гарантирует обход ТСПУ. Полную блокировку IP, TCP или TLS средствами FakeTLS устранить невозможно. После настройки проверяйте подключение отдельно у каждого нужного мобильного оператора.
