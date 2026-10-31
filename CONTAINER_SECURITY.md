# Контейнеры: версии, ограничения и воспроизводимость

Документ описывает фактический профиль `docker-compose.yml`. Он не заменяет проверки полного Linux/amd64 release.

## Проверенные версии

| Компонент | Было | Стало | Причина |
|---|---|---|---|
| Telemt | 3.4.24 | 3.5.15 | обновление стабильного backend; проверяется запуск generated-конфигурации |
| Hysteria | v2.10.0 | v2.13.0 | исправления QUIC sniffing и актуальный quic-go |
| Gunicorn | 23.0.0 | 26.2.0 | стабильный WSGI server; wheel закреплён SHA-256 |
| Werkzeug | 3.1.8 | 3.1.9 | исправления и совместимость WebSocket; wheel закреплён SHA-256 |
| Xray | 26.3.27 | 26.10.29 | стабильный release; реальные TCP/xHTTP и HandlerService проверены |
| mtg | 2.2.8 | без изменения | совместимый стабильный backend |
| Flask | 3.1.3 | без изменения | текущая стабильная ветка в offline wheelhouse |
| nginx | 1.31.1-alpine | 1.31.8-alpine | mainline с security fixes; проверен реальный TLS/SNI-router |
| Portal base | Python 3.13 / Alpine | Python 3.13.18 / Alpine 3.24.3 | ветка ABI сохранена; offline wheelhouse проходит Docker-тесты |
| ocserv | Debian stable | 1.3.0-2, GnuTLS 3.8.9-3+deb13u4 | пакет Debian stable/security в новом закреплённом base |

## Источники версий

Источники кандидатов v4.2.0 проверены 31.10.2026:

- [nginx 1.31.8, 21.10.2026](https://nginx.org/news.html), digest образа
  `sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606`.
- [Xray v26.10.29, 29.10.2026](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29),
  GitHub API: prerelease=false; digest
  `sha256:c9443f3ee297f6481bc245269d61720c6f989195ee9b58fa90fdd99f03c21044`.
- [Telemt 3.5.15, 30.10.2026](https://github.com/telemt/telemt/releases/tag/3.5.15),
  GitHub API: prerelease=false; digest
  `sha256:6d4c51be670973040dc3bb73648faeea552e1e11e62904a5a1f28158a6430b4f`.
- Debian base: `debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4`;
  ocserv берётся из [Debian stable/security](https://packages.debian.org/trixie/ocserv),
  а точные пакеты фиксируются внутри собранного образа.
- Уже актуальны: [Hysteria v2.13.0](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0),
  [mtg v2.2.8](https://github.com/9seconds/mtg/releases/tag/v2.2.8),
  Flask 3.1.3, Gunicorn 26.2.0 и Werkzeug 3.1.9 (PyPI), xterm 6.0.0 и
  addon-fit 0.11.0 (npm). Wheel SHA-256 закреплены в `portal/wheels/SHA256SUMS`.

AmneziaWG остаётся host-службой: этот release не обещает обновить загруженный
kernel module на Debian из Windows. Для проверки совместимости tools/module
используйте диагностику AmneziaWG на самом сервере.

Digests получены из registry для Linux/amd64. Полная проверка кандидата
включает запуск generated-конфигураций и обновление через портал; наличие
скачанного образа само по себе не означает готовность релиза.

Offline wheelhouse сверяется с PyPI по точной версии. Даты первой публикации
и первичные metadata URL (проверка 31.10.2026); SHA-256 каждого файла хранится
в `portal/wheels/SHA256SUMS`, полный version lock — в `portal/wheelhouse.lock`:

| Пакет | Версия | Дата UTC / metadata |
|---|---|---|
| blinker | 1.9.0 | [2024-11-08](https://pypi.org/pypi/blinker/1.9.0/json) |
| click | 8.4.2 | [2026-06-24](https://pypi.org/pypi/click/8.4.2/json) |
| colorama | 0.4.6 | [2022-10-25](https://pypi.org/pypi/colorama/0.4.6/json) |
| Flask | 3.1.3 | [2026-02-19](https://pypi.org/pypi/Flask/3.1.3/json) |
| gunicorn | 26.2.0 | [2026-08-24](https://pypi.org/pypi/gunicorn/26.2.0/json) |
| flask-sock | 0.7.0 | [2023-10-02](https://pypi.org/pypi/flask-sock/0.7.0/json) |
| simple-websocket | 1.1.0 | [2024-10-10](https://pypi.org/pypi/simple-websocket/1.1.0/json) |
| wsproto | 1.3.2 | [2025-11-20](https://pypi.org/pypi/wsproto/1.3.2/json) |
| h11 | 0.16.0 | [2025-04-24](https://pypi.org/pypi/h11/0.16.0/json) |
| itsdangerous | 2.2.0 | [2024-04-16](https://pypi.org/pypi/itsdangerous/2.2.0/json) |
| Jinja2 | 3.1.6 | [2025-03-05](https://pypi.org/pypi/Jinja2/3.1.6/json) |
| MarkupSafe | 3.0.3 | [2025-09-27](https://pypi.org/pypi/MarkupSafe/3.0.3/json) |
| packaging | 26.2 | [2026-04-24](https://pypi.org/pypi/packaging/26.2/json) |
| Werkzeug | 3.1.9 | [2026-09-27](https://pypi.org/pypi/Werkzeug/3.1.9/json) |

## Матрица ограничений

| Сервис | User процесса | Capabilities | Root FS / writable paths | PIDs / остановка | Healthcheck |
|---|---|---|---|---|---|
| portal | UID/GID 10001 | `drop ALL` | read-only; `/data`, `/tmp` | 64 / 30s | локальный `/internal/health` |
| portal-gateway | root master → UID 101 worker | `CHOWN`, `SETGID`, `SETUID` | read-only; `/var/run`, `/var/cache/nginx` | 32 / 10s | зависит от healthy portal |
| nginx | root master → UID 101 worker | `CHOWN`, `SETGID`, `SETUID` | read-only; `/var/run`, `/var/cache/nginx` | 64 / 10s | нет надёжного SNI readiness endpoint |
| telemt | upstream user; root не требуется, все caps сняты | `drop ALL` | read-only; `/tmp/telemt` | 64 / 15s | startup проверяет host-agent |
| mtg | upstream user; root не требуется, все caps сняты | `drop ALL` | read-only; writable path не нужен | 64 / 15s | startup проверяет host-agent |
| hysteria | upstream user; privileged caps не нужны | `drop ALL` | read-only; `/tmp` | 64 / 15s | UDP readiness проверяет host-agent |
| ocserv | root supervisor → `nobody` workers | `NET_ADMIN`, `CHOWN`, `SETGID`, `SETUID` | read-only; `/run` для PID/socket/passwd/xtables lock, `/tmp` для snapshot config | 256 / 20s | TUN/NAT/startup проверяет host-agent |
| xray | upstream user; privileged caps не нужны | `drop ALL` | read-only; `/tmp` | 128 / 15s | несколько inbounds, проверяет host-agent |

`NET_ADMIN` оставлен только ocserv для TUN и fail-closed NAT. Nginx получает три capabilities только для подготовки runtime-каталогов и снижения прав worker. У data-plane сервисов нет CPU quota: портал и его gateway ограничены отдельно.

Общий `json-file` budget — `10m × 2` на контейнер: максимум около 160 МиБ для восьми сервисов. Это сохраняет диагностический хвост и не резервирует гигабайты диска на VPS с 1 ГБ RAM. Приложения не должны писать secrets и клиентские конфиги в stdout/stderr.

## Профили нагрузки портала

Portal и gateway вместе ограничены 0.50 CPU, 256 MiB memory и 96 PIDs. В стандартном профиле sampler делает не более 60 тяжёлых samples в час, dashboard — около 60 snapshot и 20 history requests в час. В облегчённом профиле monitoring и background refresh отключены: тяжёлые samples, записи history и автоматические browser requests равны нулю; ручное обновление остаётся доступным.

Повторный `setup.sh` не выполняет apt/Compose install при уже рабочем Compose. `wireguard-tools` устанавливается только если effective service plan включает standard WireGuard. Backup не включает лежащие в корне release/deploy archives, поэтому не дублирует уже сохранённые Docker images.

## Пиннинг и release

- Portal base закреплён как `python:3.13-alpine@sha256:7984cf56ceaddebe4fefeb75d64000b9f45d8b77b11a09b24524da6cdc3af0c8`; ветка Python 3.13 сохранена.
- Base ocserv закреплён полным Debian digest в `ocserv/Dockerfile`.
- Upstream runtime-образы используют фиксированные version tags в Compose. Для перехода с v4.0.1 full archive сохраняет старые транспортные aliases; `transport_aliases` в manifest явно связывает их с новыми версиями. Проверка image ID выполняется до `docker image tag`; затем Compose использует реальные новые теги с `--no-build --pull never`.
- `tools/build-release.sh` принудительно получает `linux/amd64`, а manifest сохраняет image ID и `RepoDigests`; release без digest любого upstream-образа отклоняется.
- Source-only deploy остаётся fallback и использует version tags. Immutable transport гарантирует полный release, а не online pull source-режима.

Wheelhouse портала задаётся `portal/wheelhouse.lock`, проверяется через `portal/wheels/SHA256SUMS` при Docker build и обновляется командой:

```bash
bash tools/update-portal-wheelhouse.sh
docker build --target test -t kvn-portal:test portal
```
