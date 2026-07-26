# Контейнеры: версии, ограничения и воспроизводимость

Документ описывает фактический профиль `docker-compose.yml`. Он не заменяет проверки полного Linux/amd64 release.

## Проверенные версии

| Компонент | Было | Стало | Причина |
|---|---|---|---|
| Telemt | 3.4.22 | 3.4.24 | ограничение очередей по resident bytes и очистка key schedule; конфиг совместим |
| Hysteria | v2.9.3 | v2.10.0 | исправления транспорта и зависимостей; существующий server config совместим |
| Gunicorn | 23.0.0 | 26.0.0 | актуальный стабильный WSGI server; wheel закреплён SHA-256 |
| Xray | 26.3.27 | без изменения | проверенный Reality baseline; pre-release не принимаются автоматически |
| mtg | 2.2.8 | без изменения | совместимый стабильный backend |
| Flask | 3.1.3 | без изменения | текущая стабильная ветка в offline wheelhouse |
| nginx | 1.31.1-alpine | без изменения | совместим с SNI stream routing и текущими templates |

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

- Portal base закреплён как `python:3.13-alpine@sha256:399babc…`; проверенный manifest `linux/amd64` — `sha256:c25cd44f…`.
- Base ocserv закреплён полным Debian digest в `ocserv/Dockerfile`.
- Upstream runtime-образы используют version tags в Compose, потому что `docker image save/load` должен сохранить эти же tags для `update --no-build --pull never`.
- `tools/build-release.sh` принудительно получает `linux/amd64`, а manifest сохраняет image ID и `RepoDigests`; release без digest любого upstream-образа отклоняется.
- Source-only deploy остаётся fallback и использует version tags. Immutable transport гарантирует полный release, а не online pull source-режима.

Wheelhouse портала задаётся `portal/wheelhouse.lock`, проверяется через `portal/wheels/SHA256SUMS` при Docker build и обновляется командой:

```bash
bash tools/update-portal-wheelhouse.sh
docker build --target test -t kvn-portal:test portal
```
