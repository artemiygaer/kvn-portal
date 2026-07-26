#!/usr/bin/env bash
# Создаёт полный runtime-backup проекта и Docker images в одном .tar.
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${KVN_BACKUP_DIR:-/backup}"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
fail() { printf '[ОШИБКА] %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    fail "запустите от root: sudo ./tools/project-backup.sh"
fi
if [ ! -f "$COMPOSE_FILE" ]; then
    fail "docker-compose.yml не найден: $COMPOSE_FILE"
fi
if ! command -v docker >/dev/null 2>&1; then
    fail "docker не найден; backup контейнеров невозможен"
fi
if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon недоступен; архив не создан"
fi

MAINTENANCE_LOCK="${KVN_MAINTENANCE_LOCK:-/run/lock/kvn-vpn-maintenance.lock}"
MAINTENANCE_LOCK_TIMEOUT="${KVN_MAINTENANCE_LOCK_TIMEOUT:-10}"
command -v flock >/dev/null 2>&1 || fail "flock не найден (нужен пакет util-linux)"
exec 9>"$MAINTENANCE_LOCK"
if ! flock -w "$MAINTENANCE_LOCK_TIMEOUT" 9; then
    fail "другая операция обслуживания уже выполняется: $(head -n 1 "$MAINTENANCE_LOCK" 2>/dev/null || echo owner=unknown)"
fi
printf 'pid=%s action=backup started=%s\n' "$$" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >&9

timestamp="$(date -u '+%Y%m%d-%H%M%S')"
host="$(hostname 2>/dev/null | tr -cd 'A-Za-z0-9_.-' | cut -c1-48)"
[ -n "$host" ] || host="host"
archive_name="kvn-vpn-backup-${timestamp}-${host}.tar"
staging="$(mktemp -d)"
tmp_archive=""
published_archive="$BACKUP_DIR/$archive_name"

cleanup() {
    rm -rf -- "$staging"
    if [ -n "$tmp_archive" ]; then
        rm -f -- "$tmp_archive"
    fi
}
trap cleanup EXIT

if getent group kvn-portal >/dev/null 2>&1; then
    install -d -o root -g kvn-portal -m 0750 "$BACKUP_DIR"
else
    install -d -o root -g root -m 0700 "$BACKUP_DIR"
fi
tmp_archive="$(mktemp "$BACKUP_DIR/.kvn-vpn-backup.XXXXXXXXXX.tar")"

mkdir -p "$staging/metadata"

info "Собираю список Docker images проекта"
mapfile -t images < <(
    docker compose -f "$COMPOSE_FILE" --project-directory "$ROOT_DIR" config --images \
        | sed '/^[[:space:]]*$/d' \
        | sort -u
)
if [ "${#images[@]}" -eq 0 ]; then
    fail "Compose не вернул project images; архив не создан"
fi
for image in "${images[@]}"; do
    docker image inspect "$image" >/dev/null 2>&1 || fail "Docker image не найден локально: $image"
done

info "Сохраняю Docker metadata"
docker compose -f "$COMPOSE_FILE" --project-directory "$ROOT_DIR" config > "$staging/metadata/docker-compose.config.yml"
docker compose -f "$COMPOSE_FILE" --project-directory "$ROOT_DIR" ps -a > "$staging/metadata/docker-compose.ps.txt" || true
docker compose -f "$COMPOSE_FILE" --project-directory "$ROOT_DIR" images > "$staging/metadata/docker-compose.images.txt"
mapfile -t containers < <(
    docker compose -f "$COMPOSE_FILE" --project-directory "$ROOT_DIR" ps -a -q \
        | sed '/^[[:space:]]*$/d' \
        | sort -u
)
if [ "${#containers[@]}" -gt 0 ]; then
    docker inspect "${containers[@]}" > "$staging/metadata/docker-container-inspect.json"
else
    printf '[]\n' > "$staging/metadata/docker-container-inspect.json"
fi
printf '%s\n' "${images[@]}" > "$staging/metadata/docker-images.list"

info "Экспортирую Docker images"
docker save -o "$staging/docker-images.tar" "${images[@]}"

info "Архивирую каталог проекта"
tar -cf "$staging/project.tar" \
    --exclude='./.git' \
    --exclude='./.git/*' \
    --exclude='./.supergoal' \
    --exclude='./.supergoal/*' \
    --exclude='./__pycache__' \
    --exclude='./*/__pycache__' \
    --exclude='./*/*/__pycache__' \
    --exclude='./.pytest_cache' \
    --exclude='./.pytest_cache/*' \
    --exclude='./.mypy_cache' \
    --exclude='./.mypy_cache/*' \
    --exclude='./.ruff_cache' \
    --exclude='./.ruff_cache/*' \
    --exclude='./kvn-vpn-backup-*.tar' \
    --exclude='./kvn-vpn-release-linux-amd64*.tar.gz' \
    --exclude='./kvn-vpn-deploy*.tar.gz' \
    --exclude='./backup' \
    --exclude='./backup/*' \
    -C "$ROOT_DIR" .

cat > "$staging/README_RESTORE.md" <<'EOF'
# KVN VPN backup restore

Архив содержит runtime-данные проекта, клиентские конфиги, сертификаты,
portal/metrics DB и Docker images. Храните файл как секрет.

Восстановление на новом Debian-сервере:

```bash
sudo ./restore-backup.sh /backup/kvn-vpn-backup-YYYYmmdd-HHMMSS-host.tar /srv/kvn-vpn
cd /srv/kvn-vpn
sudo ./setup.sh <NEW_SERVER_IP_OR_DOMAIN>
python3 tools/kvnctl.py render
sudo ./amneziawg/sync-host-service.sh
sudo ./wireguard/sync-host-service.sh
docker compose -f docker-compose.yml up -d --build --remove-orphans
```

После смены IP/домена проверьте `users.json`, SNI, DNS, firewall и cloud firewall.
EOF
cp "$ROOT_DIR/tools/restore-backup.sh" "$staging/restore-backup.sh"
chmod 0755 "$staging/restore-backup.sh"

python3 - "$staging/manifest.json" "$archive_name" "$timestamp" "$ROOT_DIR" "$host" "${images[@]}" <<'PY'
import json
import sys
from pathlib import Path

manifest, archive_name, timestamp, root, host, *images = sys.argv[1:]
Path(manifest).write_text(json.dumps({
    "format": "kvn-vpn-backup-v1",
    "archive": archive_name,
    "created_at_utc": timestamp,
    "project_root": root,
    "host": host,
    "contains_runtime_secrets": True,
    "members": [
        "manifest.json",
        "README_RESTORE.md",
        "restore-backup.sh",
        "project.tar",
        "docker-images.tar",
        "metadata/",
    ],
    "docker_images": images,
}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

tar -cf "$tmp_archive" -C "$staging" \
    manifest.json \
    README_RESTORE.md \
    restore-backup.sh \
    project.tar \
    docker-images.tar \
    metadata

chmod 0600 "$tmp_archive"
if getent group kvn-portal >/dev/null 2>&1; then
    chgrp kvn-portal "$tmp_archive"
    chmod 0640 "$tmp_archive"
fi
mv -f -- "$tmp_archive" "$published_archive"
tmp_archive=""
ok "Backup создан: $published_archive"
ok "Размер: $(du -h "$published_archive" | awk '{print $1}')"
