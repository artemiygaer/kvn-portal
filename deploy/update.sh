#!/usr/bin/env bash
# Обновляет проект из source deploy или полного офлайн-release без повторного setup.
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="${KVN_UPDATE_ROOT:-$SCRIPT_ROOT}"
UPDATE_MODE="${KVN_UPDATE_MODE:-full}"
if [ "${1:-}" = "--bootstrap-only" ]; then
    UPDATE_MODE="bootstrap-only"
    shift
fi
case "$UPDATE_MODE" in
    full|bootstrap-only) ;;
    *)
        echo "[ОШИБКА] Неизвестный режим обновления: $UPDATE_MODE" >&2
        exit 1
        ;;
esac

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ]; then
    if [ -f "$ROOT_DIR/kvn-vpn-release-linux-amd64.tar.gz" ]; then
        ARCHIVE="$ROOT_DIR/kvn-vpn-release-linux-amd64.tar.gz"
    elif [ -f "$ROOT_DIR/kvn-vpn-deploy.tar.gz" ]; then
        ARCHIVE="$ROOT_DIR/kvn-vpn-deploy.tar.gz"
    else
        ARCHIVE="$(ls -t "$ROOT_DIR"/kvn-vpn-release-linux-amd64*.tar.gz "$ROOT_DIR"/kvn-vpn-deploy*.tar.gz 2>/dev/null | head -n1 || true)"
    fi
fi
if [ ! -f "$ARCHIVE" ]; then
    echo "[ОШИБКА] Архив не найден: $ARCHIVE" >&2
    echo "Положите full release или source deploy в корень проекта либо передайте путь аргументом." >&2
    exit 1
fi
ARCHIVE="$(readlink -f "$ARCHIVE")"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ОШИБКА] python3 не найден. Сначала выполните setup.sh." >&2
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] Запустите от root: sudo ./update.sh [архив]" >&2
    exit 1
fi
if [ "$UPDATE_MODE" = "full" ] && ! command -v docker >/dev/null 2>&1; then
    echo "[ОШИБКА] docker не найден. Сначала выполните setup.sh." >&2
    exit 1
fi

MAINTENANCE_LOCK="${KVN_MAINTENANCE_LOCK:-/run/lock/kvn-vpn-maintenance.lock}"
MAINTENANCE_LOCK_TIMEOUT="${KVN_MAINTENANCE_LOCK_TIMEOUT:-10}"
if [ "${KVN_MAINTENANCE_LOCKED:-0}" != "1" ]; then
    if ! command -v flock >/dev/null 2>&1; then
        echo "[ОШИБКА] flock не найден (нужен пакет util-linux)." >&2
        exit 1
    fi
    exec 9>"$MAINTENANCE_LOCK"
    if ! flock -w "$MAINTENANCE_LOCK_TIMEOUT" 9; then
        echo "[ОШИБКА] Другая операция обслуживания уже выполняется: $(head -n 1 "$MAINTENANCE_LOCK" 2>/dev/null || echo owner=unknown)" >&2
        exit 1
    fi
    printf 'pid=%s action=update started=%s\n' "$$" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >&9
    export KVN_MAINTENANCE_LOCKED=1
fi
cd "$ROOT_DIR"
if [ "${KVN_UPDATE_WORKER:-0}" != "1" ]; then
    WORKER_DIR="$(mktemp -d)"
    trap 'rm -rf -- "$WORKER_DIR"' EXIT
    UPDATE_OFFLINE=0
    case "$(basename "$ARCHIVE")" in
        kvn-vpn-release-linux-amd64*.tar.gz)
            if [ ! -f "$ROOT_DIR/tools/release_archive.py" ]; then
                echo "[ОШИБКА] Для full release сначала выполните bootstrap-only из source deploy." >&2
                exit 1
            fi
            python3 -m tools.release_archive extract "$ARCHIVE" "$WORKER_DIR/release" >/dev/null
            if [ "$UPDATE_MODE" = "full" ]; then
                echo "[INFO] Загружаю проверенные Docker images до изменения исходников..."
                docker image load -i "$WORKER_DIR/release/kvn-vpn-images-linux-amd64.tar"
                python3 -m tools.release_archive verify-loaded "$WORKER_DIR/release/release-manifest.json" >/dev/null
                UPDATE_OFFLINE=1
            fi
            ARCHIVE="$WORKER_DIR/release/kvn-vpn-deploy.tar.gz"
            ;;
    esac
    python3 - "$ARCHIVE" "$WORKER_DIR" <<'PY'
import json
import sys
import tarfile
from pathlib import Path

archive_path = Path(sys.argv[1])
target = Path(sys.argv[2])
required = {
    "deploy/update.sh": target / "update.sh",
    "deploy/tools/deploy_archive.py": target / "tools/deploy_archive.py",
    "deploy/tools/canonical-files.txt": target / "tools/canonical-files.txt",
}
try:
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        missing = [name.removeprefix("deploy/") for name in required if name not in members]
        if missing:
            raise SystemExit("[ОШИБКА] В архиве не хватает bootstrap-файлов: " + ", ".join(missing))
        for name, destination in required.items():
            member = members[name]
            if not member.isreg():
                raise SystemExit(f"[ОШИБКА] Bootstrap-файл не является обычным файлом: {name}")
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit(f"[ОШИБКА] Не удалось прочитать bootstrap-файл: {name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read())
except (OSError, tarfile.TarError) as exc:
    raise SystemExit(f"[ОШИБКА] Не удалось извлечь bootstrap из архива: {exc}") from exc
PY
    chmod 700 "$WORKER_DIR/update.sh"
    KVN_UPDATE_WORKER=1 KVN_UPDATE_ROOT="$ROOT_DIR" KVN_UPDATE_WORKER_DIR="$WORKER_DIR" \
        KVN_UPDATE_INSPECTOR="$WORKER_DIR/tools/deploy_archive.py" KVN_UPDATE_MODE="$UPDATE_MODE" \
        KVN_UPDATE_OFFLINE="$UPDATE_OFFLINE" exec /bin/bash "$WORKER_DIR/update.sh" "$ARCHIVE"
fi
ROOT_DIR="${KVN_UPDATE_ROOT:-$ROOT_DIR}"
cd "$ROOT_DIR"

TMP_DIR=""
STAGE_DIR=""
SNAPSHOT_DIR=""
SOURCES_INSTALLED=0
COMPOSE_STARTED=0

restore_source_snapshot() {
    if [ -z "$SNAPSHOT_DIR" ] || [ ! -f "$SNAPSHOT_DIR/sources-present" ]; then
        return 0
    fi
    echo "[WARN] Обновление остановлено до Compose apply; восстанавливаю исходные файлы из snapshot" >&2
    while IFS= read -r relative || [ -n "$relative" ]; do
        [ -n "$relative" ] || continue
        if grep -Fqx "$relative" "$SNAPSHOT_DIR/sources-present"; then
            mkdir -p "$(dirname "$relative")" || true
            cp -a "$SNAPSHOT_DIR/sources/$relative" "$relative" || true
        else
            rm -f "$relative" || true
        fi
    done < "$SNAPSHOT_DIR/canonical-files"
}

cleanup() {
    status=$?
    if [ "$status" -ne 0 ] && [ "$SOURCES_INSTALLED" = "1" ] && [ "$COMPOSE_STARTED" = "0" ]; then
        restore_source_snapshot
    fi
    if [ -n "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    if [ -n "${KVN_UPDATE_WORKER_DIR:-}" ]; then
        rm -rf "$KVN_UPDATE_WORKER_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT

if [ "$UPDATE_MODE" = "full" ] && ! command -v docker >/dev/null 2>&1; then
    echo "[ОШИБКА] docker не найден. Сначала выполните setup.sh." >&2
    exit 1
fi

INSPECTOR="${KVN_UPDATE_INSPECTOR:-$ROOT_DIR/tools/deploy_archive.py}"
if [ ! -f "$INSPECTOR" ]; then
    echo "[ОШИБКА] Не найден валидатор архива: $INSPECTOR" >&2
    exit 1
fi
if ! python3 "$INSPECTOR" "$ARCHIVE"; then
    echo "[ОШИБКА] Архив не прошёл проверку до распаковки." >&2
    exit 1
fi

TMP_DIR="$(mktemp -d)"
tar --extract --gzip --file "$ARCHIVE" --directory "$TMP_DIR" --no-same-owner --no-same-permissions
SRC="$TMP_DIR/deploy"
if [ ! -d "$SRC" ]; then
    echo "[ОШИБКА] в архиве нет каталога deploy/" >&2
    exit 1
fi
MANIFEST_FILE=".kvn-canonical-files"

SCHEMA_FILE="tools/canonical-files.txt"
if [ ! -f "$SRC/$MANIFEST_FILE" ]; then
    echo "[ОШИБКА] В архиве отсутствует manifest: $MANIFEST_FILE" >&2
    exit 1
fi
if [ ! -f "$SRC/$SCHEMA_FILE" ]; then
    echo "[ОШИБКА] В архиве отсутствует канонический список: $SCHEMA_FILE" >&2
    exit 1
fi
if ! cmp -s "$SRC/$MANIFEST_FILE" "$SRC/$SCHEMA_FILE"; then
    echo "[ОШИБКА] Manifest не совпадает с $SCHEMA_FILE; пересоберите архив: bash tools/build-deploy.sh" >&2
    exit 1
fi
mapfile -t canonical < "$SRC/$SCHEMA_FILE"
if [ "${#canonical[@]}" -eq 0 ]; then
    echo "[ОШИБКА] Канонический список архива пуст: $SCHEMA_FILE" >&2
    exit 1
fi
echo "[INFO] Список обновляемых файлов проверен по $SCHEMA_FILE"

STAGE_DIR="$TMP_DIR/stage"
for relative in "${canonical[@]}"; do
    if [ ! -f "$SRC/$relative" ]; then
        echo "[ОШИБКА] в архиве отсутствует обязательный файл: $relative" >&2
        exit 1
    fi
    mkdir -p "$STAGE_DIR/$(dirname "$relative")"
    cp -f "$SRC/$relative" "$STAGE_DIR/$relative"
done

while IFS= read -r -d '' script; do
    bash -n "$script"
done < <(find "$STAGE_DIR" -type f -name '*.sh' -print0)
STAGE_DIR="$STAGE_DIR" python3 - <<'PY'
import ast
import os
from pathlib import Path

for source in Path(os.environ["STAGE_DIR"]).rglob("*.py"):
    ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
PY

BACKUP_DIR="$ROOT_DIR/.update-backups/$(date '+%Y%m%d-%H%M%S')"
SNAPSHOT_DIR="$BACKUP_DIR"
install -d -m 700 "$SNAPSHOT_DIR/sources"
printf '%s\n' "${canonical[@]}" > "$SNAPSHOT_DIR/canonical-files"
: > "$SNAPSHOT_DIR/sources-present"
for item in users.json .env; do
    if [ -f "$item" ]; then
        cp -a "$item" "$SNAPSHOT_DIR/$item"
    fi
done
for relative in "${canonical[@]}"; do
    if [ -f "$relative" ]; then
        printf '%s\n' "$relative" >> "$SNAPSHOT_DIR/sources-present"
        mkdir -p "$SNAPSHOT_DIR/sources/$(dirname "$relative")"
        cp -a "$relative" "$SNAPSHOT_DIR/sources/$relative"
    fi
done
chmod -R go-rwx "$SNAPSHOT_DIR"
echo "[INFO] Создан root-only snapshot исходников и runtime-настроек: $SNAPSHOT_DIR"

SOURCES_INSTALLED=1
for relative in "${canonical[@]}"; do
    mkdir -p "$(dirname "$relative")"
    cp -f "$STAGE_DIR/$relative" "$relative"
done

if [ ! -f users.json ]; then
    cp "$SRC/users.json" users.json
    chmod 0600 users.json
    echo "[WARN] users.json отсутствовал; создан пустой шаблон из архива"
fi

chmod 755 setup.sh update.sh tools/*.sh amneziawg/*.sh wireguard/*.sh ocserv/*.sh portal/*.sh 2>/dev/null || true

EFFECTIVE_DOCKER_SERVICES=()
DISABLED_DOCKER_SERVICES=()
EFFECTIVE_HOST_SERVICES=()
DISABLED_HOST_SERVICES=()
EFFECTIVE_COMPOSE_PROFILES=()
PORTAL_ENABLED=0
while IFS=$'\t' read -r key value; do
    case "$key" in
        docker-enabled) IFS=',' read -r -a EFFECTIVE_DOCKER_SERVICES <<< "$value" ;;
        docker-disabled) IFS=',' read -r -a DISABLED_DOCKER_SERVICES <<< "$value" ;;
        host-enabled) IFS=',' read -r -a EFFECTIVE_HOST_SERVICES <<< "$value" ;;
        host-disabled) IFS=',' read -r -a DISABLED_HOST_SERVICES <<< "$value" ;;
        compose-profiles) IFS=',' read -r -a EFFECTIVE_COMPOSE_PROFILES <<< "$value" ;;
        portal-agent) PORTAL_ENABLED="$value" ;;
    esac
done < <(python3 tools/kvnctl.py service-plan --format lines)

service_enabled_in() {
    local wanted="$1"
    shift
    local service
    for service in "$@"; do
        [ "$service" = "$wanted" ] && return 0
    done
    return 1
}

if [ "$UPDATE_MODE" = "bootstrap-only" ]; then
    if [ "$PORTAL_ENABLED" = "1" ]; then
        bash portal/install-host-agent.sh
    elif systemctl list-unit-files kvn-portal-agent.service >/dev/null 2>&1; then
        systemctl disable --now kvn-portal-agent.service
    fi
    echo "[OK] Bootstrap-only обновление завершено: updater и host-agent синхронизированы"
    echo "Следующий шаг для полного применения: sudo ./update.sh $ARCHIVE"
    exit 0
fi
PORTAL_PORT="$(python3 - <<'PY'
import json
state=json.load(open("users.json", encoding="utf-8"))
print(state.get("portal", {}).get("port", 8443))
PY
)"
COMPOSE_PROFILE_LIST="$(IFS=','; echo "${EFFECTIVE_COMPOSE_PROFILES[*]}")"
PORTAL_GID="$(getent group kvn-portal | cut -d: -f3 || true)"
python3 - "$PORTAL_GID" "$PORTAL_PORT" "$COMPOSE_PROFILE_LIST" <<'PY'
import json
import sys
from pathlib import Path
from tools.kvnlib import atomic_write_text

gid, port, profiles = sys.argv[1:]
state = json.loads(Path("users.json").read_text(encoding="utf-8"))
mtg = state.get("mtg", {}) if isinstance(state.get("mtg"), dict) else {}
route = state.get("sni_routes", {}).get("mtg", {})
alias = route.get("default", "mtg-decoy.invalid") if mtg.get("camouflage_origin", "external") == "local-site" else "mtg-decoy.invalid"
lines = []
if gid:
    lines.append(f"KVN_PORTAL_GID={gid}")
lines.extend((f"KVN_PORTAL_PORT={port}", f"COMPOSE_PROFILES={profiles}", f"KVN_MTG_CAMOUFLAGE_HOST={alias}"))
atomic_write_text(Path(".env"), "\n".join(lines) + "\n", mode=0o600)
PY

echo "[INFO] Перегенерирую конфиги из текущего users.json..."
python3 tools/kvnctl.py render

if service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}" \
    && { ! command -v wg >/dev/null 2>&1 || ! command -v wg-quick >/dev/null 2>&1; }; then
    echo "[INFO] Устанавливаю wireguard-tools..."
    apt-get update -qq
    apt-get install -y -qq wireguard-tools
fi

if [ "$PORTAL_ENABLED" = "1" ]; then
    bash portal/install-host-agent.sh
elif systemctl list-unit-files kvn-portal-agent.service >/dev/null 2>&1; then
    systemctl disable --now kvn-portal-agent.service
fi

echo "[INFO] Синхронизирую host-службы..."
if service_enabled_in amneziawg "${EFFECTIVE_HOST_SERVICES[@]}"; then
    if systemctl list-unit-files kvn-amneziawg.service >/dev/null 2>&1; then
        bash amneziawg/sync-host-service.sh
    else
        bash amneziawg/install-host-service.sh
    fi
elif systemctl list-unit-files kvn-amneziawg.service >/dev/null 2>&1; then
    systemctl disable --now kvn-amneziawg.service
fi
if service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}"; then
    if systemctl list-unit-files kvn-wireguard.service >/dev/null 2>&1; then
        bash wireguard/sync-host-service.sh
    else
        bash wireguard/install-host-service.sh
    fi
elif systemctl list-unit-files kvn-wireguard.service >/dev/null 2>&1; then
    systemctl disable --now kvn-wireguard.service
fi

compose_cmd() {
    local profile_args=()
    local profile
    for profile in "${EFFECTIVE_COMPOSE_PROFILES[@]}"; do
        [ -n "$profile" ] && profile_args+=(--profile "$profile")
    done
    docker compose -f docker-compose.yml "${profile_args[@]}" "$@"
}

echo "[INFO] Обновляю Docker-сервисы..."
COMPOSE_STARTED=1
if [ "${#DISABLED_DOCKER_SERVICES[@]}" -gt 0 ]; then
    docker compose -f docker-compose.yml --profile portal --profile portal-custom \
        stop "${DISABLED_DOCKER_SERVICES[@]}"
fi
if [ "${#EFFECTIVE_DOCKER_SERVICES[@]}" -gt 0 ]; then
    if [ "${KVN_UPDATE_OFFLINE:-0}" = "1" ]; then
        compose_cmd up -d --no-build --pull never --remove-orphans "${EFFECTIVE_DOCKER_SERVICES[@]}"
    else
        echo "[WARN] Source-only архив: разрешены online build/pull. Для слабого сервера используйте full release."
        compose_cmd up -d --build --remove-orphans "${EFFECTIVE_DOCKER_SERVICES[@]}"
    fi
fi

running_services="$(compose_cmd ps --status running --services 2>/dev/null || true)"
for service in "${EFFECTIVE_DOCKER_SERVICES[@]}"; do
    if ! grep -Fxq "$service" <<< "$running_services"; then
        echo "[ОШИБКА] Docker-сервис не перешёл в running: $service" >&2
        compose_cmd logs --tail=80 "$service" || true
        exit 1
    fi
done

service_enabled_in amneziawg "${EFFECTIVE_HOST_SERVICES[@]}" && python3 tools/kvnctl.py amneziawg verify
service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}" && python3 tools/kvnctl.py wireguard verify
if [ "$PORTAL_ENABLED" = "1" ]; then
    systemctl is-active --quiet kvn-portal-agent.service
fi

echo "[OK] Обновление завершено"
echo "Проверка: docker compose -f docker-compose.yml ps"
