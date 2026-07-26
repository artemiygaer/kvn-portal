#!/usr/bin/env bash
# Восстанавливает проект из архива, созданного tools/project-backup.sh.
set -euo pipefail
umask 077

usage() {
    cat <<'EOF'
Использование:
  sudo ./tools/restore-backup.sh /backup/kvn-vpn-backup-YYYYmmdd-HHMMSS-host.tar /srv/kvn-vpn

Архив содержит runtime-секреты. Восстанавливайте только на доверенном Debian-сервере.
EOF
}

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
fail() { printf '[ОШИБКА] %s\n' "$*" >&2; exit 1; }

validate_tar_archive() {
    local archive_path="$1"
    local archive_role="$2"
    python3 - "$archive_path" "$archive_role" <<'PY'
import json
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, archive_role = sys.argv[1:]
max_members = 200_000
max_member_size = 64 * 1024**3
max_total_size = 256 * 1024**3


def safe_name(value: str) -> str:
    if not value or "\\" in value or any(ord(char) < 32 for char in value):
        raise ValueError(f"небезопасный путь: {value!r}")
    normalized = value
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        return ""
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"небезопасный путь: {value!r}")
    return path.as_posix()


try:
    with tarfile.open(archive_path, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > max_members:
            raise ValueError("слишком много файлов")
        names = {}
        total_size = 0
        for member in members:
            name = safe_name(member.name)
            if name in names and name:
                raise ValueError(f"повторяющийся путь: {name}")
            if not (member.isfile() or member.isdir()):
                raise ValueError(
                    f"ссылки и специальные файлы запрещены: {member.name}"
                )
            if member.size < 0 or member.size > max_member_size:
                raise ValueError(f"слишком большой файл: {member.name}")
            total_size += member.size
            if total_size > max_total_size:
                raise ValueError("суммарный размер архива слишком велик")
            if name:
                names[name] = member
        if archive_role == "outer":
            missing = {"manifest.json", "project.tar"} - names.keys()
            if missing:
                raise ValueError(
                    "в backup отсутствуют обязательные файлы: "
                    + ", ".join(sorted(missing))
                )
            manifest_member = names["manifest.json"]
            if not manifest_member.isfile() or manifest_member.size > 1024 * 1024:
                raise ValueError("manifest.json имеет неверный тип или размер")
            source = archive.extractfile(manifest_member)
            if source is None:
                raise ValueError("manifest.json не читается")
            manifest = json.loads(source.read().decode("utf-8"))
            if (
                not isinstance(manifest, dict)
                or manifest.get("format") != "kvn-vpn-backup-v1"
                or manifest.get("contains_runtime_secrets") is not True
            ):
                raise ValueError("manifest.json не соответствует backup v1")
        elif archive_role != "project":
            raise ValueError("неизвестная роль архива")
except (OSError, tarfile.TarError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
    raise SystemExit(f"[ОШИБКА] Backup archive отклонён: {exc}") from None
PY
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi
if [ "$#" -ne 2 ]; then
    usage
    exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
    fail "запустите от root"
fi

archive="$1"
target="$2"

case "$archive" in
    /*) ;;
    *) fail "путь к backup archive должен быть абсолютным" ;;
esac
case "$target" in
    /*) ;;
    *) fail "target directory должен быть абсолютным" ;;
esac
if [ ! -f "$archive" ]; then
    fail "backup archive не найден: $archive"
fi
if [ -L "$archive" ]; then
    fail "backup archive не должен быть symlink"
fi
if [ -L "$target" ]; then
    fail "target directory не должен быть symlink"
fi
archive="$(readlink -f -- "$archive")"
target="$(readlink -m -- "$target")"
case "$target" in
    /|/boot|/dev|/etc|/home|/proc|/root|/run|/sys|/tmp|/usr|/var)
        fail "target directory слишком широкий: $target"
        ;;
esac
case "$(basename "$archive")" in
    kvn-vpn-backup-*.tar) ;;
    *) fail "разрешены только архивы kvn-vpn-backup-*.tar" ;;
esac
if [ -e "$target" ] && [ -n "$(find "$target" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    fail "target directory существует и не пуст: $target"
fi
command -v python3 >/dev/null 2>&1 || fail "python3 не найден; безопасная проверка backup невозможна"
validate_tar_archive "$archive" outer

MAINTENANCE_LOCK="${KVN_MAINTENANCE_LOCK:-/run/lock/kvn-vpn-maintenance.lock}"
MAINTENANCE_LOCK_TIMEOUT="${KVN_MAINTENANCE_LOCK_TIMEOUT:-10}"
command -v flock >/dev/null 2>&1 || fail "flock не найден (нужен пакет util-linux)"
exec 9>"$MAINTENANCE_LOCK"
if ! flock -w "$MAINTENANCE_LOCK_TIMEOUT" 9; then
    fail "другая операция обслуживания уже выполняется: $(head -n 1 "$MAINTENANCE_LOCK" 2>/dev/null || echo owner=unknown)"
fi
printf 'pid=%s action=restore started=%s\n' "$$" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >&9

staging="$(mktemp -d)"
cleanup() {
    rm -rf "$staging"
}
trap cleanup EXIT

info "Извлекаю backup во временный каталог"
tar -xf "$archive" -C "$staging" --no-same-owner --no-same-permissions
[ -f "$staging/project.tar" ] || fail "в backup нет project.tar"
[ -f "$staging/manifest.json" ] || fail "в backup нет manifest.json"
validate_tar_archive "$staging/project.tar" project

install -d -m 0750 "$target"
info "Восстанавливаю проект в $target"
tar -xf "$staging/project.tar" -C "$target" --no-same-owner --no-same-permissions

if [ -f "$staging/docker-images.tar" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        info "Загружаю Docker images"
        docker load -i "$staging/docker-images.tar"
    else
        info "Docker недоступен; images не загружены. Выполните docker load позже."
    fi
fi

ok "Проект восстановлен в $target"
cat <<EOF

Следующие шаги:
  cd "$target"
  sudo ./setup.sh <NEW_SERVER_IP_OR_DOMAIN>
  python3 tools/kvnctl.py render
  sudo ./amneziawg/sync-host-service.sh
  sudo ./wireguard/sync-host-service.sh
  docker compose -f docker-compose.yml up -d --build --remove-orphans

Проверьте users.json, DNS, SNI, firewall и cloud firewall перед выдачей ссылок пользователям.
EOF
