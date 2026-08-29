#!/usr/bin/env bash
# Одноразовый безопасный мост для обновления KVN v3.1.3 до v4.
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Использование:
  sudo bash bootstrap-v4.sh --sha256 <SHA256> <АРХИВ> [КОРЕНЬ_ПРОЕКТА]

Пример:
  sudo bash bootstrap-v4.sh --sha256 <SHA256_ИЗ_SHA256SUMS> \
    ./kvn-vpn-release-linux-amd64.tar.gz /root/deploy
EOF
    exit 2
}

[ "${1:-}" = "--sha256" ] && [ "$#" -ge 3 ] || usage
EXPECTED_SHA256="$2"
shift 2
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
if [[ ! "$EXPECTED_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "[ОШИБКА] Ожидаемый SHA-256 должен содержать 64 hex-символа." >&2
    exit 2
fi
EXPECTED_SHA256="${EXPECTED_SHA256,,}"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] Запустите мост от root через sudo." >&2
    exit 1
fi
for command in python3 sha256sum readlink; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "[ОШИБКА] Не найдена обязательная команда: $command" >&2
        exit 1
    }
done

ARCHIVE="$(readlink -f "$1")"
PROJECT_ROOT="$(readlink -f "${2:-$PWD}")"
[ -f "$ARCHIVE" ] || { echo "[ОШИБКА] Архив не найден: $ARCHIVE" >&2; exit 1; }
[ -d "$PROJECT_ROOT" ] && [ -f "$PROJECT_ROOT/update.sh" ] || {
    echo "[ОШИБКА] Не найден установленный проект: $PROJECT_ROOT" >&2
    exit 1
}

ACTUAL_SHA256="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "[ОШИБКА] SHA-256 архива не совпадает." >&2
    echo "Ожидался: $EXPECTED_SHA256" >&2
    echo "Получен:  $ACTUAL_SHA256" >&2
    exit 1
fi
echo "[OK] SHA-256 архива подтверждён: $ACTUAL_SHA256"

case "$(basename "$ARCHIVE")" in
    kvn-vpn-release-linux-amd64*.tar.gz) KIND="release" ;;
    kvn-vpn-deploy*.tar.gz) KIND="deploy" ;;
    *) echo "[ОШИБКА] Допустим только штатный deploy или full release KVN." >&2; exit 1 ;;
esac

UPDATE_TMP_ROOT="$PROJECT_ROOT/.update-tmp"
[ ! -L "$UPDATE_TMP_ROOT" ] || {
    echo "[ОШИБКА] Каталог временных файлов не должен быть символической ссылкой." >&2
    exit 1
}
install -d -m 700 "$UPDATE_TMP_ROOT"
WORK="$(mktemp -d "$UPDATE_TMP_ROOT/v4-bootstrap.XXXXXXXXXX")"
trap 'rm -rf -- "$WORK"' EXIT
SOURCE_ARCHIVE="$ARCHIVE"
[ "$KIND" = "deploy" ] || SOURCE_ARCHIVE="$WORK/kvn-vpn-deploy.tar.gz"
BOOTSTRAP="$WORK/bootstrap"

python3 - "$ARCHIVE" "$SOURCE_ARCHIVE" "$BOOTSTRAP" "$KIND" <<'PY'
import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

outer, source_archive, target = map(Path, sys.argv[1:4])
kind = sys.argv[4]

def safe_members(archive):
    members = archive.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("небезопасный путь в архиве")
        if not member.isreg():
            raise ValueError("в bootstrap допустимы только обычные файлы")
    return members

try:
    if kind == "release":
        required = ["release-manifest.json", "kvn-vpn-deploy.tar.gz", "kvn-vpn-images-linux-amd64.tar"]
        with tarfile.open(outer, "r:gz") as archive:
            members = safe_members(archive)
            names = [member.name for member in members]
            if names != required or len(set(names)) != len(names):
                raise ValueError("неверный состав full release")
            by_name = dict(zip(names, members, strict=True))
            manifest_handle = archive.extractfile(by_name[required[0]])
            if manifest_handle is None or by_name[required[0]].size > 1024 * 1024:
                raise ValueError("manifest full release не читается")
            manifest = json.loads(manifest_handle.read().decode("utf-8"))
            record = manifest.get("source")
            source_member = by_name[required[1]]
            if manifest.get("format") != 1 or manifest.get("platform") != "linux/amd64":
                raise ValueError("full release предназначен не для linux/amd64")
            if not isinstance(record, dict) or record.get("name") != required[1] or record.get("size") != source_member.size:
                raise ValueError("неверная source-секция full release")
            source_handle = archive.extractfile(source_member)
            if source_handle is None:
                raise ValueError("вложенный deploy не читается")
            digest = hashlib.sha256()
            with source_archive.open("xb") as output:
                while chunk := source_handle.read(1024 * 1024):
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != record.get("sha256"):
                source_archive.unlink(missing_ok=True)
                raise ValueError("SHA-256 вложенного deploy не совпадает")

    required_bootstrap = {
        "deploy/update.sh": target / "update.sh",
        "deploy/tools/deploy_archive.py": target / "tools/deploy_archive.py",
        "deploy/tools/canonical-files.txt": target / "tools/canonical-files.txt",
    }
    with tarfile.open(source_archive, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        missing = [name for name in required_bootstrap if name not in members]
        if missing:
            raise ValueError("не хватает bootstrap-файлов: " + ", ".join(missing))
        for name, destination in required_bootstrap.items():
            member = members[name]
            if not member.isreg() or not 1 <= member.size <= 2 * 1024 * 1024:
                raise ValueError(f"неверный bootstrap-файл: {name}")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"bootstrap-файл не читается: {name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
    raise SystemExit(f"[ОШИБКА] Архив отклонён bootstrap-мостом: {exc}") from exc
PY

chmod 700 "$BOOTSTRAP/update.sh" "$BOOTSTRAP/tools/deploy_archive.py"
echo "[INFO] Устанавливаю updater и host-agent v4 без перезапуска VPN-контейнеров..."
KVN_UPDATE_WORKER=1 KVN_UPDATE_ROOT="$PROJECT_ROOT" \
    KVN_UPDATE_INSPECTOR="$BOOTSTRAP/tools/deploy_archive.py" KVN_UPDATE_MODE=bootstrap-only \
    /bin/bash "$BOOTSTRAP/update.sh" "$SOURCE_ARCHIVE"

echo "[INFO] Bootstrap завершён. Запускаю полное обновление штатным updater v4..."
trap - EXIT
rm -rf -- "$WORK"
exec env KVN_UPDATE_ROOT="$PROJECT_ROOT" /bin/bash "$PROJECT_ROOT/update.sh" "$ARCHIVE"
