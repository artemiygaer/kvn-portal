#!/usr/bin/env bash
# Синхронизирует чистый deploy-шаблон и собирает tar.gz без runtime-данных.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON3="${PYTHON3:-python3}"
ARCHIVE="${1:-$ROOT_DIR/kvn-vpn-deploy.tar.gz}"
case "$ARCHIVE" in
  /*) ;;
  *) ARCHIVE="$ROOT_DIR/$ARCHIVE" ;;
esac
cd "$ROOT_DIR"

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kvn-deploy.XXXXXXXXXX")"
STAGE_DEPLOY="$STAGE_DIR/deploy"
cleanup() {
  rm -rf "$STAGE_DIR"
}
trap cleanup EXIT

MANIFEST_FILE=".kvn-canonical-files"
BUILD_ID="${KVN_BUILD_ID:-$(date -u '+%Y%m%d-%H%M%S')}"

SCHEMA_FILE="tools/canonical-files.txt"
if [ ! -f "$SCHEMA_FILE" ]; then
  echo "[ОШИБКА] Не найден канонический список: $SCHEMA_FILE" >&2
  exit 1
fi
mapfile -t canonical < "$SCHEMA_FILE"
if [ "${#canonical[@]}" -eq 0 ]; then
  echo "[ОШИБКА] Канонический список пуст: $SCHEMA_FILE" >&2
  exit 1
fi

deploy_only=(
  "DEPLOY.md"
  "users.json"
  "nginx/site/index.html"
  "nginx/web/.gitkeep"
  "hy2/.gitkeep"
  "mtg/.gitkeep"
  "telemt/.gitkeep"
  "xray/.gitkeep"
  "portal-data/.gitkeep"
  "portal-runtime/.gitkeep"
)

compatibility_only=(
  # Нужен для перехода с версии, где старый update.sh уже требует этот файл.
  "portal/build_info.py"
)

for source in "${canonical[@]}"; do
  if [ ! -f "$source" ]; then
    echo "[ОШИБКА] Не найден исходный файл: $source" >&2
    exit 1
  fi
done

case "$BUILD_ID" in
  *[!A-Za-z0-9._-]*)
    echo "[ОШИБКА] KVN_BUILD_ID должен содержать только латиницу, цифры, точку, подчёркивание и дефис" >&2
    exit 1
    ;;
esac
for source in "${compatibility_only[@]}"; do
  case "$source" in
    portal/build_info.py) ;;
    *)
      echo "[ОШИБКА] Неизвестный compatibility-файл: $source" >&2
      exit 1
      ;;
  esac
done

# Один Python-процесс заменяет сотни mkdir/cp, что особенно важно на Windows/WSL.
"$PYTHON3" tools/build_deploy_tree.py \
  stage "$ROOT_DIR" "$STAGE_DEPLOY" "$BUILD_ID" "${deploy_only[@]}"

blocked=(
  "clients"
  "CLIENT_LINKS.md"
  "certs"
  "site-certs"
  "ocserv/certs"
  "hy2/certs"
  "nginx/nginx.conf"
  "xray/config.json"
  "hy2/config.yaml"
  "amneziawg/awg0.conf"
  "wireguard/wg0.conf"
  "telemt/config.toml"
  "mtg/config.toml"
  "ocserv/ocserv.conf"
  "ocserv/users.txt"
  "ocserv/ocserv.env"
  "nginx/portal-gateway.conf"
  "portal-data/portal.db"
  "portal-data/portal.db-wal"
  "portal-data/portal.db-shm"
  "portal-data/metrics.db"
  "portal-data/metrics.db-wal"
  "portal-data/metrics.db-shm"
  "portal-runtime/users.json"
  "backup"
  ".env"
)

for path in "${blocked[@]}"; do
  if [ -e "$ROOT_DIR/deploy/$path" ]; then
    echo "[ОШИБКА] В deploy найден сгенерированный или устаревший файл: $path" >&2
    exit 1
  fi
done

DEPLOY_DIR="$STAGE_DEPLOY" "$PYTHON3" - <<'PY'
import json
import os
import re
from pathlib import Path

deploy_dir = Path(os.environ["DEPLOY_DIR"])
path = deploy_dir / "users.json"
state = json.loads(path.read_text(encoding="utf-8"))
if state.get("server") != "YOUR_SERVER_IP":
    raise SystemExit("[ОШИБКА] deploy/users.json должен содержать server=YOUR_SERVER_IP")
if state.get("users") != []:
    raise SystemExit("[ОШИБКА] deploy/users.json должен содержать пустой users")
if state.get("portal") != {"enabled": False}:
    raise SystemExit("[ОШИБКА] deploy/users.json должен содержать portal.enabled=false без других полей")

forbidden = {
    "private_key", "privateKey", "public_key", "publicKey", "preshared_key",
    "secret16", "hysteria_obfs", "hysteria_password", "telemt_secret",
    "ocserv_password", "sub_token", "uuid", "password_hash", "proxy_secret",
    "hysteria_secret", "agent_secret", "session_secret", "csrf_secret",
}

def walk(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in forbidden:
                raise SystemExit(f"[ОШИБКА] Секретное поле в deploy/users.json: {key}")
            walk(item)
    elif isinstance(value, list):
        for item in value:
            walk(item)

walk(state)

openers = {"if": "endif", "for": "endfor", "block": "endblock", "macro": "endmacro", "filter": "endfilter", "with": "endwith"}
closers = {value: key for key, value in openers.items()}
for template in sorted((deploy_dir / "portal/app/templates").glob("*.html")):
    text = template.read_text(encoding="utf-8")
    if text.count("{{") != text.count("}}") or text.count("{%") != text.count("%}"):
        raise SystemExit(f"[ERROR:PORTAL_TEMPLATE] Некорректный шаблон портала: {template}")
    stack = []
    for token in re.findall(r"{%\s*([a-zA-Z]+)\b.*?%}", text, re.DOTALL):
        if token in openers:
            stack.append(token)
        elif token in closers:
            if not stack or stack.pop() != closers[token]:
                raise SystemExit(f"[ERROR:PORTAL_TEMPLATE] Некорректный шаблон портала: {template}")
    if stack:
        raise SystemExit(f"[ERROR:PORTAL_TEMPLATE] Некорректный шаблон портала: {template}")
PY

while IFS= read -r runtime; do
  if [ -n "$runtime" ]; then
    echo "[ОШИБКА] В deploy найден runtime-файл портала: $runtime" >&2
    exit 1
  fi
done < <(find "$STAGE_DEPLOY" -type f \( -name '*.db' -o -name '*.db-wal' -o -name '*.db-shm' -o -name '*.log' -o -name '*.sock' -o -name '*.png' -o -name 'kvn-vpn-backup-*.tar' \) -print)

allowed=()
for source in "${canonical[@]}"; do allowed+=("$source"); done
for source in "${deploy_only[@]}"; do allowed+=("$source"); done
for source in "${compatibility_only[@]}"; do allowed+=("$source"); done
allowed+=("$MANIFEST_FILE")

while IFS= read -r file; do
  relative="${file#"$STAGE_DEPLOY"/}"
  known=0
  for expected in "${allowed[@]}"; do
    if [ "$relative" = "$expected" ]; then
      known=1
      break
    fi
  done
  if [ "$known" -ne 1 ]; then
    echo "[ОШИБКА] Неожиданный файл в deploy: $file" >&2
    exit 1
  fi
done < <(find "$STAGE_DEPLOY" -type f -print | sort)

# Обновляем checked-in deploy-зеркало только после полной проверки временного дерева.
"$PYTHON3" tools/build_deploy_tree.py sync "$ROOT_DIR" "$STAGE_DEPLOY"

rm -f "$ARCHIVE"
ARCHIVE="$ARCHIVE" STAGE_DIR="$STAGE_DIR" "$PYTHON3" - <<'PY'
import gzip
import os
import tarfile
from pathlib import Path

archive_path = Path(os.environ["ARCHIVE"])
stage_dir = Path(os.environ["STAGE_DIR"])
deploy_dir = stage_dir / "deploy"

def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info

paths = [deploy_dir, *sorted(deploy_dir.rglob("*"), key=lambda item: item.as_posix())]
with archive_path.open("wb") as output:
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for path in paths:
                archive.add(
                    path,
                    arcname=path.relative_to(stage_dir).as_posix(),
                    recursive=False,
                    filter=normalize,
                )
PY

echo "[OK] Deploy синхронизирован по каноническому списку: ${#canonical[@]} файлов"
echo "[OK] Deploy archive: $ARCHIVE"
