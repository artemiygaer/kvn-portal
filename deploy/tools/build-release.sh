#!/usr/bin/env bash
# Собирает переносимый Linux/amd64 release без build/pull на целевом сервере.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT_DIR/kvn-vpn-release-linux-amd64.tar.gz}"
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$ROOT_DIR/$OUTPUT" ;;
esac
BUILD_ID="${KVN_BUILD_ID:-$(date -u '+%Y%m%d-%H%M%S')}"
OFFLINE="${KVN_RELEASE_OFFLINE:-0}"
case "$BUILD_ID" in
  ""|*[!A-Za-z0-9._-]*)
    echo "[ОШИБКА] Недопустимый KVN_BUILD_ID: $BUILD_ID" >&2
    exit 1
    ;;
esac
case "$OFFLINE" in
  0|1) ;;
  *)
    echo "[ОШИБКА] KVN_RELEASE_OFFLINE должен быть 0 или 1" >&2
    exit 1
    ;;
esac

for command in docker python3 gzip tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "[ОШИБКА] Не найдена команда: $command" >&2
    exit 1
  fi
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/kvn-release.XXXXXXXXXX")"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT
cd "$ROOT_DIR"

SOURCE="$WORK_DIR/kvn-vpn-deploy.tar.gz"
IMAGES="$WORK_DIR/kvn-vpn-images-linux-amd64.tar"
METADATA="$WORK_DIR/image-metadata.json"
RAW_METADATA="$WORK_DIR/image-inspect.json"
REFS_FILE="$WORK_DIR/image-refs.txt"

refs=(
  "kvn-portal:local"
  "nginx:1.31.1-alpine"
  "ghcr.io/telemt/telemt:3.4.24"
  "nineseconds/mtg:2.2.8"
  "tobyxdd/hysteria:v2.10.0"
  "kvn-ocserv:local"
  "ghcr.io/xtls/xray-core:26.3.27"
)

echo "[INFO] Собираю локальные образы для linux/amd64..."
if [ "$OFFLINE" = "1" ]; then
  echo "[INFO] Offline release: используются семь заранее подготовленных runtime-образов"
  for ref in "${refs[@]}"; do
    if ! docker image inspect "$ref" >/dev/null 2>&1; then
      echo "[ОШИБКА] Offline release: локальный образ отсутствует: $ref" >&2
      exit 1
    fi
  done
  portal_build_id="$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' kvn-portal:local \
    | sed -n 's/^KVN_BUILD_ID=//p' | tail -n 1)"
  if [ "$portal_build_id" != "$BUILD_ID" ]; then
    echo "[ОШИБКА] Offline release: kvn-portal:local имеет KVN_BUILD_ID=$portal_build_id, ожидался $BUILD_ID" >&2
    exit 1
  fi
else
  docker build --platform linux/amd64 --provenance=false --target runtime --build-arg "KVN_BUILD_ID=$BUILD_ID" \
    -t kvn-portal:local portal
  docker build --platform linux/amd64 --provenance=false --network host -t kvn-ocserv:local ocserv
fi

if [ "$OFFLINE" = "0" ]; then
  for ref in \
    "nginx:1.31.1-alpine" \
    "ghcr.io/telemt/telemt:3.4.24" \
    "nineseconds/mtg:2.2.8" \
    "tobyxdd/hysteria:v2.10.0" \
    "ghcr.io/xtls/xray-core:26.3.27"; do
    docker pull --platform linux/amd64 "$ref"
  done
fi

printf '%s\n' "${refs[@]}" > "$REFS_FILE"
docker image inspect "${refs[@]}" > "$RAW_METADATA"
RAW_METADATA="$RAW_METADATA" REFS_FILE="$REFS_FILE" METADATA="$METADATA" python3 - <<'PY'
import json
import os
from pathlib import Path

raw = json.loads(Path(os.environ["RAW_METADATA"]).read_text(encoding="utf-8"))
refs = Path(os.environ["REFS_FILE"]).read_text(encoding="utf-8").splitlines()
if len(raw) != len(refs):
    raise SystemExit("[ОШИБКА] docker image inspect вернул неверное число образов")
metadata = []
for ref, item in zip(refs, raw, strict=True):
    platform = f"{item.get('Os', '')}/{item.get('Architecture', '')}"
    if platform != "linux/amd64":
        raise SystemExit(f"[ОШИБКА] Неверная платформа образа {ref}: {platform}")
    metadata.append({
        "ref": ref,
        "id": item.get("Id", ""),
        "platform": platform,
        "repo_digests": item.get("RepoDigests") or [],
    })
Path(os.environ["METADATA"]).write_text(
    json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY

echo "[INFO] Экспортирую семь runtime-образов..."
docker image save -o "$IMAGES" "${refs[@]}"
python3 -m tools.release_archive normalize-images "$IMAGES" >/dev/null
IMAGES="$IMAGES" METADATA="$METADATA" python3 - <<'PY'
import json
import os
import tarfile
from pathlib import Path

metadata_path = Path(os.environ["METADATA"])
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
with tarfile.open(os.environ["IMAGES"], "r:") as archive:
    handle = archive.extractfile("manifest.json")
    if handle is None:
        raise SystemExit("[ОШИБКА] Docker image archive не содержит manifest.json")
    docker_manifest = json.loads(handle.read().decode("utf-8"))
loaded_ids = {}
for item in docker_manifest:
    image_id = "sha256:" + Path(item["Config"]).name.removesuffix(".json")
    for ref in item.get("RepoTags") or []:
        loaded_ids[ref] = image_id
for item in metadata:
    if item["ref"] not in loaded_ids:
        raise SystemExit(f"[ОШИБКА] В image archive нет tag: {item['ref']}")
    item["id"] = loaded_ids[item["ref"]]
metadata_path.write_text(
    json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
PY
KVN_BUILD_ID="$BUILD_ID" bash tools/build-deploy.sh "$SOURCE"

python3 -m tools.release_archive create \
  --build-id "$BUILD_ID" --source "$SOURCE" --images "$IMAGES" \
  --metadata "$METADATA" --output "$OUTPUT"
python3 -m tools.release_archive inspect "$OUTPUT" >/dev/null

OUTPUT="$OUTPUT" SOURCE="$SOURCE" IMAGES="$IMAGES" METADATA="$METADATA" python3 - <<'PY'
import hashlib
import json
import os
import sys
from pathlib import Path

def describe(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"{path.name}: sha256={digest}, size={path.stat().st_size}"

metadata = json.loads(Path(os.environ["METADATA"]).read_text(encoding="utf-8"))
for item in metadata:
    sys.stdout.write(f"[IMAGE] {item['ref']} {item['id']} {item['platform']}\n")
for variable in ("SOURCE", "IMAGES", "OUTPUT"):
    sys.stdout.write("[ARTIFACT] " + describe(Path(os.environ[variable])) + "\n")
sys.stdout.write("[LEAK_SCAN] runtime users/keys/certs/clients/DB/.env/backups: 0; users.json: clean template only\n")
PY

echo "[OK] Release готов: $OUTPUT"
