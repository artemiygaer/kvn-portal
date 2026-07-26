#!/usr/bin/env bash
# Пересобирает offline wheelhouse портала для Linux/amd64 и обновляет SHA-256.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORTAL_DIR="$ROOT_DIR/portal"
LOCK_FILE="$PORTAL_DIR/wheelhouse.lock"
WHEEL_DIR="$PORTAL_DIR/wheels"
STAGE="$(mktemp -d "$PORTAL_DIR/.wheelhouse.XXXXXXXX")"

cleanup() {
  case "$STAGE" in
    "$PORTAL_DIR"/.wheelhouse.*) rm -rf -- "$STAGE" ;;
  esac
}
trap cleanup EXIT

python3 -m pip download \
  --disable-pip-version-check \
  --only-binary=:all: \
  --no-deps \
  --platform musllinux_1_2_x86_64 \
  --implementation cp \
  --python-version 3.13 \
  --abi cp313 \
  --dest "$STAGE" \
  -r "$LOCK_FILE"

expected="$(grep -Ec '^[A-Za-z0-9_.-]+==' "$LOCK_FILE")"
actual="$(find "$STAGE" -maxdepth 1 -type f -name '*.whl' | wc -l)"
if [[ "$actual" -ne "$expected" ]]; then
  echo "[ОШИБКА] Wheelhouse неполон: ожидалось $expected, получено $actual" >&2
  exit 1
fi

(
  cd "$STAGE"
  sha256sum ./*.whl | sed 's#  \./#  #' | LC_ALL=C sort -k2 >SHA256SUMS
  sha256sum -c SHA256SUMS
)

install -d -m 0755 "$WHEEL_DIR"
find "$WHEEL_DIR" -maxdepth 1 -type f \( -name '*.whl' -o -name SHA256SUMS \) -delete
find "$STAGE" -maxdepth 1 -type f -name '*.whl' -exec install -m 0644 {} "$WHEEL_DIR/" \;
install -m 0644 "$STAGE/SHA256SUMS" "$WHEEL_DIR/SHA256SUMS"
echo "[OK] Offline wheelhouse обновлён: $actual файлов"
