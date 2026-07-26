#!/usr/bin/env bash
# Backward-compatible wrapper. Минимальная настройка хоста теперь живёт в tools/.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$ROOT_DIR/tools/tune-host-network.sh"
