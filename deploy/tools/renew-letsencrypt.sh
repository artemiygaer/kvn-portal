#!/usr/bin/env bash
# Обновляет Let's Encrypt сертификаты и раскладывает их в проектные пути.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

python3 tools/kvnctl.py letsencrypt renew --restart
