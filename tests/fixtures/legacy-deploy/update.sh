#!/usr/bin/env bash
# Фиксирует старый updater, который ожидал validator в установленном проекте.
set -euo pipefail
python3 tools/deploy_archive.py kvn-vpn-deploy.tar.gz
