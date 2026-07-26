#!/usr/bin/env bash
# Проверка, доступен ли AmneziaWG kernel mode на хосте.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] запустите от root: sudo ./amneziawg/check-mode.sh" >&2
    exit 1
fi

if modprobe amneziawg 2>/dev/null; then
    echo "[OK] modprobe amneziawg выполнен"
else
    echo "[WARN] modprobe amneziawg не сработал"
fi

if ip link add awg-kernel-test type amneziawg 2>/dev/null; then
    ip link delete awg-kernel-test
    echo "[OK] kernel mode доступен"
else
    echo "[ОШИБКА] kernel mode недоступен. Выполните sudo ./amneziawg/install-kernel-module.sh" >&2
    exit 1
fi
