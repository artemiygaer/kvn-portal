#!/usr/bin/env bash
# Минимальная настройка хоста для KVN VPN.
# Автоматический setup не применяет агрессивный сетевой тюнинг. Скрипт оставлен
# для совместимости и включает только маршрутизацию IPv4 для host VPN-интерфейсов.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] запустите от root: sudo ./tools/tune-host-network.sh" >&2
    exit 1
fi

cat >/etc/sysctl.d/99-kvn-vpn.conf <<'EOF'
# KVN VPN: маршрутизация для host VPN-интерфейсов.
net.ipv4.ip_forward = 1
EOF

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -p /etc/sysctl.d/99-kvn-vpn.conf >/dev/null

echo "[OK] IPv4 forwarding включён"
