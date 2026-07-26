#!/usr/bin/env bash
# Запуск стандартного WireGuard как локальной systemd-службы на хосте.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_CONF="$ROOT_DIR/wireguard/wg0.conf"
DST_DIR="/etc/wireguard"
DST_CONF="$DST_DIR/wg0.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] запустите от root: sudo ./wireguard/install-host-service.sh" >&2
    exit 1
fi

if [ ! -f "$SRC_CONF" ]; then
    echo "[ОШИБКА] не найден $SRC_CONF. Сначала выполните: python3 tools/kvnctl.py render" >&2
    exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1 || ! command -v wg >/dev/null 2>&1; then
    echo "[ОШИБКА] wg/wg-quick не найдены. Установите пакет wireguard-tools." >&2
    exit 1
fi

WAN_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [ -z "$WAN_IFACE" ]; then
    echo "[ОШИБКА] не удалось определить внешний интерфейс" >&2
    exit 1
fi
if [[ ! "$WAN_IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
    echo "[ОШИБКА] небезопасное имя внешнего интерфейса: $WAN_IFACE" >&2
    exit 1
fi

echo "[INFO] Внешний интерфейс: $WAN_IFACE"
mkdir -p "$DST_DIR"
cp "$SRC_CONF" "$DST_CONF"
sed -i "s/-o eth0 /-o ${WAN_IFACE} /g" "$DST_CONF"
chmod 600 "$DST_CONF"

WG_IFACE="$(basename "$DST_CONF" .conf)"
WG_VALUES_OUTPUT="$(python3 - "$DST_CONF" <<'PY'
import ipaddress
import sys

address = ""
port = ""
for line in open(sys.argv[1], encoding="utf-8"):
    if line.strip().startswith("Address"):
        address = line.split("=", 1)[1].strip().split(",", 1)[0].strip()
    elif line.strip().startswith("ListenPort"):
        port = line.split("=", 1)[1].strip()
if not address:
    raise SystemExit("не найден Address в WireGuard config")
if not port.isdigit() or not 1 <= int(port) <= 65535:
    raise SystemExit("не найден корректный ListenPort в WireGuard config")
print(ipaddress.ip_interface(address).network)
print(port)
PY
)"
readarray -t WG_VALUES <<< "$WG_VALUES_OUTPUT"
WG_NETWORK="${WG_VALUES[0]}"
WG_PORT="${WG_VALUES[1]}"

cat >/etc/systemd/system/kvn-wireguard.service <<EOF
[Unit]
Description=KVN WireGuard host service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sh -c 'while iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -i $WG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o $WG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -t nat -D POSTROUTING -s $WG_NETWORK -o $WAN_IFACE -j MASQUERADE 2>/dev/null; do :; done; ip link delete $WG_IFACE 2>/dev/null || true'
ExecStart=/usr/bin/wg-quick up $DST_CONF
ExecStop=/bin/sh -c '/usr/bin/wg-quick down $DST_CONF 2>/dev/null || ip link delete $WG_IFACE 2>/dev/null || true; while iptables -D INPUT -p udp --dport $WG_PORT -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -i $WG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o $WG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -t nat -D POSTROUTING -s $WG_NETWORK -o $WAN_IFACE -j MASQUERADE 2>/dev/null; do :; done'

[Install]
WantedBy=multi-user.target
EOF

sysctl -w net.ipv4.ip_forward=1 >/dev/null
cat >/etc/sysctl.d/99-kvn-vpn.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF
if ! sysctl -p /etc/sysctl.d/99-kvn-vpn.conf >/dev/null; then
    echo "[ОШИБКА] не удалось применить persistent IPv4 forwarding" >&2
    exit 1
fi
if [ ! -r /proc/sys/net/ipv4/ip_forward ] || [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    echo "[ОШИБКА] IPv4 forwarding выключен; трафик WireGuard не будет работать" >&2
    exit 1
fi

if ip link show "$WG_IFACE" >/dev/null 2>&1; then
    echo "[INFO] Удаляю старый интерфейс $WG_IFACE..."
    ip link delete "$WG_IFACE" 2>/dev/null || wg-quick down "$DST_CONF" 2>/dev/null || true
fi

systemctl daemon-reload
systemctl enable kvn-wireguard.service
systemctl restart kvn-wireguard.service

echo "[OK] WireGuard запущен на хосте через systemd"
echo "Проверка: systemctl status kvn-wireguard --no-pager"
systemctl --no-pager --full status kvn-wireguard.service || true
