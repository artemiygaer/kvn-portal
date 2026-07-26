#!/usr/bin/env bash
# Синхронизирует project-конфиг AmneziaWG; peer-only изменения применяет без разрыва сессий.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_CONF="$ROOT_DIR/amneziawg/awg0.conf"
DST_DIR="/etc/amnezia/amneziawg"
DST_CONF="$DST_DIR/awg0.conf"
UNIT="/etc/systemd/system/kvn-amneziawg.service"

if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] запустите от root: sudo ./amneziawg/sync-host-service.sh" >&2
    exit 1
fi

if [ ! -f "$SRC_CONF" ]; then
    echo "[ОШИБКА] не найден $SRC_CONF. Сначала выполните: python3 tools/kvnctl.py render" >&2
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

verify_ipv4_forwarding() {
    if [ ! -r /proc/sys/net/ipv4/ip_forward ] || [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
        echo "KVN_AWG_ERROR=ipv4_forwarding_disabled" >&2
        echo "[ОШИБКА] IPv4 forwarding выключен; трафик AmneziaWG не будет работать" >&2
        echo "[ПОДСКАЗКА] Выполните вне portal-agent: sudo ./tools/tune-host-network.sh" >&2
        exit 1
    fi
}

mkdir -p "$DST_DIR"
OLD_CONF="$(mktemp)"
STRIPPED_CONF="$(mktemp)"
NEW_CONF="$(mktemp "$DST_DIR/.awg0.conf.XXXXXX")"
trap 'rm -f "$OLD_CONF" "$STRIPPED_CONF" "$NEW_CONF"' EXIT
if [ -f "$DST_CONF" ]; then
    cp "$DST_CONF" "$OLD_CONF"
fi
cp "$SRC_CONF" "$NEW_CONF"
sed -i "s/-o eth0 /-o ${WAN_IFACE} /g" "$NEW_CONF"
chmod 600 "$NEW_CONF"

AWG_IFACE="$(basename "$DST_CONF" .conf)"
AWG_VALUES_OUTPUT="$(python3 - "$NEW_CONF" <<'PY'
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
    raise SystemExit("не найден Address в AmneziaWG config")
if not port.isdigit() or not 1 <= int(port) <= 65535:
    raise SystemExit("не найден корректный ListenPort в AmneziaWG config")
print(ipaddress.ip_interface(address).network)
print(port)
PY
)"
readarray -t AWG_VALUES <<< "$AWG_VALUES_OUTPUT"
AWG_NETWORK="${AWG_VALUES[0]}"
AWG_PORT="${AWG_VALUES[1]}"
STRUCTURAL_CHANGED=true
if [ -s "$OLD_CONF" ] && diff -q \
    <(awk '/^\[Peer\]/{exit} {print}' "$OLD_CONF") \
    <(awk '/^\[Peer\]/{exit} {print}' "$NEW_CONF") >/dev/null; then
    STRUCTURAL_CHANGED=false
fi

write_unit() {
    cat >"$UNIT" <<EOF
[Unit]
Description=KVN AmneziaWG host service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sh -c 'while iptables -D INPUT -p udp --dport $AWG_PORT -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -i $AWG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o $AWG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -t nat -D POSTROUTING -s $AWG_NETWORK -o $WAN_IFACE -j MASQUERADE 2>/dev/null; do :; done; ip link delete $AWG_IFACE 2>/dev/null || true'
ExecStart=/usr/bin/awg-quick up $DST_CONF
ExecStop=/bin/sh -c '/usr/bin/awg-quick down $DST_CONF 2>/dev/null || ip link delete $AWG_IFACE 2>/dev/null || true; while iptables -D INPUT -p udp --dport $AWG_PORT -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -i $AWG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -D FORWARD -o $AWG_IFACE -j ACCEPT 2>/dev/null; do :; done; while iptables -t nat -D POSTROUTING -s $AWG_NETWORK -o $WAN_IFACE -j MASQUERADE 2>/dev/null; do :; done'

[Install]
WantedBy=multi-user.target
EOF
}

verify_ipv4_forwarding
mv -f "$NEW_CONF" "$DST_CONF"

if [ "$STRUCTURAL_CHANGED" = true ] || [ ! -f "$UNIT" ]; then
    write_unit
    systemctl daemon-reload
fi

HOT_UPDATE=false
SYNC_FALLBACK=false
if [ "$STRUCTURAL_CHANGED" = false ] \
    && systemctl is-active --quiet kvn-amneziawg.service \
    && ip link show "$AWG_IFACE" >/dev/null 2>&1; then
    if awg-quick strip "$DST_CONF" >"$STRIPPED_CONF" \
        && awg syncconf "$AWG_IFACE" "$STRIPPED_CONF"; then
        HOT_UPDATE=true
    else
        SYNC_FALLBACK=true
    fi
fi

if [ "$HOT_UPDATE" = true ]; then
    echo "KVN_AWG_APPLY_MODE=syncconf"
    echo "[OK] peers AmneziaWG обновлены через awg syncconf без перезапуска"
else
    systemctl restart kvn-amneziawg.service
    echo "KVN_AWG_APPLY_MODE=restart"
    if [ "$SYNC_FALLBACK" = true ]; then
        echo "KVN_AWG_FALLBACK=syncconf_failed"
    fi
    echo "[OK] конфигурация AmneziaWG применена с перезапуском"
fi
systemctl --no-pager --full status kvn-amneziawg.service || true
