#!/usr/bin/env bash
set -euo pipefail

CONF="${OCSERV_CONF:-/etc/ocserv/ocserv.conf}"
USERS="${OCSERV_USERS:-/etc/ocserv/users.txt}"
PASSWD="/run/ocserv/ocpasswd"
NETWORK="${OCSERV_NETWORK:-10.77.77.0/24}"

mkdir -p /run/ocserv
: >"$PASSWD"

created=0
if [[ -f "$USERS" ]]; then
    while IFS=: read -r username password rest; do
        [[ -z "${username:-}" || "${username:0:1}" == "#" ]] && continue
        if [[ -n "${rest:-}" || -z "${password:-}" ]]; then
            echo "[ocserv] invalid users.txt line for ${username:-<empty>}" >&2
            exit 1
        fi
        printf '%s\n%s\n' "$password" "$password" | ocpasswd -c "$PASSWD" "$username" >/dev/null
        created=$((created + 1))
    done <"$USERS"
fi

if [[ "$created" -eq 0 ]]; then
    echo "[ocserv] warning: no users configured" >&2
fi

WAN_IFACE="$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')"
if [[ -z "$WAN_IFACE" || ! "$WAN_IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]; then
    echo "[ocserv] error: не удалось определить безопасный внешний интерфейс" >&2
    exit 1
fi
if [[ ! -r /proc/sys/net/ipv4/ip_forward ]] || [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
    echo "[ocserv] error: IPv4 forwarding выключен; проверьте sysctls контейнера" >&2
    exit 1
fi
if ! iptables -t nat -C POSTROUTING -s "$NETWORK" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null; then
    if ! iptables -t nat -A POSTROUTING -s "$NETWORK" -o "$WAN_IFACE" -j MASQUERADE; then
        echo "[ocserv] error: не удалось добавить NAT rule для $WAN_IFACE" >&2
        exit 1
    fi
fi

exec ocserv -f -c "$CONF"
