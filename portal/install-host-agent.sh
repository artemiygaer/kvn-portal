#!/usr/bin/env bash
# Устанавливает локальный root-agent управления KVN VPN.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ОШИБКА] Запустите от root: sudo $0" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT=/etc/systemd/system/kvn-portal-agent.service
CONFIG_DIR=/etc/kvn-portal
SECRET_FILE="$CONFIG_DIR/agent.secret"
GITHUB_TOKEN_FILE="$CONFIG_DIR/github.token"
STATE_DIR=/var/lib/kvn-portal
FINGERPRINT_FILE="$STATE_DIR/agent-source.sha256"

getent group kvn-portal >/dev/null 2>&1 || groupadd --system kvn-portal
install -d -o root -g kvn-portal -m 0750 "$CONFIG_DIR"
install -d -o root -g kvn-portal -m 0750 "$STATE_DIR"
# Portal работает с фиксированным UID 10001; upload не должен попадать в tmpfs /tmp.
install -d -o 10001 -g kvn-portal -m 0700 "$ROOT_DIR/portal-data"
install -d -o 10001 -g kvn-portal -m 0700 "$ROOT_DIR/portal-data/updates"
install -d -o root -g root -m 0700 /etc/amnezia /etc/amnezia/amneziawg /etc/wireguard
install -d -o root -g root -m 0755 /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt

if [[ ! -s "$SECRET_FILE" ]]; then
    python3 - "$SECRET_FILE" <<'PY'
import secrets
import sys
from pathlib import Path

path = Path(sys.argv[1])
path.write_text(secrets.token_hex(32) + "\n", encoding="utf-8")
PY
fi
chown root:kvn-portal "$SECRET_FILE"
chmod 0640 "$SECRET_FILE"
if [[ -e "$GITHUB_TOKEN_FILE" ]]; then
    if [[ -L "$GITHUB_TOKEN_FILE" || ! -f "$GITHUB_TOKEN_FILE" ]]; then
        echo "[ОШИБКА] $GITHUB_TOKEN_FILE должен быть обычным файлом" >&2
        exit 1
    fi
    chown root:root "$GITHUB_TOKEN_FILE"
    chmod 0600 "$GITHUB_TOKEN_FILE"
fi

unit_tmp="$(mktemp)"
trap 'rm -f "$unit_tmp"' EXIT
cat >"$unit_tmp" <<EOF
[Unit]
Description=KVN VPN privileged portal agent
After=docker.service network-online.target
Wants=docker.service network-online.target

[Service]
Type=simple
User=root
Group=kvn-portal
WorkingDirectory=$ROOT_DIR
ExecStart=/usr/bin/python3 $ROOT_DIR/portal/agent.py --project-root $ROOT_DIR --socket /run/kvn-portal/control.sock --secret-file $SECRET_FILE --socket-group kvn-portal --metrics-db /var/lib/kvn-portal/metrics.db
Restart=on-failure
RestartSec=2s
MemoryHigh=192M
MemoryMax=256M
CPUQuota=40%
TasksMax=128
RuntimeDirectory=kvn-portal
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=restart
StateDirectory=kvn-portal
StateDirectoryMode=0750
UMask=0007
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=tmpfs
BindPaths=$ROOT_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
ReadWritePaths=$ROOT_DIR /run/kvn-portal $STATE_DIR /etc/amnezia/amneziawg /etc/wireguard /etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /etc/systemd/system
ReadOnlyPaths=-$GITHUB_TOKEN_FILE

[Install]
WantedBy=multi-user.target
EOF

unit_changed=0
if [[ ! -f "$UNIT" ]] || ! cmp -s "$unit_tmp" "$UNIT"; then
    install -o root -g root -m 0644 "$unit_tmp" "$UNIT"
    unit_changed=1
fi

source_fingerprint="$({
    find \
        "$ROOT_DIR/portal/agent.py" \
        "$ROOT_DIR/portal/agent_protocol.py" \
        "$ROOT_DIR/portal/agent_handlers" \
        "$ROOT_DIR/portal/control.py" \
        "$ROOT_DIR/portal/control" \
        "$ROOT_DIR/portal/github_updates.py" \
        "$ROOT_DIR/portal/metrics.py" \
        "$ROOT_DIR/portal/system_user_helper.py" \
        "$ROOT_DIR/tools/kvnctl.py" \
        "$ROOT_DIR/tools/kvnlib" \
        -type f -name '*.py' -print0 \
        | sort -z \
        | xargs -0 sha256sum
} | sha256sum | awk '{print $1}')"
installed_fingerprint="$(cat "$FINGERPRINT_FILE" 2>/dev/null || true)"
restart_required=0
if [[ "$unit_changed" = "1" || "$source_fingerprint" != "$installed_fingerprint" ]]; then
    restart_required=1
fi

if [[ "$unit_changed" = "1" ]]; then
    systemctl daemon-reload
fi
systemctl enable kvn-portal-agent.service
if systemctl is-active --quiet kvn-portal-agent.service; then
    if [[ "$restart_required" = "1" ]]; then
        rm -f /run/kvn-portal/control.sock
        systemctl restart kvn-portal-agent.service
    fi
else
    rm -f /run/kvn-portal/control.sock
    systemctl start kvn-portal-agent.service
fi

for _ in $(seq 1 120); do
    if systemctl is-active --quiet kvn-portal-agent.service \
        && [[ -S /run/kvn-portal/control.sock ]]; then
        runtime_group="$(stat -c '%G' /run/kvn-portal)"
        runtime_meta="$(stat -c '%U:%G:%a' /run/kvn-portal)"
        socket_meta="$(stat -c '%U:%G:%a' /run/kvn-portal/control.sock)"
        if [[ "$runtime_group" != "kvn-portal" || "$runtime_meta" != "root:kvn-portal:750" ]]; then
            echo "[ОШИБКА] /run/kvn-portal имеет неверные owner/group/mode" >&2
            exit 1
        fi
        if [[ "$socket_meta" != "root:kvn-portal:660" ]]; then
            echo "[ОШИБКА] control.sock имеет неверные owner/group/mode" >&2
            exit 1
        fi
        if [[ ! -r "$SECRET_FILE" || "$(stat -c '%U:%G:%a' "$SECRET_FILE")" != "root:kvn-portal:640" ]]; then
            echo "[ОШИБКА] agent.secret недоступен или имеет неверные owner/group/mode" >&2
            exit 1
        fi
        if python3 - "$ROOT_DIR" "$SECRET_FILE" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from portal.agent_client import AgentClient

secret = Path(sys.argv[2]).read_text(encoding="utf-8").strip()
client = AgentClient(Path("/run/kvn-portal/control.sock"), secret, timeout=2)
health = client.call("health.host", {})
capability = client.call("ping", {})
current = client.call("metrics.current", {})
history = client.call("metrics.history", {"range_hours": 1, "step": 1})
required = {"rpc-v1", "dashboard-snapshot-v1", "runtime-apply-v1", "session-bound-shell-v1"}
if (
    not all(isinstance(result, dict) for result in (health, capability, current, history))
    or capability.get("status") != "ok"
    or not isinstance(capability.get("generation"), str)
    or len(capability["generation"]) != 32
    or not required.issubset(set(capability.get("capabilities", [])))
):
    raise SystemExit(1)
PY
        then
            fingerprint_tmp="$STATE_DIR/.agent-source.sha256.tmp"
            printf '%s\n' "$source_fingerprint" >"$fingerprint_tmp"
            chown root:kvn-portal "$fingerprint_tmp"
            chmod 0640 "$fingerprint_tmp"
            mv -f "$fingerprint_tmp" "$FINGERPRINT_FILE"
            if [[ "$restart_required" = "1" ]]; then
                echo "[OK] kvn-portal-agent.service обновлён; Unix-сокет и RPC работают (health/metrics)"
            else
                echo "[OK] kvn-portal-agent.service не изменился; перезапуск не потребовался"
            fi
            exit 0
        fi
    fi
    sleep 0.25
done

echo "[ОШИБКА] kvn-portal-agent.service не создал Unix-сокет" >&2
systemctl --no-pager --full status kvn-portal-agent.service >&2 || true
journalctl -u kvn-portal-agent.service -n 50 --no-pager >&2 || true
exit 1
