#!/usr/bin/env bash
# Install systemd timer for Let's Encrypt renew + KVN Docker cert deployment.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "[ОШИБКА] Запустите от root: sudo $0" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE="/etc/systemd/system/kvn-letsencrypt-renew.service"
TIMER="/etc/systemd/system/kvn-letsencrypt-renew.timer"

cat >"$SERVICE" <<EOF
[Unit]
Description=KVN VPN Let's Encrypt renew and deploy
Wants=network-online.target
After=network-online.target docker.service

[Service]
Type=oneshot
WorkingDirectory=$ROOT_DIR
Environment=PYTHONIOENCODING=utf-8
ExecStart=$ROOT_DIR/tools/renew-letsencrypt.sh
EOF

cat >"$TIMER" <<'EOF'
[Unit]
Description=Run KVN VPN Let's Encrypt renew twice daily

[Timer]
OnCalendar=*-*-* 04,16:17:00
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

chmod 0644 "$SERVICE" "$TIMER"
chmod 0755 "$ROOT_DIR/tools/renew-letsencrypt.sh"
systemctl daemon-reload
systemctl enable --now kvn-letsencrypt-renew.timer
systemctl list-timers kvn-letsencrypt-renew.timer --no-pager
