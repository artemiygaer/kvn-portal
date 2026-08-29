#!/usr/bin/env bash
# Установка AmneziaWG kernel module на Debian-хост.
# Основано на официальной инструкции:
# https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[ОШИБКА] запустите от root: sudo ./amneziawg/install-kernel-module.sh" >&2
    exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

. /etc/os-release 2>/dev/null || true
PPA_SUITE="${AMNEZIAWG_PPA_SUITE:-focal}"
if [ "${ID:-}" = "debian" ] && [ "${VERSION_CODENAME:-}" = "trixie" ]; then
    PPA_SUITE="${AMNEZIAWG_PPA_SUITE:-noble}"
elif [ "${ID:-}" = "ubuntu" ] && [ "${VERSION_CODENAME:-}" = "noble" ]; then
    PPA_SUITE="${AMNEZIAWG_PPA_SUITE:-noble}"
fi

echo "[INFO] Устанавливаю зависимости AmneziaWG kernel module..."
apt-get update
apt-get install -y ca-certificates gnupg dirmngr dkms build-essential kmod

INSTALLED_VERSION_BEFORE="$(dpkg-query -W -f='${Version}' amneziawg 2>/dev/null || true)"

CURRENT_KERNEL="$(uname -r)"
NEW_KERNEL_INSTALLED=0
if apt-cache show "linux-headers-${CURRENT_KERNEL}" >/dev/null 2>&1; then
    apt-get install -y "linux-headers-${CURRENT_KERNEL}"
else
    echo "[ОШИБКА] В репозиториях нет headers для текущего kernel: ${CURRENT_KERNEL}" >&2
    echo "[INFO] Ставлю актуальные Debian kernel/headers metapackages: linux-image-amd64 linux-headers-amd64" >&2
    apt-get install -y linux-image-amd64 linux-headers-amd64
    NEW_KERNEL_INSTALLED=1
fi

KEYRING="/usr/share/keyrings/amneziawg-archive-keyring.gpg"
if [ ! -s "$KEYRING" ]; then
    echo "[INFO] Добавляю ключ PPA Amnezia..."
    GNUPG_HOME="$(mktemp -d)"
    chmod 700 "$GNUPG_HOME"
    trap 'rm -rf -- "$GNUPG_HOME"' EXIT
    gpg --homedir "$GNUPG_HOME" --batch \
        --keyserver-options timeout=15 \
        --keyserver hkps://keyserver.ubuntu.com \
        --recv-keys 57290828
    gpg --homedir "$GNUPG_HOME" --batch --export 57290828 | gpg --dearmor -o "$KEYRING"
    rm -rf -- "$GNUPG_HOME"
    trap - EXIT
    chmod 644 "$KEYRING"
fi

echo "[INFO] Настраиваю PPA Amnezia: ubuntu ${PPA_SUITE}"
cat >/etc/apt/sources.list.d/amnezia-ppa.list <<EOF
deb [signed-by=$KEYRING] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu ${PPA_SUITE} main
deb-src [signed-by=$KEYRING] https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu ${PPA_SUITE} main
EOF

apt-get update
apt-get install -y amneziawg
INSTALLED_VERSION_AFTER="$(dpkg-query -W -f='${Version}' amneziawg 2>/dev/null || true)"
if [ -z "$INSTALLED_VERSION_AFTER" ]; then
    echo "[ОШИБКА] apt завершился без установленного пакета amneziawg" >&2
    exit 1
fi
PACKAGE_CHANGED=0
if [ "$INSTALLED_VERSION_BEFORE" != "$INSTALLED_VERSION_AFTER" ]; then
    PACKAGE_CHANGED=1
    echo "[INFO] Версия AmneziaWG изменена: ${INSTALLED_VERSION_BEFORE:-не установлен} -> ${INSTALLED_VERSION_AFTER}"
else
    echo "[OK] AmneziaWG уже актуален: ${INSTALLED_VERSION_AFTER}"
fi

if ! command -v awg >/dev/null 2>&1; then
    echo "[ОШИБКА] пакет установлен без утилиты awg" >&2
    exit 1
fi
AWG_SET_HELP="$(awg set --help 2>&1 || true)"
if ! grep -q -- 'header-protection-key' <<<"$AWG_SET_HELP" \
    || ! grep -q -- 'content-padding-addition' <<<"$AWG_SET_HELP" \
    || ! grep -q -- 'rekey-after-time' <<<"$AWG_SET_HELP"; then
    echo "[ОШИБКА] PPA установил устаревшие awg-tools без поддержки AWG 3.1" >&2
    echo "[ПОДСКАЗКА] Проверьте PPA/AMNEZIAWG_PPA_SUITE и повторите apt update." >&2
    exit 1
fi
echo "[OK] awg-tools поддерживает HeaderProtectionKey, ContentPaddingAddition и тайминги AWG 3.x"

# Пакет мог быть установлен до появления headers текущего ядра. В этом случае
# повторный apt install не запускает DKMS postinst, а tools остаются без модуля.
if ! modinfo -k "$CURRENT_KERNEL" amneziawg >/dev/null 2>&1; then
    echo "[WARN] Модуль AmneziaWG отсутствует для текущего kernel: ${CURRENT_KERNEL}"
    echo "[INFO] Запускаю явную DKMS-сборку для текущего kernel..."
    DKMS_AUTOINSTALL_OK=1
    dkms autoinstall -k "$CURRENT_KERNEL" || DKMS_AUTOINSTALL_OK=0
    depmod -a "$CURRENT_KERNEL"
    if ! modinfo -k "$CURRENT_KERNEL" amneziawg >/dev/null 2>&1; then
        echo "[ОШИБКА] DKMS не установил модуль AmneziaWG для kernel ${CURRENT_KERNEL}" >&2
        dkms status -m amneziawg >&2 || true
        echo "[ПОДСКАЗКА] Проверьте последний make.log:" >&2
        echo "  find /var/lib/dkms/amneziawg -name make.log -type f -print" >&2
        exit 1
    fi
    if [ "$DKMS_AUTOINSTALL_OK" -eq 0 ]; then
        echo "[WARN] DKMS сообщил об ошибке другого модуля, но AmneziaWG для текущего kernel установлен."
    fi
    echo "[OK] DKMS-модуль AmneziaWG установлен для kernel ${CURRENT_KERNEL}"
fi

if [ "$NEW_KERNEL_INSTALLED" -eq 1 ]; then
    echo "" >&2
    echo "[ДЕЙСТВИЕ] Новый kernel, headers и AmneziaWG module установлены за один проход." >&2
    echo "Перезагрузите сервер, чтобы загрузиться в новый kernel:" >&2
    echo "  reboot" >&2
    echo "После reboot заново запустите setup для продолжения установки:" >&2
    echo "  cd ${ROOT_DIR}" >&2
    echo "  ./setup.sh" >&2
    echo "Setup не продолжится автоматически после перезагрузки." >&2
    exit 2
fi

echo "[INFO] Загружаю kernel module..."
modprobe amneziawg

if ip link add awg-kernel-test type amneziawg 2>/dev/null; then
    ip link delete awg-kernel-test
    echo "[OK] AmneziaWG kernel module работает"
else
    echo "[ОШИБКА] kernel module установлен, но ip link add type amneziawg не работает" >&2
    echo "Проверьте headers/kernel и dmesg." >&2
    exit 1
fi

if [ "$PACKAGE_CHANGED" -eq 1 ]; then
    echo "" >&2
    echo "[ДЕЙСТВИЕ] AmneziaWG kernel module установлен/обновлён. Перезагрузите сервер:" >&2
    echo "  reboot" >&2
    echo "После reboot заново запустите setup для продолжения установки:" >&2
    echo "  cd ${ROOT_DIR}" >&2
    echo "  ./setup.sh" >&2
    echo "Setup не продолжится автоматически после перезагрузки." >&2
    exit 3
fi

exit 0
