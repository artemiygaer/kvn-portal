#!/usr/bin/env bash
# KVN VPN v3 — Первичная настройка сервера.
# Запускается на сервере: ./setup.sh или ./setup.sh <IP>
# Всё генерируется из users.json через kvnctl.py.
set -euo pipefail

# Локальные provenance-attestations меняют manifest digest при каждом build и вынуждают
# Compose пересоздавать неизменённые контейнеры. Release provenance даёт сам архив SHA-256.
export BUILDX_NO_DEFAULT_ATTESTATIONS=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
OFFLINE_RELEASE="${KVN_RELEASE_ARCHIVE:-}"
SETUP_SERVER_ARG="${1:-}"
if [ "${1:-}" = "--release" ]; then
    OFFLINE_RELEASE="${2:-}"
    SETUP_SERVER_ARG="${3:-}"
elif [ "${2:-}" = "--release" ]; then
    OFFLINE_RELEASE="${3:-}"
fi

# ── Цвета ──────────────────────────────────────────────────────────────────

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    R='\033[0m'    # reset
    B='\033[1m'    # bold
    D='\033[2m'    # dim
    RED='\033[31m'
    GRN='\033[32m'
    YLW='\033[33m'
    CYN='\033[36m'
else
    R='' B='' D='' RED='' GRN='' YLW='' CYN=''
fi

ok()   { echo -e "${GRN}[OK]${R} $*"; }
warn() { echo -e "${YLW}[WARN]${R} $*"; }
err()  { echo -e "${RED}[ОШИБКА]${R} $*"; }
info() { echo -e "${CYN}[INFO]${R} $*"; }

prompt_yes_no() {
    local prompt="$1"
    local default="${2:-n}"
    local answer=""
    while true; do
        read -rp "$prompt" answer
        answer="${answer,,}"
        if [ -z "$answer" ]; then
            answer="$default"
        fi
        case "$answer" in
            y|yes|д|да) return 0 ;;
            n|no|н|нет) return 1 ;;
            *) err "Введите y/да или n/нет" ;;
        esac
    done
}

header() {
    local msg="$1"
    local width=$(( ${#msg} + 4 ))
    [ "$width" -lt 52 ] && width=52
    local line=""
    for ((i=0; i<width; i++)); do line+="═"; done
    echo ""
    echo -e "${B}${CYN}${line}${R}"
    echo -e "${B}${CYN}  ${msg}${R}"
    echo -e "${B}${CYN}${line}${R}"
}

separator() {
    echo -e "${D}────────────────────────────────────────────────────${R}"
}

# ── Проверка root ─────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    err "запустите от root (sudo ./setup.sh)"
    exit 1
fi

MAINTENANCE_LOCK="${KVN_MAINTENANCE_LOCK:-/run/lock/kvn-vpn-maintenance.lock}"
MAINTENANCE_LOCK_TIMEOUT="${KVN_MAINTENANCE_LOCK_TIMEOUT:-10}"
if ! command -v flock >/dev/null 2>&1; then
    err "flock не найден (нужен пакет util-linux)"
    exit 1
fi
exec 9>"$MAINTENANCE_LOCK"
if ! flock -w "$MAINTENANCE_LOCK_TIMEOUT" 9; then
    err "другая операция обслуживания уже выполняется: $(head -n 1 "$MAINTENANCE_LOCK" 2>/dev/null || echo owner=unknown)"
    exit 1
fi
printf 'pid=%s action=setup started=%s\n' "$$" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >&9

# ── Ввод IP ───────────────────────────────────────────────────────────────
SERVER_IP="$SETUP_SERVER_ARG"
if [ -z "$SERVER_IP" ]; then
    # Попробуем определить автоматически
    AUTO_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
    if [ -n "$AUTO_IP" ]; then
        read -rp "Введите IP-адрес сервера [$AUTO_IP]: " SERVER_IP
        SERVER_IP="${SERVER_IP:-$AUTO_IP}"
    else
        while [ -z "$SERVER_IP" ]; do
            read -rp "Введите IP-адрес сервера: " SERVER_IP
            [ -n "$SERVER_IP" ] || err "IP адрес не указан"
        done
    fi
fi

if [ -z "$SERVER_IP" ]; then
    err "IP адрес не указан"
    echo "  Использование: ./setup.sh <SERVER_IP>"
    exit 1
fi

header "KVN VPN v3 — Настройка сервера: $SERVER_IP"
echo -e "  ${D}Дата: $(date '+%Y-%m-%d %H:%M:%S')${R}"
echo ""

# ── Docker и системные компоненты ─────────────────────────────────────────

install_docker() {
    if command -v docker >/dev/null 2>&1; then
        ok "Docker: $(docker --version)"
        return
    fi
    if [ ! -r /etc/os-release ]; then
        err "Не удалось определить версию ОС: отсутствует /etc/os-release"
        exit 1
    fi
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "debian" ] || [[ "${VERSION_ID:-}" != "12" && "${VERSION_ID:-}" != "13" ]]; then
        err "Поддерживаются только Debian 12/13; обнаружено ${PRETTY_NAME:-unknown}"
        exit 1
    fi
    if [ -z "${VERSION_CODENAME:-}" ]; then
        err "Не удалось определить Debian codename для Docker apt-репозитория"
        exit 1
    fi
    if ! command -v dpkg >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        err "Для безопасной установки Docker нужны dpkg и gpg"
        exit 1
    fi
    info "Docker не найден. Устанавливаю из официального signed apt-репозитория..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -d -m 0755 /etc/apt/keyrings
    local key_tmp
    key_tmp="$(mktemp)"
    trap 'rm -f -- "$key_tmp"' EXIT
    if ! curl --fail --silent --show-error --location \
        --connect-timeout 10 --max-time 60 \
        --retry 3 --retry-all-errors \
        https://download.docker.com/linux/debian/gpg \
        --output "$key_tmp"; then
        rm -f -- "$key_tmp"
        err "Не удалось загрузить официальный Docker GPG key"
        exit 1
    fi
    if ! gpg --dearmor --yes --output /etc/apt/keyrings/docker.gpg "$key_tmp"; then
        rm -f -- "$key_tmp"
        err "Не удалось установить Docker GPG key"
        exit 1
    fi
    rm -f -- "$key_tmp"
    trap - EXIT
    chmod a+r /etc/apt/keyrings/docker.gpg
    printf '%s\n' \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    systemctl enable --now docker
    ok "Docker установлен"
}

ensure_compose() {
    if docker compose version >/dev/null 2>&1; then
        ok "Docker Compose: $(docker compose version --short 2>/dev/null)"
        return
    fi

    if command -v docker-compose >/dev/null 2>&1; then
        ok "Docker Compose standalone: $(docker-compose version --short 2>/dev/null)"
        warn "Рекомендуется обновить: apt install docker-compose-plugin"
        return
    fi

    info "Docker Compose не найден. Устанавливаю plugin..."
    apt-get update -qq
    apt-get install -y -qq docker-compose-plugin
    if docker compose version >/dev/null 2>&1; then
        ok "Docker Compose plugin установлен"
    else
        err "не удалось установить docker-compose-plugin"
        exit 1
    fi
}

ensure_python3() {
    if command -v python3 >/dev/null 2>&1; then
        ok "Python3: $(python3 --version 2>/dev/null)"
        return
    fi
    info "Python3 не найден. Устанавливаю..."
    apt-get update -qq
    apt-get install -y -qq python3
    ok "Python3 установлен"
}

ensure_qrencode() {
    if command -v qrencode >/dev/null 2>&1; then
        ok "qrencode: установлен"
        return
    fi
    info "qrencode не найден. Устанавливаю для QR AmneziaWG..."
    apt-get update -qq
    apt-get install -y -qq qrencode
    ok "qrencode установлен"
}

ensure_certbot() {
    if command -v certbot >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
        ok "certbot: $(certbot --version 2>/dev/null | head -n1)"
        return
    fi
    info "Устанавливаю Certbot и OpenSSL для Let's Encrypt..."
    apt-get update -qq
    apt-get install -y -qq certbot openssl
    ok "certbot и openssl установлены"
}

ensure_wireguard_tools() {
    if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
        ok "WireGuard tools: установлен"
        return
    fi
    info "Устанавливаю wireguard-tools для стандартного WireGuard..."
    apt-get update -qq
    apt-get install -y -qq wireguard-tools
    if command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; then
        ok "wireguard-tools установлен"
    else
        err "wireguard-tools установлен не полностью: wg/wg-quick не найдены"
        exit 1
    fi
}

stop_for_kernel_reboot() {
    local reason="${1:-module}"
    echo ""
    echo -e "${RED}${B}============================================================${R}"
    echo -e "${RED}${B}[ТРЕБУЕТСЯ ПЕРЕЗАГРУЗКА СЕРВЕРА]${R}"
    if [ "$reason" = "new-kernel" ]; then
        echo -e "${RED}Установлены новый kernel и headers. Текущее ядро ещё старое.${R}"
    else
        echo -e "${RED}Установлен/обновлён AmneziaWG kernel module.${R}"
    fi
    echo -e "${RED}До перезагрузки продолжать установку и запуск сервисов нельзя.${R}"
    echo ""
    echo -e "${RED}${B}1. Перезагрузите сервер:${R}"
    echo -e "${RED}   reboot${R}"
    echo -e "${RED}${B}2. После загрузки заново запустите setup для продолжения:${R}"
    echo -e "${RED}   cd ${SCRIPT_DIR}${R}"
    echo -e "${RED}   ./setup.sh ${SERVER_IP}${R}"
    echo -e "${RED}${B}Установка не продолжится автоматически после reboot.${R}"
    echo -e "${RED}${B}============================================================${R}"
    echo ""
    exit 2
}

ensure_amneziawg_kernel_module() {
    if command -v awg-quick >/dev/null 2>&1; then
        info "AmneziaWG найден. Проверяю обновление пакета через apt..."
    else
        if [ ! -t 0 ]; then
            err "awg-quick не найден. Запустите setup в интерактивном терминале или установите модуль: sudo ./amneziawg/install-kernel-module.sh"
            exit 1
        fi

        if ! prompt_yes_no "awg-quick не найден. Установить AmneziaWG kernel module сейчас? (y/N): " "n"; then
            err "Для AmneziaWG-службы нужен awg-quick. Выполните: sudo ./amneziawg/install-kernel-module.sh"
            exit 1
        fi
    fi

    set +e
    bash ./amneziawg/install-kernel-module.sh
    awg_install_rc=$?
    set -e
    if [ "$awg_install_rc" -eq 2 ]; then
        stop_for_kernel_reboot "new-kernel"
    elif [ "$awg_install_rc" -eq 3 ]; then
        stop_for_kernel_reboot "module"
    elif [ "$awg_install_rc" -ne 0 ]; then
        err "Установка AmneziaWG kernel module завершилась с ошибкой"
        exit "$awg_install_rc"
    fi

    if ! command -v awg-quick >/dev/null 2>&1; then
        err "Установщик завершился успешно, но awg-quick не найден"
        exit 1
    fi
    ok "AmneziaWG установлен, пакет актуален, kernel module работает"
}

header "Установка Docker и системных компонентов"
install_docker

SETUP_OFFLINE=0
if [ -n "$OFFLINE_RELEASE" ]; then
    OFFLINE_RELEASE="$(readlink -f "$OFFLINE_RELEASE")"
    [ -f "$OFFLINE_RELEASE" ] || { err "Full release не найден: $OFFLINE_RELEASE"; exit 1; }
    info "Проверяю full release и загружаю готовые Docker images..."
    RELEASE_WORK="$(mktemp -d)"
    (
        trap 'rm -rf "$RELEASE_WORK"' EXIT
        python3 -m tools.release_archive extract "$OFFLINE_RELEASE" "$RELEASE_WORK/content" >/dev/null
        docker image load -i "$RELEASE_WORK/content/kvn-vpn-images-linux-amd64.tar"
        python3 -m tools.release_archive verify-loaded "$RELEASE_WORK/content/release-manifest.json" >/dev/null
    )
    SETUP_OFFLINE=1
    ok "Семь release-образов загружены и проверены"
else
    warn "Full release не указан: setup может выполнять online build/pull. На сервере 1 ГБ используйте --release."
fi
ensure_compose
ensure_python3
ensure_qrencode
ensure_certbot
ensure_wireguard_tools
ensure_amneziawg_kernel_module

# ── Домены ────────────────────────────────────────────────────────────────

trim_csv_first() {
    local value="${1%%,*}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

normalize_optional_value() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    local lower="${value,,}"
    case "$lower" in
        "-"|"none"|"no"|"n"|"skip"|"нет")
            printf ''
            ;;
        *)
            printf '%s' "$value"
            ;;
    esac
}

validate_domain_csv_input() {
    python3 - "$1" <<'PY'
import json
import sys
from tools.kvnctl import validate_sni_domain

for item in sys.argv[1].split(","):
    domain = item.strip()
    if not domain:
        continue
    try:
        validate_sni_domain(domain)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from None
PY
}

validate_site_title_input() {
    python3 - "$1" <<'PY'
import sys
from tools.kvnctl import validate_site_title

try:
    validate_site_title(sys.argv[1])
except SystemExit as exc:
    print(exc, file=sys.stderr)
    raise SystemExit(1) from None
PY
}

prompt_domain_csv() {
    local target="$1"
    local prompt="$2"
    local default="$3"
    local entered=""
    local candidate=""
    local validation_error=""
    while true; do
        read -rp "$prompt [$default]: " entered
        if [ -n "$entered" ]; then
            candidate="$(normalize_optional_value "$entered")"
        else
            candidate="$default"
        fi
        if validation_error="$(validate_domain_csv_input "$candidate" 2>&1)"; then
            printf -v "$target" '%s' "$candidate"
            return
        fi
        err "$validation_error"
    done
}

prompt_site_title() {
    local target="$1"
    local prompt="$2"
    local default="$3"
    local entered=""
    local candidate=""
    local validation_error=""
    while true; do
        read -rp "$prompt [$default]: " entered
        candidate="${entered:-$default}"
        if validation_error="$(validate_site_title_input "$candidate" 2>&1)"; then
            printf -v "$target" '%s' "$candidate"
            return
        fi
        err "$validation_error"
    done
}

CURRENT_SITE_DOMAINS=$(python3 - <<'PY' 2>/dev/null || true
import json
try:
    state = json.load(open("users.json", encoding="utf-8"))
except Exception:
    state = {}
le = state.get("letsencrypt", {})
domains = le.get("domains") or ([le.get("domain")] if le.get("domain") else [])
print(",".join(d for d in domains if d))
PY
)
CURRENT_SITE_TITLE=$(python3 - <<'PY' 2>/dev/null || true
import json
try:
    state = json.load(open("users.json", encoding="utf-8"))
except Exception:
    state = {}
print(state.get("site", {}).get("title", "Сервисная страница"))
PY
)
CURRENT_SUB_HOST=$(python3 - <<'PY' 2>/dev/null || true
import json
try:
    state = json.load(open("users.json", encoding="utf-8"))
except Exception:
    state = {}
print(state.get("subscription", {}).get("public_host", ""))
PY
)
CURRENT_OCSERV_SNI=$(python3 - <<'PY' 2>/dev/null || true
import json
try:
    state = json.load(open("users.json", encoding="utf-8"))
except Exception:
    state = {}
print(state.get("ocserv", {}).get("sni", ""))
PY
)
CURRENT_OCSERV_ALIASES=$(python3 - <<'PY' 2>/dev/null || true
import json
try:
    state = json.load(open("users.json", encoding="utf-8"))
except Exception:
    state = {}
aliases = state.get("ocserv", {}).get("front_snis", [])
print(",".join(aliases if isinstance(aliases, list) else []))
PY
)

current_sni_field() {
    local system="$1"
    local field="$2"
    python3 - "$system" "$field" <<'PY' 2>/dev/null || true
import json
import sys

defaults = {
    "tls": ("www.microsoft.com", ["www.microsoft.com", "www.apple.com", "www.android.com"]),
    "reality-xhttp": ("github.com", ["github.com", "miu.com", "android.com", "cloudflare.com", "www.github.com", "www.bing.com"]),
    "reality-tcp": ("apple.com", ["apple.com"]),
    "hysteria": ("www.apple.com", ["www.apple.com", "gateway.icloud.com", "www.gstatic.com"]),
    "telemt": ("yandex.com", ["yandex.com", "www.yandex.com"]),
    "mtg": ("ya.ru", ["ya.ru"]),
}

system, field = sys.argv[1], sys.argv[2]
try:
    state = json.load(open("users.json", encoding="utf-8"))
except Exception:
    state = {}
route = state.get("sni_routes", {}).get(system, {})
default_sni, default_aliases = defaults[system]
if field == "default":
    print(route.get("default", default_sni) if isinstance(route, dict) else default_sni)
else:
    aliases = route.get("aliases", default_aliases) if isinstance(route, dict) else default_aliases
    print(",".join(aliases if isinstance(aliases, list) else default_aliases))
PY
}

CURRENT_SNI_TLS_DEFAULT="$(current_sni_field tls default)"
CURRENT_SNI_TLS_ALIASES="$(current_sni_field tls aliases)"
CURRENT_SNI_REALITY_XHTTP_DEFAULT="$(current_sni_field reality-xhttp default)"
CURRENT_SNI_REALITY_XHTTP_ALIASES="$(current_sni_field reality-xhttp aliases)"
CURRENT_SNI_REALITY_TCP_DEFAULT="$(current_sni_field reality-tcp default)"
CURRENT_SNI_REALITY_TCP_ALIASES="$(current_sni_field reality-tcp aliases)"
CURRENT_SNI_HYSTERIA_DEFAULT="$(current_sni_field hysteria default)"
CURRENT_SNI_HYSTERIA_ALIASES="$(current_sni_field hysteria aliases)"
CURRENT_SNI_TELEMT_DEFAULT="$(current_sni_field telemt default)"
CURRENT_SNI_TELEMT_ALIASES="$(current_sni_field telemt aliases)"
CURRENT_SNI_MTG_DEFAULT="$(current_sni_field mtg default)"
CURRENT_SNI_MTG_ALIASES="$(current_sni_field mtg aliases)"

SITE_DOMAINS="$CURRENT_SITE_DOMAINS"
SITE_TITLE="$CURRENT_SITE_TITLE"
SUB_PUBLIC_HOST="$CURRENT_SUB_HOST"
OCSERV_SNI_INPUT="$CURRENT_OCSERV_SNI"
OCSERV_ALIASES_INPUT="$CURRENT_OCSERV_ALIASES"
SETUP_SNI_CONFIGURE=0
SNI_TLS_DEFAULT="$CURRENT_SNI_TLS_DEFAULT"
SNI_TLS_ALIASES="$CURRENT_SNI_TLS_ALIASES"
SNI_REALITY_XHTTP_DEFAULT="$CURRENT_SNI_REALITY_XHTTP_DEFAULT"
SNI_REALITY_XHTTP_ALIASES="$CURRENT_SNI_REALITY_XHTTP_ALIASES"
SNI_REALITY_TCP_DEFAULT="$CURRENT_SNI_REALITY_TCP_DEFAULT"
SNI_REALITY_TCP_ALIASES="$CURRENT_SNI_REALITY_TCP_ALIASES"
SNI_HYSTERIA_DEFAULT="$CURRENT_SNI_HYSTERIA_DEFAULT"
SNI_HYSTERIA_ALIASES="$CURRENT_SNI_HYSTERIA_ALIASES"
SNI_TELEMT_DEFAULT="$CURRENT_SNI_TELEMT_DEFAULT"
SNI_TELEMT_ALIASES="$CURRENT_SNI_TELEMT_ALIASES"
SNI_MTG_DEFAULT="$CURRENT_SNI_MTG_DEFAULT"
SNI_MTG_ALIASES="$CURRENT_SNI_MTG_ALIASES"

prompt_sni_route() {
    local label="$1"
    local prefix="$2"
    local current_default_var="CURRENT_SNI_${prefix}_DEFAULT"
    local current_aliases_var="CURRENT_SNI_${prefix}_ALIASES"
    local default_var="SNI_${prefix}_DEFAULT"
    local aliases_var="SNI_${prefix}_ALIASES"
    local current_default="${!current_default_var}"
    local current_aliases="${!current_aliases_var}"

    prompt_domain_csv "$default_var" "SNI ${label} default" "$current_default"
    prompt_domain_csv "$aliases_var" "SNI ${label} aliases через запятую" "$current_aliases"
}

if [ -t 0 ]; then
    echo ""
    separator
    info "Настройка доменных имён"
    separator
    echo -e "  ${D}Enter — оставить значение по умолчанию; '-' или 'none' — пропустить домены.${R}"
    prompt_domain_csv SITE_DOMAINS "Домены сайта через запятую, если есть" "$CURRENT_SITE_DOMAINS"
    prompt_site_title SITE_TITLE "Надпись на сайте" "$CURRENT_SITE_TITLE"
    if [ -n "$SITE_DOMAINS" ]; then
        prompt_domain_csv SUB_PUBLIC_HOST "Домен подписки Happ на 443, если есть" "$CURRENT_SUB_HOST"
        prompt_domain_csv OCSERV_SNI_INPUT "Домен OpenConnect/ocserv, если есть" "$CURRENT_OCSERV_SNI"
        prompt_domain_csv OCSERV_ALIASES_INPUT "Дополнительные ocserv SNI через запятую" "$CURRENT_OCSERV_ALIASES"
    else
        SUB_PUBLIC_HOST=""
        OCSERV_SNI_INPUT=""
        OCSERV_ALIASES_INPUT=""
    fi

    echo ""
    if prompt_yes_no "Настроить SNI сервисов? Enter/N — оставить текущие/стандартные, y — изменить: " "n"; then
        SETUP_SNI_CONFIGURE=1
        prompt_sni_route "VLESS TLS" TLS
        prompt_sni_route "Reality xHTTP" REALITY_XHTTP
        prompt_sni_route "Reality TCP" REALITY_TCP
        prompt_sni_route "Hysteria 2" HYSTERIA
        prompt_sni_route "Telemt" TELEMT
        prompt_sni_route "mtg FakeTLS" MTG
    fi
fi

SERVER_HOST="$SERVER_IP"
PRIMARY_SITE_DOMAIN="$(trim_csv_first "$SITE_DOMAINS")"
if [ -n "$PRIMARY_SITE_DOMAIN" ]; then
    SERVER_HOST="$PRIMARY_SITE_DOMAIN"
fi

export SETUP_SERVER_HOST="$SERVER_HOST"
export SETUP_SITE_DOMAINS="$SITE_DOMAINS"
export SETUP_SITE_TITLE="$SITE_TITLE"
export SETUP_SUB_PUBLIC_HOST="$SUB_PUBLIC_HOST"
export SETUP_OCSERV_SNI="$OCSERV_SNI_INPUT"
export SETUP_OCSERV_ALIASES="$OCSERV_ALIASES_INPUT"
export SETUP_SNI_CONFIGURE
export SETUP_SNI_TLS_DEFAULT="$SNI_TLS_DEFAULT"
export SETUP_SNI_TLS_ALIASES="$SNI_TLS_ALIASES"
export SETUP_SNI_REALITY_XHTTP_DEFAULT="$SNI_REALITY_XHTTP_DEFAULT"
export SETUP_SNI_REALITY_XHTTP_ALIASES="$SNI_REALITY_XHTTP_ALIASES"
export SETUP_SNI_REALITY_TCP_DEFAULT="$SNI_REALITY_TCP_DEFAULT"
export SETUP_SNI_REALITY_TCP_ALIASES="$SNI_REALITY_TCP_ALIASES"
export SETUP_SNI_HYSTERIA_DEFAULT="$SNI_HYSTERIA_DEFAULT"
export SETUP_SNI_HYSTERIA_ALIASES="$SNI_HYSTERIA_ALIASES"
export SETUP_SNI_TELEMT_DEFAULT="$SNI_TELEMT_DEFAULT"
export SETUP_SNI_TELEMT_ALIASES="$SNI_TELEMT_ALIASES"
export SETUP_SNI_MTG_DEFAULT="$SNI_MTG_DEFAULT"
export SETUP_SNI_MTG_ALIASES="$SNI_MTG_ALIASES"
python3 - <<'PY'
import json
import os
import re
from pathlib import Path

path = Path("users.json")
try:
    state = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    state = {}

host_re = re.compile(r"^[A-Za-z0-9.-]{1,253}$")

def split_domains(value):
    result = []
    for item in (value or "").split(","):
        domain = item.strip().lower().rstrip(".")
        if not domain:
            continue
        if not host_re.match(domain) or ".." in domain:
            raise SystemExit(f"Невалидный домен: {domain}")
        if domain not in result:
            result.append(domain)
    return result

server_host = os.environ["SETUP_SERVER_HOST"].strip()
site_domains = split_domains(os.environ.get("SETUP_SITE_DOMAINS", ""))
site_title = os.environ.get("SETUP_SITE_TITLE", "").strip() or "Сервисная страница"
sub_host = split_domains(os.environ.get("SETUP_SUB_PUBLIC_HOST", ""))
ocserv_sni = split_domains(os.environ.get("SETUP_OCSERV_SNI", ""))
ocserv_aliases = split_domains(os.environ.get("SETUP_OCSERV_ALIASES", ""))
sni_configure = os.environ.get("SETUP_SNI_CONFIGURE") == "1"

if len(site_title) > 80:
    raise SystemExit("Надпись сайта не должна быть длиннее 80 символов")
if any(ord(ch) < 32 for ch in site_title):
    raise SystemExit("Надпись сайта не должна содержать управляющие символы")

state["server"] = server_host
state.setdefault("users", [])
state.setdefault("site", {})["title"] = site_title

if sni_configure:
    default_snis = {
        "tls": "www.microsoft.com",
        "reality-xhttp": "github.com",
        "reality-tcp": "apple.com",
        "hysteria": "www.apple.com",
        "telemt": "yandex.com",
        "mtg": "ya.ru",
    }
    default_dests = {
        "tls": "xray:443",
        "reality-xhttp": "xray:2053",
        "reality-tcp": "xray:2054",
        "hysteria": "hysteria:443",
        "telemt": "telemt:3129",
        "mtg": "mtg:3128",
    }
    env_names = {
        "tls": "TLS",
        "reality-xhttp": "REALITY_XHTTP",
        "reality-tcp": "REALITY_TCP",
        "hysteria": "HYSTERIA",
        "telemt": "TELEMT",
        "mtg": "MTG",
    }
    routes = state.setdefault("sni_routes", {})
    for system, env_name in env_names.items():
        default_value = split_domains(os.environ.get(f"SETUP_SNI_{env_name}_DEFAULT", "")) or [default_snis[system]]
        aliases = split_domains(os.environ.get(f"SETUP_SNI_{env_name}_ALIASES", "")) or [default_value[0]]
        if default_value[0] not in aliases:
            aliases.insert(0, default_value[0])
        route = routes.setdefault(system, {})
        route["default"] = default_value[0]
        route["dest"] = route.get("dest") or default_dests[system]
        route["aliases"] = aliases

sub = state.setdefault("subscription", {})
sub.setdefault("enabled", True)
sub.setdefault("port", 2096)
if sub_host:
    sub["public_host"] = sub_host[0]
    sub["public_port"] = 443
else:
    sub.pop("public_host", None)
    sub.pop("public_port", None)

le = state.setdefault("letsencrypt", {})
if site_domains:
    for domain in sub_host:
        if domain not in site_domains:
            site_domains.append(domain)
    le["enabled"] = True
    le["domain"] = site_domains[0]
    le["domains"] = site_domains
else:
    le["enabled"] = False
    le.pop("domain", None)
    le.pop("domains", None)

oc = state.setdefault("ocserv", {})
oc.setdefault("enabled", True)
oc.setdefault("dtls_enabled", True)
oc.setdefault("udp_port", 4443)
oc.setdefault("network", "10.77.77.0/24")
oc.setdefault("dns", ["1.1.1.1", "8.8.8.8"])
oc.setdefault("mtu", 1280)
if ocserv_sni:
    oc["enabled"] = True
    oc["sni_enabled"] = True
    oc["sni"] = ocserv_sni[0]
    oc["front_snis"] = [d for d in ocserv_aliases if d != ocserv_sni[0]]
else:
    oc["sni_enabled"] = False
    oc.pop("sni", None)
    oc["front_snis"] = ocserv_aliases

path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY

# ── Web-портал ───────────────────────────────────────────────────────────
repair_portal_gateway_config_target() {
    local target="./nginx/portal-gateway.conf"
    if [ ! -d "$target" ]; then
        return
    fi
    if [ -n "$(find "$target" -mindepth 1 -print -quit)" ]; then
        err "$target должен быть файлом, но является непустым каталогом; проверьте содержимое вручную"
        exit 1
    fi
    docker rm -f kvn-portal-gateway >/dev/null 2>&1 || true
    rmdir "$target"
    warn "удалён пустой каталог $target, созданный Docker вместо файла конфигурации"
}

repair_portal_gateway_config_target

if [ -t 0 ]; then
    echo ""
    separator
    info "Настройка web-портала (HTTPS, custom path, защита входа)"
    separator
    python3 ./tools/kvnctl.py portal configure
else
    info "Неинтерактивный setup сохраняет текущую конфигурацию web-портала"
fi

# ── AmneziaWG ─────────────────────────────────────────────────────────────

if [ -f docker-compose.override.yml ]; then
    if grep -Eq "docker-amneziawg-disabled|^[[:space:]]*amneziawg:" docker-compose.override.yml; then
        warn "Удаляю устаревший docker-compose.override.yml: AmneziaWG больше не запускается в Docker."
        rm -f docker-compose.override.yml
    else
        warn "Найден docker-compose.override.yml. setup использует только docker-compose.yml; проверьте override вручную."
    fi
fi

# ── Интерактивный мастер управления пользователями ─────────────────────
if [ -t 0 ]; then
    echo ""
    if prompt_yes_no "Запустить интерактивный мастер для управления пользователями? (y/N): " "n"; then
        python3 ./tools/kvnctl.py interactive --server "$SERVER_HOST" --no-restart-on-exit
    fi
fi

# Проверка: есть ли пользователи в users.json
USER_COUNT=$(python3 -c "import json; print(len(json.load(open('users.json')).get('users', [])))" 2>/dev/null || echo "0")
if [ "$USER_COUNT" -eq 0 ]; then
    warn "В users.json нет пользователей!"
    echo ""
    echo "  Без пользователей сервисы не будут работать корректно."
    echo "  Создайте хотя бы одного пользователя:"
    echo ""
    echo "    python3 tools/kvnctl.py add-user User1 --systems tls,reality-xhttp,reality-tcp,hysteria,telemt,mtg,amneziawg,wireguard,ocserv"
    echo ""
    if prompt_yes_no "Создать тестового пользователя 'User1' со всеми системами? (y/N): " "n"; then
        python3 ./tools/kvnctl.py add-user User1 --systems tls,reality-xhttp,reality-tcp,hysteria,telemt,mtg,amneziawg,wireguard,ocserv --server "$SERVER_HOST"
    else
        err "Пользователи не созданы. Запустите setup.sh заново после добавления пользователей."
        exit 1
    fi
fi

echo ""
separator
info "Генерация сертификатов и конфигов"
separator

# Сохраняем inode bind-mounted каталогов: работающие контейнеры должны увидеть новые файлы.
mkdir -p certs site-certs ocserv/certs hy2/certs

# Каталог для файлов подписки (раздаётся nginx по HTTPS-эндпоинту)
mkdir -p nginx/web
mkdir -p amneziawg wireguard ocserv

# kvnctl.py делает всё: сертификаты с SAN, nginx, xray, hysteria, telemt, mtg, amneziawg, wireguard, ocserv, клиенты
python3 ./tools/kvnctl.py render --server "$SERVER_HOST" --certs

PORTAL_DOMAIN=$(python3 -c "import json; print(json.load(open('users.json')).get('portal', {}).get('domain', ''))")
PORTAL_PORT=$(python3 -c "import json; print(json.load(open('users.json')).get('portal', {}).get('port', 8443))")
PORTAL_HOST_KIND=$(python3 -c "import json,ipaddress; h=json.load(open('users.json')).get('portal', {}).get('domain', ''); print('ipv4' if h and isinstance(ipaddress.ip_address(h), ipaddress.IPv4Address) else 'domain')" 2>/dev/null || echo domain)
PORTAL_PUBLIC_READY=0

PORTAL_GID=10001
EFFECTIVE_DOCKER_SERVICES=()
DISABLED_DOCKER_SERVICES=()
EFFECTIVE_HOST_SERVICES=()
DISABLED_HOST_SERVICES=()
EFFECTIVE_COMPOSE_PROFILES=()
PORTAL_RUNTIME_ENABLED=0
while IFS=$'\t' read -r key value; do
    case "$key" in
        docker-enabled) IFS=',' read -r -a EFFECTIVE_DOCKER_SERVICES <<< "$value" ;;
        docker-disabled) IFS=',' read -r -a DISABLED_DOCKER_SERVICES <<< "$value" ;;
        host-enabled) IFS=',' read -r -a EFFECTIVE_HOST_SERVICES <<< "$value" ;;
        host-disabled) IFS=',' read -r -a DISABLED_HOST_SERVICES <<< "$value" ;;
        compose-profiles) IFS=',' read -r -a EFFECTIVE_COMPOSE_PROFILES <<< "$value" ;;
        portal-agent) PORTAL_RUNTIME_ENABLED="$value" ;;
    esac
done < <(python3 ./tools/kvnctl.py service-plan --format lines)

service_enabled_in() {
    local wanted="$1"
    shift
    local service
    for service in "$@"; do
        [ "$service" = "$wanted" ] && return 0
    done
    return 1
}

if [ "$PORTAL_RUNTIME_ENABLED" = "1" ]; then
    if [ "$PORTAL_PORT" = "443" ]; then
        warn "На общем L4-порту 443 backend видит адрес SNI-router: блокировка после 5 ошибок будет общей. Для точной IP-блокировки выберите custom port."
    elif ss -ltnH "( sport = :$PORTAL_PORT )" 2>/dev/null | grep -q . \
        && [ "$(docker inspect -f '{{.State.Running}}' kvn-portal-gateway 2>/dev/null || true)" != "true" ]; then
        err "Выбранный порт портала $PORTAL_PORT/tcp уже занят"
        exit 1
    fi
    if [ "$PORTAL_HOST_KIND" = "ipv4" ]; then
        echo ""
        separator
        info "HTTPS-сертификат web-портала по IP"
        separator
        if [ "$PORTAL_DOMAIN" != "$SERVER_IP" ]; then
            err "IP портала $PORTAL_DOMAIN не совпадает с публичным IP сервера $SERVER_IP"
            exit 1
        fi
        if python3 - <<'PY'
from tools import kvnctl
raise SystemExit(0 if kvnctl.certbot_supports_ip_certificates() else 1)
PY
        then
            if python3 - <<'PY'
from tools import kvnctl
state = kvnctl.load_state()
portal = kvnctl.portal_config(state)
ip = portal["domain"]
email = kvnctl.letsencrypt_config(state).get("email", "")
kvnctl.run_certbot_issue_ip(ip, email=email or None)
kvnctl.deploy_letsencrypt_ip_certificate(state, ip, restart=False)
PY
            then
                ok "Доверенный short-lived Let's Encrypt IP-сертификат установлен"
            else
                warn "Let's Encrypt IP-сертификат не выпущен; проверяю explicit self-signed fallback"
            fi
        else
            warn "Certbot ниже 5.4: IP-сертификат Let's Encrypt пропущен; unstable/PyPI не подключаются"
        fi
        PORTAL_PUBLIC_READY=$(python3 - <<'PY'
from tools import kvnctl
print("1" if kvnctl.portal_public_ready(kvnctl.load_state()) else "0")
PY
)
        if [ "$PORTAL_PUBLIC_READY" = "1" ]; then
            ok "HTTPS route по IP готов; Host/path/login/secret protections включены"
        else
            warn "IP route закрыт: разрешите self-signed fallback или установите сертификат с совпадающим IP SAN"
            echo "  python3 tools/kvnctl.py portal configure --enable true --domain $SERVER_IP --port $PORTAL_PORT --allow-self-signed-ip true"
        fi
    else
        echo ""
        separator
        info "Обязательный сертификат Let's Encrypt для web-портала"
        separator
        DNS_READY=0
        if getent ahosts "$PORTAL_DOMAIN" 2>/dev/null | awk '{print $1}' | grep -Fxq "$SERVER_IP"; then
            DNS_READY=1
        else
            warn "DNS $PORTAL_DOMAIN пока не указывает на $SERVER_IP"
        fi
        if ss -ltnH '( sport = :80 )' 2>/dev/null | grep -q .; then
            warn "80/tcp уже занят: если это nginx проекта, Certbot временно остановит его; иначе выпуск может не пройти"
        fi
        if [ "$DNS_READY" = "1" ]; then
        if python3 - <<'PY'
from tools import kvnctl

state = kvnctl.load_state()
portal = kvnctl.portal_config(state)
portal_domain = portal["domain"]
if not kvnctl.letsencrypt_eligible_domain(portal_domain):
    raise SystemExit(f"Домен портала не подходит для публичного Let's Encrypt: {portal_domain}")

domains = kvnctl.letsencrypt_target_domains(state, "site")
domains = [portal_domain, *[domain for domain in domains if domain != portal_domain]]
if not domains:
    domains = [portal_domain]
email = kvnctl.letsencrypt_config(state).get("email", "")

try:
    kvnctl.run_certbot_issue(domains, email=email or None)
    issued_domains = domains
except SystemExit:
    if len(domains) <= 1:
        raise
    kvnctl.warn(
        "общий site-сертификат не выпущен; пробую отдельный сертификат только для web-портала"
    )
    kvnctl.run_certbot_issue([portal_domain], email=email or None)
    issued_domains = [portal_domain]

kvnctl.deploy_letsencrypt_certificate(state, issued_domains, restart=False, target="site")
kvnctl.save_state(state)
PY
            then
                PORTAL_PUBLIC_READY=1
                ok "Let's Encrypt выпущен; публичный route портала разрешён"
            else
                warn "Let's Encrypt не выпущен; публичный route портала остаётся закрытым"
            fi
        fi
        PORTAL_PUBLIC_READY=$(python3 - <<'PY'
from tools import kvnctl
print("1" if kvnctl.portal_public_ready(kvnctl.load_state()) else "0")
PY
)
        if [ "$PORTAL_PUBLIC_READY" != "1" ]; then
            echo "  Повтор после исправления DNS и открытия 80/tcp:"
            echo "  ./setup.sh $SERVER_IP"
        fi
    fi
fi

if [ "$PORTAL_RUNTIME_ENABLED" = "1" ]; then
    echo ""
    separator
    info "Установка защищённого host-agent web-портала"
    separator
    bash ./portal/install-host-agent.sh
    PORTAL_GID=$(getent group kvn-portal | cut -d: -f3)
    install -d -o 10001 -g "$PORTAL_GID" -m 0700 portal-data
    install -d -o 10001 -g "$PORTAL_GID" -m 0700 portal-data/updates
    install -d -o root -g "$PORTAL_GID" -m 0750 portal-runtime
    install -d -o root -g "$PORTAL_GID" -m 0750 /backup
    if [ -f portal-runtime/users.json ]; then
        chown root:"$PORTAL_GID" portal-runtime/users.json
        chmod 0640 portal-runtime/users.json
    fi
elif systemctl list-unit-files kvn-portal-agent.service >/dev/null 2>&1; then
    systemctl disable --now kvn-portal-agent.service || true
fi

COMPOSE_PROFILE_LIST="$(IFS=','; echo "${EFFECTIVE_COMPOSE_PROFILES[*]}")"
python3 - "$PORTAL_GID" "$PORTAL_PORT" "$COMPOSE_PROFILE_LIST" <<'PY'
import sys
from pathlib import Path
from tools.kvnlib import atomic_write_text

gid, port, profiles = sys.argv[1:]
state = json.loads(Path("users.json").read_text(encoding="utf-8"))
mtg = state.get("mtg", {}) if isinstance(state.get("mtg"), dict) else {}
route = state.get("sni_routes", {}).get("mtg", {})
alias = route.get("default", "mtg-decoy.invalid") if mtg.get("camouflage_origin", "external") == "local-site" else "mtg-decoy.invalid"
atomic_write_text(
    Path(".env"),
    f"KVN_PORTAL_GID={gid}\nKVN_PORTAL_PORT={port}\nCOMPOSE_PROFILES={profiles}\nKVN_MTG_CAMOUFLAGE_HOST={alias}\n",
    mode=0o600,
)
PY

echo ""
separator
info "Настройка автопродления Let's Encrypt"
separator

if command -v systemctl >/dev/null 2>&1; then
    python3 ./tools/kvnctl.py letsencrypt install-renewal || warn "Не удалось установить timer автопродления Let's Encrypt"
else
    warn "systemctl не найден — timer автопродления Let's Encrypt не установлен"
fi

# Удаляем временные файлы openssl (остаются после генерации сертификатов)
find . -name "openssl.cnf" -delete 2>/dev/null || true

echo ""
separator
info "Проверка конфигурации Xray"
separator

if service_enabled_in xray "${EFFECTIVE_DOCKER_SERVICES[@]}" \
    && command -v docker >/dev/null 2>&1; then
    if docker run --rm --entrypoint xray \
        -v "$SCRIPT_DIR/xray/config.json:/etc/xray/config.json:ro" \
        -v "$SCRIPT_DIR/certs:/etc/xray/certs:ro" \
        ghcr.io/xtls/xray-core:26.3.27 run -test -c /etc/xray/config.json 2>/dev/null; then
        ok "Конфигурация Xray валидна"
    else
        warn "Проверка Xray не удалась — возможно образ ещё скачивается"
    fi
fi

echo ""
separator
info "Настройка точных прав на файлы и Docker volume mounts"
separator
python3 ./tools/kvnctl.py render
[ -f ./users.json ] && chmod 0600 ./users.json || true
[ -d ./clients ] && chmod 0700 ./clients && find ./clients -type d -exec chmod 0700 {} + -o -type f -exec chmod 0600 {} + 2>/dev/null || true
if [ "$PORTAL_RUNTIME_ENABLED" = "1" ]; then
    chmod 0700 ./portal-data
    install -d -o root -g kvn-portal -m 0750 ./portal-runtime
    if [ -f ./portal-runtime/users.json ]; then
        chown root:kvn-portal ./portal-runtime/users.json
        chmod 0640 ./portal-runtime/users.json
    fi
fi
find ./amneziawg -maxdepth 1 -name "*.sh" -exec chmod 755 {} + 2>/dev/null || true
find ./wireguard -maxdepth 1 -name "*.sh" -exec chmod 755 {} + 2>/dev/null || true
find ./ocserv -maxdepth 1 -name "*.sh" -exec chmod 755 {} + 2>/dev/null || true
find ./tools -maxdepth 1 -name "*.sh" -exec chmod 755 {} + 2>/dev/null || true
ok "Права на файлы установлены по матрице секретных и public paths"

echo ""
separator
info "Применение lifecycle AmneziaWG"
separator
if service_enabled_in amneziawg "${EFFECTIVE_HOST_SERVICES[@]}"; then
    if ! command -v awg-quick >/dev/null 2>&1; then
        err "awg-quick пропал после ранней проверки. Заново запустите setup и проверьте установку AmneziaWG."
        exit 1
    fi
    bash ./amneziawg/install-host-service.sh
elif systemctl list-unit-files kvn-amneziawg.service >/dev/null 2>&1; then
    systemctl disable --now kvn-amneziawg.service
    ok "AmneziaWG отключён согласно users.json"
fi

echo ""
separator
info "Применение lifecycle стандартного WireGuard"
separator
if service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}"; then
    if ! command -v wg-quick >/dev/null 2>&1 || ! command -v wg >/dev/null 2>&1; then
        err "wg/wg-quick пропали после ранней проверки. Заново запустите setup и проверьте wireguard-tools."
        exit 1
    fi
    bash ./wireguard/install-host-service.sh
elif systemctl list-unit-files kvn-wireguard.service >/dev/null 2>&1; then
    systemctl disable --now kvn-wireguard.service
    ok "WireGuard отключён согласно users.json"
fi

echo ""
separator
info "Запуск сервисов"
separator

COMPOSE_PROFILE_ARGS=()
for profile in "${EFFECTIVE_COMPOSE_PROFILES[@]}"; do
    [ -n "$profile" ] && COMPOSE_PROFILE_ARGS+=(--profile "$profile")
done

compose_cmd() {
    docker compose -f docker-compose.yml "${COMPOSE_PROFILE_ARGS[@]}" "$@"
}

REQUIRED_DOCKER_SERVICES=("${EFFECTIVE_DOCKER_SERVICES[@]}")

verify_compose_services() {
    local missing=()
    local service available
    if ! available="$(compose_cmd config --services)"; then
        err "Не удалось прочитать список сервисов docker compose"
        exit 1
    fi
    for service in "${REQUIRED_DOCKER_SERVICES[@]}"; do
        if ! grep -Fxq "$service" <<< "$available"; then
            missing+=("$service")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        err "В docker compose отсутствуют сервисы: ${missing[*]}"
        echo "Найденные сервисы:"
        printf '%s\n' "$available"
        echo ""
        echo "Проверьте, что в текущей папке есть полный docker-compose.yml из deploy-пакета."
        exit 1
    fi
    ok "Compose содержит Docker-сервисы: ${REQUIRED_DOCKER_SERVICES[*]}"
}

wait_for_required_services() {
    local attempt service missing running
    for attempt in $(seq 1 30); do
        running="$(compose_cmd ps --status running --services 2>/dev/null || true)"
        missing=()
        for service in "${REQUIRED_DOCKER_SERVICES[@]}"; do
            if ! grep -Fxq "$service" <<< "$running"; then
                missing+=("$service")
            fi
        done
        if [ "${#missing[@]}" -eq 0 ]; then
            ok "Все Docker-контейнеры запущены: ${REQUIRED_DOCKER_SERVICES[*]}"
            return 0
        fi
        sleep 2
    done

    err "Не все контейнеры перешли в running: ${missing[*]}"
    compose_cmd ps || true
    echo ""
    echo "Логи проблемных сервисов:"
    for service in "${missing[@]}"; do
        compose_cmd logs --tail=80 "$service" || true
    done
    exit 1
}

repair_stale_bind_mounts() {
    local service="$1"
    shift
    local host_path container_path host_hash container_hash container_id stale=0
    container_id="$(compose_cmd ps -q "$service" 2>/dev/null || true)"
    if ! compose_cmd ps --status running --services 2>/dev/null | grep -Fxq "$service"; then
        stale=1
    fi
    while [ "$#" -ge 2 ]; do
        host_path="$1"
        container_path="$2"
        shift 2
        [ -f "$host_path" ] || continue
        host_hash="$(sha256sum "$host_path" | awk '{print $1}')"
        container_hash="$(docker cp "$container_id:$container_path" - 2>/dev/null | tar -xO 2>/dev/null | sha256sum | awk '{print $1}' || true)"
        if [ "$host_hash" != "$container_hash" ]; then
            stale=1
        fi
    done
    if [ "$stale" = "1" ]; then
        warn "$service видит устаревший bind mount; выполняю точечный recreate"
        compose_cmd up -d --no-deps --force-recreate "$service"
    fi
}

verify_amneziawg_host_service() {
    local interface
    interface="$(python3 -c "import json; print(json.load(open('users.json')).get('amneziawg', {}).get('interface', 'awg0'))" 2>/dev/null || echo awg0)"
    if ! systemctl is-active --quiet kvn-amneziawg.service; then
        err "AmneziaWG host-служба не active"
        systemctl --no-pager --full status kvn-amneziawg.service || true
        exit 1
    fi
    if ! ip link show "$interface" >/dev/null 2>&1; then
        err "AmneziaWG-служба active, но интерфейс $interface отсутствует"
        systemctl --no-pager --full status kvn-amneziawg.service || true
        exit 1
    fi
    if command -v awg >/dev/null 2>&1 && ! awg show "$interface" >/dev/null 2>&1; then
        err "Интерфейс $interface найден, но awg не может прочитать его состояние"
        exit 1
    fi
    ok "AmneziaWG host-служба active, интерфейс $interface поднят"
    if ! python3 tools/kvnctl.py amneziawg verify; then
        err "AmneziaWG peers не совпадают с users.json/project/host/runtime"
        echo "Диагностика: python3 tools/kvnctl.py amneziawg diagnose"
        echo "Журнал: journalctl -u kvn-amneziawg.service -n 100 --no-pager"
        exit 1
    fi
}

verify_wireguard_host_service() {
    local interface
    interface="$(python3 -c "import json; print(json.load(open('users.json')).get('wireguard', {}).get('interface', 'wg0'))" 2>/dev/null || echo wg0)"
    if ! systemctl is-active --quiet kvn-wireguard.service; then
        err "WireGuard host-служба не active"
        systemctl --no-pager --full status kvn-wireguard.service || true
        exit 1
    fi
    if ! ip link show "$interface" >/dev/null 2>&1; then
        err "WireGuard-служба active, но интерфейс $interface отсутствует"
        systemctl --no-pager --full status kvn-wireguard.service || true
        exit 1
    fi
    if command -v wg >/dev/null 2>&1 && ! wg show "$interface" >/dev/null 2>&1; then
        err "Интерфейс $interface найден, но wg не может прочитать его состояние"
        exit 1
    fi
    ok "WireGuard host-служба active, интерфейс $interface поднят"
    if ! python3 tools/kvnctl.py wireguard verify; then
        err "WireGuard peers не совпадают с users.json/project/host/runtime"
        echo "Диагностика: python3 tools/kvnctl.py wireguard diagnose"
        echo "Журнал: journalctl -u kvn-wireguard.service -n 100 --no-pager"
        exit 1
    fi
}

verify_portal_agent_bridge() {
    if [ "$PORTAL_RUNTIME_ENABLED" != "1" ]; then
        return
    fi
    local attempt
    for attempt in $(seq 1 20); do
        if systemctl is-active --quiet kvn-portal-agent.service \
            && [ -S /run/kvn-portal/control.sock ]; then
            break
        fi
        sleep 0.25
    done
    if ! systemctl is-active --quiet kvn-portal-agent.service \
        || [ ! -S /run/kvn-portal/control.sock ]; then
        err "host-agent портала не active или не создал Unix-сокет"
        systemctl --no-pager --full status kvn-portal-agent.service || true
        journalctl -u kvn-portal-agent.service -n 50 --no-pager || true
        exit 1
    fi
    for attempt in $(seq 1 10); do
        if compose_cmd exec -T portal python -c \
            'from pathlib import Path; from agent_client import AgentClient; secret=Path("/run/secrets/agent-token").read_text(encoding="utf-8").strip(); client=AgentClient(Path("/run/kvn-portal/control.sock"), secret, timeout=5); health=client.call("health.host", {}); current=client.call("metrics.current", {}); history=client.call("metrics.history", {"range_hours":1,"step":1}); assert all(isinstance(value, dict) for value in (health,current,history)); assert history.get("range_hours")==1' \
            >/dev/null 2>&1; then
            ok "portal → host-agent health и metrics RPC работают"
            return
        fi
        sleep 0.5
    done
    err "контейнер portal не может обратиться к host-agent"
    compose_cmd exec -T portal id || true
    compose_cmd exec -T portal ls -ld /run/kvn-portal /run/kvn-portal/control.sock /run/secrets/agent-token || true
    systemctl --no-pager --full status kvn-portal-agent.service || true
    exit 1
}

verify_portal_public_https() {
    if [ "$PORTAL_RUNTIME_ENABLED" != "1" ] || [ "$PORTAL_PUBLIC_READY" != "1" ]; then
        return
    fi
    local suffix="" url cert_source attempt response
    [ "$PORTAL_PORT" != "443" ] && suffix=":$PORTAL_PORT"
    url="https://${PORTAL_DOMAIN}${suffix}$(python3 -c "import json; print(json.load(open('users.json'))['portal']['path'])")/login"
    cert_source="$(python3 -c "from tools import kvnctl; print(kvnctl.certificate_source(kvnctl.SITE_CERTS_DIR / 'server.crt'))")"
    local curl_tls=()
    [ "$cert_source" = "self-signed" ] && curl_tls=(-k)
    for attempt in $(seq 1 20); do
        response="$(curl -fsS "${curl_tls[@]}" --resolve "${PORTAL_DOMAIN}:${PORTAL_PORT}:127.0.0.1" --max-time 5 "$url" 2>/dev/null || true)"
        if grep -q '<form' <<<"$response" && grep -q 'csrf_token' <<<"$response"; then
            ok "HTTPS login web-портала доступен: $url"
            return
        fi
        sleep 0.5
    done
    err "HTTPS route портала отмечен готовым, но login page не открывается: $url"
    compose_cmd logs --tail 80 portal portal-gateway || true
    exit 1
}

verify_compose_services
if [ "${#DISABLED_DOCKER_SERVICES[@]}" -gt 0 ]; then
    docker compose -f docker-compose.yml --profile portal --profile portal-custom \
        stop "${DISABLED_DOCKER_SERVICES[@]}"
fi
if [ "${#REQUIRED_DOCKER_SERVICES[@]}" -gt 0 ]; then
    if [ "$SETUP_OFFLINE" = "1" ]; then
        compose_cmd up -d --no-build --pull never --remove-orphans "${REQUIRED_DOCKER_SERVICES[@]}"
    else
        compose_cmd up -d --build --remove-orphans "${REQUIRED_DOCKER_SERVICES[@]}"
    fi
fi
if service_enabled_in nginx "${REQUIRED_DOCKER_SERVICES[@]}"; then
    repair_stale_bind_mounts nginx \
        nginx/nginx.conf /etc/nginx/nginx.conf \
        nginx/site/index.html /var/www/site/index.html \
        site-certs/server.crt /etc/nginx/certs/server.crt
fi
service_enabled_in xray "${REQUIRED_DOCKER_SERVICES[@]}" && repair_stale_bind_mounts xray xray/config.json /etc/xray/config.json certs/server.crt /etc/xray/certs/server.crt
service_enabled_in hysteria "${REQUIRED_DOCKER_SERVICES[@]}" && repair_stale_bind_mounts hysteria hy2/config.yaml /etc/hysteria/config.yaml hy2/certs/server.crt /etc/hysteria/certs/server.crt
service_enabled_in telemt "${REQUIRED_DOCKER_SERVICES[@]}" && repair_stale_bind_mounts telemt telemt/config.toml /app/config.toml
service_enabled_in mtg "${REQUIRED_DOCKER_SERVICES[@]}" && repair_stale_bind_mounts mtg mtg/config.toml /config.toml
service_enabled_in ocserv "${REQUIRED_DOCKER_SERVICES[@]}" && repair_stale_bind_mounts ocserv ocserv/ocserv.conf /etc/ocserv/ocserv.conf ocserv/certs/server.crt /etc/ocserv/certs/server.crt
if [ "$PORTAL_RUNTIME_ENABLED" = "1" ]; then
    repair_stale_bind_mounts portal portal-runtime/users.json /project/runtime/users.json
    if service_enabled_in portal-gateway "${REQUIRED_DOCKER_SERVICES[@]}"; then
        repair_stale_bind_mounts portal-gateway \
            nginx/portal-gateway.conf /etc/nginx/nginx.conf \
            site-certs/server.crt /etc/nginx/certs/server.crt
    fi
fi
wait_for_required_services
service_enabled_in amneziawg "${EFFECTIVE_HOST_SERVICES[@]}" && verify_amneziawg_host_service
service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}" && verify_wireguard_host_service
if [ "$PORTAL_RUNTIME_ENABLED" = "1" ]; then
    verify_portal_agent_bridge
    verify_portal_public_https
fi

echo ""
header "KVN VPN v3 настроен и запущен!"
echo ""
echo -e "  ${B}IP:${R}        $SERVER_IP"
echo -e "  ${B}Сервер:${R}    $SERVER_HOST"
SUB_PORT=$(python3 -c "import json; print(json.load(open('users.json')).get('subscription', {}).get('port', 2096))" 2>/dev/null || echo "2096")
SITE_DOMAINS_OUT=$(python3 -c "import json; s=json.load(open('users.json')); print(','.join(s.get('letsencrypt', {}).get('domains', []) or []))" 2>/dev/null || true)
SUB_PUBLIC_OUT=$(python3 -c "import json; print(json.load(open('users.json')).get('subscription', {}).get('public_host', ''))" 2>/dev/null || true)
OCSERV_DOMAINS_OUT=$(python3 -c "import json; s=json.load(open('users.json')); oc=s.get('ocserv', {}); domains=[]; sni=oc.get('sni'); aliases=oc.get('front_snis', []); domains += [sni] if sni else []; domains += aliases if isinstance(aliases, list) else []; print(','.join(d for d in domains if d))" 2>/dev/null || true)
SERVICE_SNIS_OUT=$(python3 -c "import json; s=json.load(open('users.json')); r=s.get('sni_routes', {}); keys=['tls','reality-xhttp','reality-tcp','hysteria','telemt','mtg']; print('; '.join(f'{k}='+r.get(k, {}).get('default', '-') for k in keys))" 2>/dev/null || true)
[ -n "$SITE_DOMAINS_OUT" ] && echo -e "  ${B}Домены сайта:${R} $SITE_DOMAINS_OUT"
[ -n "$SUB_PUBLIC_OUT" ] && echo -e "  ${B}Подписка 443:${R} https://${SUB_PUBLIC_OUT}/<token>"
[ -n "$OCSERV_DOMAINS_OUT" ] && echo -e "  ${B}ocserv SNI:${R} $OCSERV_DOMAINS_OUT"
[ -n "$SERVICE_SNIS_OUT" ] && echo -e "  ${B}SNI сервисов:${R} $SERVICE_SNIS_OUT"
if service_enabled_in amneziawg "${EFFECTIVE_HOST_SERVICES[@]}"; then
    echo -e "  ${B}AmneziaWG:${R} systemd service kvn-amneziawg.service"
else
    echo -e "  ${B}AmneziaWG:${R} отключён в users.json"
fi
if service_enabled_in wireguard "${EFFECTIVE_HOST_SERVICES[@]}"; then
    echo -e "  ${B}WireGuard:${R} systemd service kvn-wireguard.service"
else
    echo -e "  ${B}WireGuard:${R} отключён в users.json"
fi
if [ "$PORTAL_RUNTIME_ENABLED" = "1" ]; then
    PORTAL_PATH_OUT=$(python3 -c "import json; print(json.load(open('users.json'))['portal']['path'])")
    PORTAL_SUFFIX=""
    [ "$PORTAL_PORT" != "443" ] && PORTAL_SUFFIX=":$PORTAL_PORT"
    if [ "$PORTAL_PUBLIC_READY" = "1" ]; then
        echo -e "  ${B}Web-портал:${R} https://${PORTAL_DOMAIN}${PORTAL_SUFFIX}${PORTAL_PATH_OUT}/"
    else
        if [ "$PORTAL_HOST_KIND" = "ipv4" ]; then
            echo -e "  ${B}Web-портал:${R} backend запущен, IP route закрыт до сертификата с совпадающим IP SAN"
        else
            echo -e "  ${B}Web-портал:${R} backend запущен, публичный доступ закрыт до Let's Encrypt"
        fi
    fi
fi
echo -e "  ${B}Порты:${R}     80/tcp (HTTP проверка домена и редирект на HTTPS)"
echo -e "             443/tcp (nginx SNI-роутер)"
echo -e "             443/udp (Hysteria 2)"
echo -e "             4443/udp (OpenConnect DTLS)"
echo -e "             51820/udp (AmneziaWG)"
echo -e "             51821/udp (WireGuard)"
echo -e "             ${SUB_PORT}/tcp (HTTPS-подписка)"
echo -e "             2443-2448/tcp (прямые резервные порты мимо nginx)"
echo ""
echo -e "  ${YLW}Откройте порт подписки в firewall:${R} ${D}ufw allow ${SUB_PORT}/tcp${R} ${D}(или cloud-firewall)${R}"
if [ "$PORTAL_RUNTIME_ENABLED" = "1" ] && [ "$PORTAL_PORT" != "443" ]; then
    echo -e "  ${YLW}Откройте порт web-портала:${R} ${D}ufw allow ${PORTAL_PORT}/tcp${R} ${D}(и cloud-firewall)${R}"
fi
echo -e "  ${YLW}Откройте порт AmneziaWG:${R} ${D}ufw allow 51820/udp${R} ${D}(или cloud-firewall)${R}"
echo -e "  ${YLW}Откройте порт WireGuard:${R} ${D}ufw allow 51821/udp${R} ${D}(или cloud-firewall)${R}"
echo -e "  ${YLW}Откройте порт OpenConnect DTLS:${R} ${D}ufw allow 4443/udp${R} ${D}(или cloud-firewall; иначе ocserv будет медленным TCP-only)${R}"
echo -e "  ${YLW}Откройте прямые TCP-порты:${R} ${D}ufw allow 2443:2448/tcp${R} ${D}(резерв, если nginx недоступен)${R}"
echo -e "  ${YLW}Откройте HTTP:${R} ${D}ufw allow 80/tcp${R} ${D}(проверка домена и Certbot HTTP-01)${R}"
echo -e "  ${CYN}Автопродление LE/IP:${R} ${D}systemctl list-timers kvn-letsencrypt-renew.timer${R}"
echo -e "  ${YLW}Важно:${R} первый setup ставит временные self-signed сертификаты. Для Let's Encrypt выполните команды ниже после проверки DNS и 80/tcp."
if [ -n "$SITE_DOMAINS_OUT" ]; then
    SITE_ARGS=""
    IFS=',' read -ra site_arr <<< "$SITE_DOMAINS_OUT"
    for domain in "${site_arr[@]}"; do SITE_ARGS+=" --domain $domain"; done
    echo -e "  ${CYN}Let's Encrypt сайт:${R}${D} python3 tools/kvnctl.py letsencrypt issue${SITE_ARGS} --restart${R}"
fi
if [ -n "$OCSERV_DOMAINS_OUT" ]; then
    OCSERV_ARGS=""
    IFS=',' read -ra oc_arr <<< "$OCSERV_DOMAINS_OUT"
    for domain in "${oc_arr[@]}"; do OCSERV_ARGS+=" --domain $domain"; done
    echo -e "  ${CYN}Let's Encrypt ocserv:${R}${D} python3 tools/kvnctl.py letsencrypt issue${OCSERV_ARGS} --target ocserv --restart${R}"
fi
echo -e "  ${D}Ссылка подписки: python3 tools/kvnctl.py links ИМЯ — в Happ вставить как подписку + тумблер insecure${R}"
echo ""
echo -e "  ${CYN}Проверка Docker:${R}  docker compose -f docker-compose.yml ps"
echo -e "  ${CYN}Проверка AWG:${R}     systemctl status kvn-amneziawg --no-pager"
echo -e "  ${CYN}Логи Docker:${R}      docker compose -f docker-compose.yml logs -f"
echo ""
echo -e "  ${B}Управление пользователями:${R}"
echo -e "    ${D}python3 tools/kvnctl.py interactive${R}"
echo ""
echo -e "  ${B}CLI команды:${R}"
echo -e "    ${D}python3 tools/kvnctl.py add-user ИМЯ --systems tls,hysteria${R}"
echo -e "    ${D}python3 tools/kvnctl.py edit-user ИМЯ --new-name НОВОЕ_ИМЯ${R}"
echo -e "    ${D}python3 tools/kvnctl.py export-links ИМЯ${R}"
echo -e "    ${D}python3 tools/kvnctl.py list-users${R}"
echo ""
echo -e "  ${B}Ссылки для клиентов:${R}  ${D}clients/<имя>/links.txt${R}  и  ${D}clients/<имя>/send.txt${R}"
echo ""
