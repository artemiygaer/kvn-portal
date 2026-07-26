#!/usr/bin/env bash
# Удаляет только безопасный локальный мусор проекта. По умолчанию работает в dry-run.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY=0

usage() {
  cat <<'EOF'
Использование: tools/cleanup-project.sh [--dry-run|--apply]

Без аргументов скрипт показывает, что может удалить. Реальное удаление выполняется только с --apply.
Удаляются только кеши и временные файлы: __pycache__, .pytest_cache, .mypy_cache, .ruff_cache, *.pyc, *.tmp, *.bak, *.orig, *~.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)
      APPLY=0
      ;;
    --apply)
      APPLY=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ОШИБКА] Неизвестный аргумент: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

is_protected_relative() {
  case "$1" in
    users.json|users.json/*|.env|.env/*|CLIENT_LINKS.md|CLIENT_LINKS.md/*)
      return 0
      ;;
    clients|clients/*|certs|certs/*|site-certs|site-certs/*|ocserv/certs|ocserv/certs/*|hy2/certs|hy2/certs/*)
      return 0
      ;;
    portal-data|portal-data/*|portal-runtime|portal-runtime/*|backup|backup/*)
      return 0
      ;;
    nginx/nginx.conf|nginx/portal-gateway.conf|nginx/site|nginx/site/*|nginx/web|nginx/web/*)
      return 0
      ;;
    xray/config.json|hy2/config.yaml|amneziawg/awg0.conf|wireguard/wg0.conf)
      return 0
      ;;
    telemt/config.toml|mtg/config.toml|ocserv/ocserv.conf|ocserv/users.txt|ocserv/ocserv.env)
      return 0
      ;;
  esac
  return 1
}

is_protected_absolute() {
  case "$1" in
    /backup|/backup/*)
      return 0
      ;;
  esac
  return 1
}

relative_path() {
  local path="$1"
  case "$path" in
    "$ROOT_DIR")
      printf '.'
      ;;
    "$ROOT_DIR"/*)
      printf '%s' "${path#"$ROOT_DIR"/}"
      ;;
    *)
      return 1
      ;;
  esac
}

validate_candidate() {
  local target="$1"
  local rel
  if is_protected_absolute "$target"; then
    echo "[ОШИБКА] Cleanup отказался трогать защищённый путь: $target" >&2
    exit 1
  fi
  if ! rel="$(relative_path "$target")"; then
    echo "[ОШИБКА] Cleanup нашёл путь вне проекта: $target" >&2
    exit 1
  fi
  if [ "$rel" = "." ] || is_protected_relative "$rel"; then
    echo "[ОШИБКА] Cleanup отказался трогать защищённый путь: $rel" >&2
    exit 1
  fi
}

declare -a candidates=()
while IFS= read -r -d '' item; do
  validate_candidate "$item"
  candidates+=("$item")
done < <(
  find "$ROOT_DIR" \
    \( -path "$ROOT_DIR/.git" -o -path "$ROOT_DIR/.supergoal" \
       -o -path "$ROOT_DIR/clients" -o -path "$ROOT_DIR/certs" -o -path "$ROOT_DIR/site-certs" \
       -o -path "$ROOT_DIR/ocserv/certs" -o -path "$ROOT_DIR/hy2/certs" \
       -o -path "$ROOT_DIR/portal-data" -o -path "$ROOT_DIR/portal-runtime" -o -path "$ROOT_DIR/backup" \
       -o -path "$ROOT_DIR/nginx/web" -o -path "$ROOT_DIR/nginx/site" \) -prune \
    -o \( \
       -type d \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache -o -name .ruff_cache \) \
       -o -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.tmp' -o -name '*.bak' -o -name '*.orig' -o -name '*~' \) \
    \) -print0
)

if [ "${#candidates[@]}" -eq 0 ]; then
  echo "[OK] Безопасный мусор не найден."
  exit 0
fi

if [ "$APPLY" -ne 1 ]; then
  echo "[DRY-RUN] Найдено безопасных объектов: ${#candidates[@]}"
  for item in "${candidates[@]}"; do
    printf '  %s\n' "$(relative_path "$item")"
  done
  echo "[INFO] Для удаления запустите: tools/cleanup-project.sh --apply"
  exit 0
fi

deleted=0
for item in "${candidates[@]}"; do
  validate_candidate "$item"
  if [ -e "$item" ] || [ -L "$item" ]; then
    rm -rf -- "$item"
    deleted=$((deleted + 1))
    printf '[APPLY] Удалено: %s\n' "$(relative_path "$item")"
  fi
done

echo "[OK] Удалено объектов: $deleted"
