#!/bin/sh
# Этот файл запускается из проверенного дерева установки Portal-first.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"
exec python3 -m v5.install.setup "$@"
