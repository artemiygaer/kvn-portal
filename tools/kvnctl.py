#!/usr/bin/env python3
"""Тонкий совместимый facade KVN CLI.

При импорте модуль становится alias command-composition реализации. Это
сохраняет старые monkey-patch/import контракты без дублирования кода.
"""

from __future__ import annotations

import sys

try:
    from tools.kvnlib.commands import implementation as _implementation
except ModuleNotFoundError:  # запуск как python3 tools/kvnctl.py
    from kvnlib.commands import implementation as _implementation

if __name__ == "__main__":
    _implementation.main()
else:
    sys.modules[__name__] = _implementation
