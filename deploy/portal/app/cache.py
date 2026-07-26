"""Небольшой потокобезопасный TTL-кеш виджетов портала."""

from __future__ import annotations

import copy
import threading


class WidgetCache:
    def __init__(self):
        self._items = {}
        self._lock = threading.Lock()
        self._loading = {}

    def get(self, name: str, loader, now: int, ttl: int = 10) -> dict:
        wait_for = None
        with self._lock:
            cached = self._items.get(name)
            if cached and now - cached["collected_at"] < ttl:
                result = copy.deepcopy(cached)
                result.update(stale=False, error="")
                return result
            wait_for = self._loading.get(name)
            if wait_for is None:
                wait_for = threading.Event()
                self._loading[name] = wait_for
                owns_loader = True
            else:
                owns_loader = False
                if cached:
                    result = copy.deepcopy(cached)
                    result.update(stale=True, error="Источник обновляется.")
                    return result
        if not owns_loader:
            wait_for.wait(timeout=10)
            with self._lock:
                result = copy.deepcopy(self._items.get(name, {
                    "data": None, "collected_at": now,
                }))
            result.update(stale=result.get("data") is None, error="" if result.get("data") is not None else "Источник временно недоступен.")
            return result
        try:
            data = loader()
        except Exception:
            with self._lock:
                cached = self._items.get(name)
                self._loading.pop(name, None)
                wait_for.set()
            if cached:
                result = copy.deepcopy(cached)
                result.update(stale=True, error="Источник временно недоступен.")
                return result
            return {
                "data": None,
                "collected_at": now,
                "stale": False,
                "error": "Источник временно недоступен.",
            }
        result = {"data": data, "collected_at": now, "stale": False, "error": ""}
        with self._lock:
            self._items[name] = copy.deepcopy(result)
            self._loading.pop(name, None)
            wait_for.set()
        return result
