"""Ограничение попыток входа в одном web-worker."""

from collections import OrderedDict, deque
import threading
import time


class LoginBudget:
    """Локальные пределы и сериализация дорогого scrypt; без фоновых задач."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self._lock = threading.Lock()
        self._addresses = OrderedDict()
        self._global = deque()
        self.scrypt_slot = threading.BoundedSemaphore(1)

    def allow(self, address: str) -> bool:
        now = self.clock()
        with self._lock:
            while self._global and self._global[0] <= now - 60:
                self._global.popleft()
            if len(self._global) >= 20:
                return False
            attempts = self._addresses.setdefault(address, deque())
            self._addresses.move_to_end(address)
            while len(self._addresses) > 256:
                self._addresses.popitem(last=False)
            while attempts and attempts[0] <= now - 43200:
                attempts.popleft()
            if len(attempts) >= 5:
                return False
            attempts.append(now)
            self._global.append(now)
            return True

    def clear(self, address: str) -> None:
        with self._lock:
            self._addresses.pop(address, None)
