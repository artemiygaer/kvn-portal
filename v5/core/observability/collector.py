"""Необязательный сборщик минутных снимков; запускается только явно."""

from pathlib import Path
import signal
import threading

from v5.core.observability.history import History
from v5.core.observability.live import Observer

DIRECTORY = Path("/var/lib/kvn-v5/observability")
INTERVAL = 60


def collect(observer, history):
    snapshot = observer.snapshot()
    history.append(snapshot)


def main():
    history = History(DIRECTORY)
    history.initialize()
    observer = Observer()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    while not stopped.is_set():
        collect(observer, history)
        stopped.wait(INTERVAL)


if __name__ == "__main__":
    main()
