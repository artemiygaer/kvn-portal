"""Замерить нагрузку явно заданных непересекающихся cgroup v2."""

import argparse
import json
from pathlib import Path
import time


def read_usage(group):
    """Вернуть CPU microseconds и текущую память; отсутствие данных — ошибка."""
    entries = dict(line.split(maxsplit=1) for line in (group / "cpu.stat").read_text().splitlines())
    return int(entries["usage_usec"]), int((group / "memory.current").read_text().strip())


def validate_groups(names, root=Path("/sys/fs/cgroup")):
    root = root.resolve(strict=True)
    groups = []
    for name in names:
        path = (root / name.lstrip("/")).resolve(strict=True)
        if path == root or not path.is_relative_to(root) or not path.is_dir():
            raise ValueError("Укажите непустую cgroup внутри /sys/fs/cgroup")
        if any(path == other or path in other.parents or other in path.parents for other in groups):
            raise ValueError("Группы не должны повторяться или быть вложенными")
        groups.append(path)
    if not groups:
        raise ValueError("Не указаны группы")
    return groups


def measure(groups, seconds=300, interval=5):
    if seconds <= 0 or interval <= 0:
        raise ValueError("Интервал и длительность должны быть положительными")
    start = time.monotonic()
    initial = [read_usage(group)[0] for group in groups]
    peak = 0
    while True:
        current = [read_usage(group) for group in groups]
        peak = max(peak, sum(memory for _, memory in current))
        elapsed = time.monotonic() - start
        if elapsed >= seconds:
            break
        time.sleep(min(interval, seconds - elapsed))
    deltas = [cpu - old for (cpu, _), old in zip(current, initial)]
    if any(delta < 0 for delta in deltas):
        raise RuntimeError("Счётчик CPU уменьшился: группа могла перезапуститься")
    used = sum(deltas)
    return {"seconds": round(elapsed, 3), "cpu_percent_one_core": round(used / (elapsed * 1_000_000) * 100, 3),
            "memory_peak_sampled_bytes": peak, "sample_interval_seconds": interval,
            "groups": [str(group) for group in groups]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("groups", nargs="+", help="Пути cgroup v2 относительно /sys/fs/cgroup")
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args()
    print(json.dumps(measure(validate_groups(args.groups), args.seconds, args.interval), ensure_ascii=False))


if __name__ == "__main__":
    main()
