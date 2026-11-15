"""Узкий локальный протокол: одна JSON-строка, затем ограниченные PTY-кадры."""

import json
import re
import struct
import time

MAX_REQUEST = 8192
MAX_FRAME = 16384
HEADER = struct.Struct("!BI")
SIZE = struct.Struct("!HH")
INPUT = 1
RESIZE = 2
OUTPUT = 3
TOKEN = re.compile(r"[A-Za-z0-9_-]{32,64}\Z", re.ASCII)


def token(value) -> bool:
    return isinstance(value, str) and TOKEN.fullmatch(value) is not None


def terminal_size(rows, columns) -> bool:
    return type(rows) is int and type(columns) is int and 2 <= rows <= 200 and 10 <= columns <= 500


def _exact(connection, size: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        connection.settimeout(remaining)
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def _object(pairs):
    output = {}
    for name, value in pairs:
        if name in output:
            raise ValueError("invalid_request")
        output[name] = value
    return output


def read_line(connection, timeout=2) -> dict:
    data = bytearray()
    deadline = time.monotonic() + timeout
    # Не забирать байты первого PTY-кадра вместе с заголовком запроса.
    while len(data) <= MAX_REQUEST:
        byte = _exact(connection, 1, deadline)
        if byte == b"\n":
            result = json.loads(data, object_pairs_hook=_object)
            if isinstance(result, dict):
                return result
            break
        data.extend(byte)
    raise ValueError("invalid_request")


def send_line(connection, data: dict) -> None:
    connection.sendall(json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")


def read_frame(connection) -> tuple[int, bytes]:
    deadline = time.monotonic() + 2
    kind, size = HEADER.unpack(_exact(connection, HEADER.size, deadline))
    if not 0 < size <= MAX_FRAME or kind not in (INPUT, RESIZE, OUTPUT) or (kind == RESIZE and size != SIZE.size):
        raise ValueError("invalid_frame")
    result = _exact(connection, size, deadline)
    connection.settimeout(2)
    return kind, result


def frame(kind: int, data: bytes) -> bytes:
    if not 0 < len(data) <= MAX_FRAME or kind not in (INPUT, RESIZE, OUTPUT) or (kind == RESIZE and len(data) != SIZE.size):
        raise ValueError("invalid_frame")
    return HEADER.pack(kind, len(data)) + data
