"""Границы транспорта пользовательского архива."""

from pathlib import Path

from .crypto import MAX_ENCRYPTED

MIGRATION_SOCKET = Path("/run/kvn-v5-migration.sock")
MAX_MIGRATION_FORM = MAX_ENCRYPTED + 128 * 1024
MAX_MIGRATION_REPLY = 128 * 1024
