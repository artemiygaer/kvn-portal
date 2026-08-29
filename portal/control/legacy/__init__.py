"""Единственная compatibility-реализация Control API."""

from .implementation import ControlError, KvnControl

__all__ = ["ControlError", "KvnControl"]
