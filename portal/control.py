"""Compatibility facade; реализация и services находятся в ``portal.control``."""

from portal.control.legacy.implementation import ControlError, KvnControl

__all__ = ["ControlError", "KvnControl"]
