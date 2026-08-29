"""Совместимый импорт фабрики handlers; регистрация живёт в route-модулях."""

from ..routes import build_views

__all__ = ["build_views"]
