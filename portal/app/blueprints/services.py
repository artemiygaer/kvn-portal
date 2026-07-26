"""Маршруты управления сервисами и host-agent операциями."""

from .common import make_compat_blueprint

blueprint = make_compat_blueprint("services")
