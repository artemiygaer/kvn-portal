"""Маршруты мониторинга, логов, аудита и внутренних проверок."""

from .common import make_compat_blueprint

blueprint = make_compat_blueprint("diagnostics")
