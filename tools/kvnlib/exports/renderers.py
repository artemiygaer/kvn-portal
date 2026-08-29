"""Типизированный registry клиентских renderer'ов."""

from __future__ import annotations

from collections.abc import Callable, Mapping

Renderer = Callable[[dict, dict, str], str]

RENDERER_NAMES = (
    "happ",
    "karing",
    "subscription",
    "openconnect",
    "amneziawg",
    "wireguard",
)

class RendererRegistry:
    """Явная таблица dispatch без импортов CLI или портала."""
    def __init__(self, renderers: Mapping[str, Renderer]):
        unknown = set(renderers) - set(RENDERER_NAMES)
        if unknown:
            raise ValueError(f"Неизвестные renderers: {', '.join(sorted(unknown))}")
        self._renderers = dict(renderers)

    def names(self) -> tuple[str, ...]:
        return tuple(name for name in RENDERER_NAMES if name in self._renderers)

    def render(self, name: str, state: dict, user: dict, public_key: str = "") -> str:
        try:
            renderer = self._renderers[name]
        except KeyError as exc:
            raise ValueError("Renderer экспорта не зарегистрирован.") from exc
        return renderer(state, user, public_key)

__all__ = ["RENDERER_NAMES", "Renderer", "RendererRegistry"]
