"""План и явная предварительная проверка зависимостей без установки."""

from collections.abc import Callable
from dataclasses import dataclass

from .manifest import Manifest


@dataclass(frozen=True)
class Dependencies:
    host_checks: tuple[str, ...]
    online_image: str | None = None
    offline_image: bool = False

    def missing(self, check_host: Callable[[str], bool],
                check_image: Callable[[str], bool]) -> tuple[str, ...]:
        result = tuple(name for name in self.host_checks if not check_host(name))
        if self.online_image is not None and not check_image(self.online_image):
            result += ("image_unavailable",)
        return result


def dependencies(manifest: Manifest) -> Dependencies:
    if manifest.image_ref is not None:
        return Dependencies(("container_runtime",),
                            None if manifest.offline_image else manifest.image_ref, manifest.offline_image)
    host = {
        "wireguard": ("wireguard_tools", "wireguard_kernel"),
        "amneziawg": ("amneziawg_tools", "amneziawg_kernel"),
    }
    return Dependencies(host[manifest.module_id])
