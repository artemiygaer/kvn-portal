"""Чистая модель маршрутизации SNI."""

from ..xray import LOCAL_REALITY_TARGET, reality_mode, reality_target

def reality_route_for_mode(route: dict, mode: str, domain: str, site_domains: list[str]) -> dict:
    """Готовит явную смену режима/SNI, сохраняя внешний пул для возврата."""
    reality_target(domain, site_domains, mode)
    if mode == "external" and domain in site_domains:
        raise ValueError("Для внешнего режима выберите внешний HTTPS-домен.")
    if mode == reality_mode(route) and domain == route.get("default"):
        return dict(route)
    result = dict(route)
    result.update(default=domain, reality_mode=mode)
    aliases = route.get("aliases", [])
    if mode == "external":
        aliases = [alias for alias in aliases if alias not in site_domains]
    result["aliases"] = list(dict.fromkeys([domain, *aliases]))
    return result

def site_route_destination(domain: str, site_domains: list[str], routes: dict) -> str:
    """Self-steal разделяет SNI сайта только с одним штатным Reality backend."""
    if domain not in site_domains:
        return "127.0.0.1:8443"
    candidates = set()
    for system, destination in (("reality-tcp", "xray:2054"), ("reality-xhttp", "xray:2053")):
        route = routes.get(system, {})
        if not isinstance(route, dict) or route.get("dest", destination) != destination:
            continue
        default = route.get("default", "")
        if reality_mode(route) != "self-steal":
            continue
        if reality_target(default, site_domains, "self-steal") != LOCAL_REALITY_TARGET:
            continue
        if domain in [default, *route.get("aliases", [])]:
            candidates.add(destination)
    return next(iter(candidates)) if len(candidates) == 1 else "127.0.0.1:8443"

def route_collisions(domain_to_routes: dict[str, list[tuple[str, str]]]) -> dict[str, list[tuple[str, str]]]:
    return {domain: routes for domain, routes in domain_to_routes.items() if len({dest for _, dest in routes}) > 1}

def reality_alias_allowed(default: str, aliases: list[str], selected: str) -> bool:
    return selected in dict.fromkeys([default, *aliases])

def unique_domains(*groups: list[str]) -> list[str]:
    result = []
    for group in groups:
        for domain in group:
            if domain and domain not in result:
                result.append(domain)
    return result

def nginx_map_hash_sizes(keys: list[str]) -> tuple[int, int]:
    """Размеры nginx map для UTF-8 ключей с выравниванием 64-битного hash entry."""
    bucket = 64
    longest = max((len(key.encode("utf-8")) for key in keys), default=0)
    # Значение entry и завершающий NULL-pointer bucket занимают по 8 байт.
    entry_size = 16 + ((longest + 2 + 7) // 8) * 8
    while bucket < entry_size:
        bucket *= 2
    max_size = 2048
    while max_size < len(keys) * 2:
        max_size *= 2
    return bucket, max_size

__all__ = ["nginx_map_hash_sizes", "reality_alias_allowed", "reality_route_for_mode", "route_collisions", "site_route_destination", "unique_domains"]
