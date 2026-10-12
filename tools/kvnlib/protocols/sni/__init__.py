"""Чистая модель маршрутизации SNI."""

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

__all__ = ["nginx_map_hash_sizes", "reality_alias_allowed", "route_collisions", "unique_domains"]
